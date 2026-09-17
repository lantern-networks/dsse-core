package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// revocation_mesh.go is the cross-region (multi-region) propagation of admission revocations between regional
// control planes. When a device is revoked at THIS region's CP (admin kill-switch, or a node-reported W-2 auto-
// revoke folded in via /admin/revocations/report), the overlay's mesh reporter pushes the item to the tenant's
// peer-region CPs. A peer CP folds it into its cross-region layer (RevokeFromMesh) — denied on its edges, never
// re-pushed (no-loop). It is the single-region Slice-3 propagation lifted one ring out.
//
// Residency: the configured peer set IS the tenant's allowed-region CPs (a per-tenant residency-scoped peer list
// is the multi-tenant refinement; today's deployment is per-tenant-per-fabric, so the flag carries that scope).

type revocationMeshPeer struct {
	region string
	url    string // peer region CP base URL (e.g. https://cp.osaka:9443)
}

// revocationMeshSource pushes origin revocations to peer-region CPs.
type revocationMeshSource struct {
	originRegion string
	peers        []revocationMeshPeer
	secret       string
	client       *http.Client
	outbox       *revocationMeshOutbox // pending queue with optional persistence; nil => legacy retries
}

// revocationMeshItem is the cross-region wire payload: small, device-linked, monotonic.
type revocationMeshItem struct {
	Identity     string `json:"identity"`
	Reason       string `json:"reason"`
	OriginRegion string `json:"origin_region"`
}

// parseRevocationMeshPeers parses "region=URL;region=URL". Empty -> no peers (mesh disabled; single-region).
func parseRevocationMeshPeers(raw string) ([]revocationMeshPeer, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var peers []revocationMeshPeer
	seen := map[string]bool{}
	for _, entry := range strings.Split(raw, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		region, url, ok := strings.Cut(entry, "=")
		region = strings.ToLower(strings.TrimSpace(region))
		url = strings.TrimSpace(url)
		if !ok || region == "" || url == "" {
			return nil, fmt.Errorf("revocation mesh peer %q must be region=URL", entry)
		}
		if seen[region] {
			return nil, fmt.Errorf("revocation mesh peer region %q is configured more than once", region)
		}
		seen[region] = true
		peers = append(peers, revocationMeshPeer{region: region, url: url})
	}
	return peers, nil
}

// pushFunc returns the overlay mesh reporter: on a NEW ORIGIN revocation, ENQUEUE the push for every peer CP
// (reporting whether saving was confirmed) then deliver asynchronously with bounded retries. A peer
// blip never blocks the local revoke (which already applied + denies instantly in the origin region); the item is
// monotonic, so an unchanged duplicate does not change enforcement. The receiver
// still retries saving before acknowledging it.
func (s revocationMeshSource) pushFunc() func(identity, reason string) {
	return func(identity, reason string) {
		item := revocationMeshItem{Identity: identity, Reason: reason, OriginRegion: s.originRegion}
		for _, peer := range s.peers {
			s.deliverToPeer(peer, item)
		}
	}
}

// deliverToPeer retains a push in the outbox, attempts persistence, then starts delivery.
// Restart recovery requires a confirmed save. Peer acceptance and saved cleanup are
// checked separately. With no outbox, only the legacy in-process retry loop runs.
func (s revocationMeshSource) deliverToPeer(peer revocationMeshPeer, item revocationMeshItem) {
	if s.outbox == nil {
		go s.pushToPeerWithRetry(peer, item)
		return
	}
	entry, persistence, _ := s.outbox.enqueue(revocationMeshOutboxEntry{
		Region: peer.region, URL: peer.url, Identity: item.Identity, Reason: item.Reason,
		OriginRegion: item.OriginRegion, EnqueuedAt: time.Now().UTC().Format(time.RFC3339),
	})
	log.Printf("revocation mesh outbox: enqueue identity=%q region=%q persistence=%s", entry.Identity, entry.Region, persistence)
	go s.pushPendingToPeerWithRetry(peer, item, &entry)
}

// resumePendingDeliveries re-drives every push that was enqueued but not acked before a restart: it
// is called once at boot after the outbox is loaded. Returns the number of pending pushes resumed. A duplicate
// delivery does not change enforcement on the peer, but retries saving there.
func (s revocationMeshSource) resumePendingDeliveries() int {
	if s.outbox == nil {
		return 0
	}
	pending := s.outbox.snapshot()
	for _, e := range pending {
		peer := revocationMeshPeer{region: e.Region, url: e.URL}
		item := revocationMeshItem{Identity: e.Identity, Reason: e.Reason, OriginRegion: e.OriginRegion}
		go s.pushPendingToPeerWithRetry(peer, item, &e)
	}
	return len(pending)
}

// Legacy delivery without an outbox retains bounded in-process retries.
func (s revocationMeshSource) pushToPeerWithRetry(peer revocationMeshPeer, item revocationMeshItem) bool {
	return s.pushPendingToPeerWithRetry(peer, item, nil)
}

// A peer's ACK and confirmation that its pending entry was removed from storage
// are separate outcomes. Once acknowledged, retry only cleanup, not the network.
func (s revocationMeshSource) pushPendingToPeerWithRetry(peer revocationMeshPeer, item revocationMeshItem, entry *revocationMeshOutboxEntry) bool {
	const maxBackoff = 30 * time.Second
	const maxWindow = 10 * time.Minute
	backoff := time.Second
	deadline := time.Now().UTC().Add(maxWindow)
	peerAccepted := false
	for {
		if entry != nil && !s.outbox.isCurrent(*entry) {
			log.Printf("revocation mesh outbox: superseded identity=%q region=%q", entry.Identity, entry.Region)
			return false
		}
		if !peerAccepted {
			if entry != nil {
				current, persistence, _ := s.outbox.retryPending(*entry)
				if !current {
					return false
				}
				if persistence != "not_attempted" {
					log.Printf("revocation mesh outbox: retry pending identity=%q region=%q persistence=%s", entry.Identity, entry.Region, persistence)
				}
			}
			peerAccepted = s.pushOnce(peer, item)
		}
		if peerAccepted {
			if entry == nil {
				log.Printf("revocation mesh: pushed %q (origin %s) to peer region %s", item.Identity, item.OriginRegion, peer.region)
				return true
			}
			removed, persistence, err := s.outbox.ack(*entry)
			log.Printf("revocation mesh outbox: peer_accepted=true identity=%q region=%q removed=%t persistence=%s", entry.Identity, entry.Region, removed, persistence)
			if err == nil {
				return removed
			}
		}
		if !time.Now().UTC().Before(deadline) {
			if entry == nil {
				log.Printf("revocation mesh: delivery unconfirmed identity=%q region=%q; retry window ended without a persistent outbox", item.Identity, peer.region)
			} else {
				log.Printf("revocation mesh outbox: retry window ended identity=%q region=%q peer_accepted=%t; pending retained in this process, restart recovery requires confirmed storage", item.Identity, peer.region, peerAccepted)
			}
			return false
		}
		time.Sleep(backoff)
		if backoff *= 2; backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func (s revocationMeshSource) pushOnce(peer revocationMeshPeer, item revocationMeshItem) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	body, _ := json.Marshal(item)
	url := strings.TrimRight(peer.url, "/") + "/revocation-mesh/admission"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return false
	}
	if s.secret != "" {
		req.Header.Set("x-revocation-mesh-secret", s.secret)
	}
	// Anti-replay: stamp ts+nonce+HMAC so a captured push cannot be replayed to re-apply a stale revocation.
	signMeshRequest(req.Header, s.secret, body, time.Now().UTC())
	req.Header.Set("content-type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		log.Printf("revocation mesh: push %q -> region %s failed (will retry): %v", item.Identity, peer.region, err)
		return false
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("revocation mesh: peer region %s returned %d for %q (will retry)", peer.region, resp.StatusCode, item.Identity)
		return false
	}
	return true
}
