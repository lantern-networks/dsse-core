package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
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
	outbox       *revocationMeshOutbox // durable pending-push queue; nil => in-memory only (legacy)
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
// (durably, when an outbox is configured) then deliver async + retry-until-acked. Best-effort delivery: a peer
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

// deliverToPeer enqueues a push in the durable outbox (so it survives a CP restart) and spawns the retry loop,
// acking the outbox entry once the peer confirms. With no outbox it degrades to the legacy in-memory push.
func (s revocationMeshSource) deliverToPeer(peer revocationMeshPeer, item revocationMeshItem) {
	if s.outbox != nil {
		s.outbox.enqueue(revocationMeshOutboxEntry{
			Region: peer.region, URL: peer.url, Identity: item.Identity, Reason: item.Reason,
			OriginRegion: item.OriginRegion, EnqueuedAt: time.Now().UTC().Format(time.RFC3339),
		})
	}
	go func() {
		if s.pushToPeerWithRetry(peer, item) && s.outbox != nil {
			s.outbox.ack(peer.region, item.Identity)
		}
	}()
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
		go func() {
			if s.pushToPeerWithRetry(peer, item) {
				s.outbox.ack(peer.region, item.Identity)
			}
		}()
	}
	return len(pending)
}

// pushToPeerWithRetry pushes a revocation to one peer CP, retrying with exponential backoff for a long window so a
// transient peer/network outage converges (a security kill-switch must not give up after a blip). The item is
// monotonic, so an unchanged duplicate leaves enforcement unchanged while retrying the peer's save.
// Returns true once the peer acks. On give-up the caller leaves the
// entry in the durable outbox so the next boot's resumePendingDeliveries drives it to completion —
// a CP restart no longer drops a not-yet-acked cross-region push.
func (s revocationMeshSource) pushToPeerWithRetry(peer revocationMeshPeer, item revocationMeshItem) bool {
	const maxBackoff = 30 * time.Second
	const maxWindow = 10 * time.Minute
	backoff := time.Second
	deadline := time.Now().UTC().Add(maxWindow)
	for {
		if s.pushOnce(peer, item) {
			log.Printf("revocation mesh: pushed %q (origin %s) to peer region %s", item.Identity, item.OriginRegion, peer.region)
			return true
		}
		if !time.Now().UTC().Before(deadline) {
			log.Printf("revocation mesh: gave up pushing %q to peer region %s after %s in this process; it stays in the durable outbox and is resumed on the next boot", item.Identity, peer.region, maxWindow)
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

// revocationMeshOutboxEntry is one pending cross-region push, persisted so it survives a CP restart. Keyed by
// (Region, Identity): a re-revoke of the same identity to the same peer overwrites (monotonic — latest reason
// wins); the entry is removed once the peer acks. Un-revoke is deliberately NOT mesh-propagated, so the outbox
// only ever holds revokes.
type revocationMeshOutboxEntry struct {
	Region       string `json:"region"`
	URL          string `json:"url"`
	Identity     string `json:"identity"`
	Reason       string `json:"reason"`
	OriginRegion string `json:"origin_region"`
	EnqueuedAt   string `json:"enqueued_at"`
}

// revocationMeshOutbox is the durable queue of not-yet-acked cross-region pushes. It persists the whole
// pending set as a JSON blob on every enqueue/ack via a blobstore.Persister (file or Postgres); with a nil
// persister it is memory-only (delivery still works, just not restart-durable — matches the pre-outbox behaviour).
type revocationMeshOutbox struct {
	mu        sync.Mutex
	persister blobstore.Persister
	pending   map[string]revocationMeshOutboxEntry
}

func revocationMeshOutboxKey(region, identity string) string { return region + "\x00" + identity }

// newRevocationMeshOutbox loads any persisted pending pushes so a restart resumes them. A nil persister yields an
// empty memory-only outbox.
func newRevocationMeshOutbox(p blobstore.Persister) (*revocationMeshOutbox, error) {
	o := &revocationMeshOutbox{persister: p, pending: map[string]revocationMeshOutboxEntry{}}
	if p == nil {
		return o, nil
	}
	data, err := p.Load()
	if err != nil {
		return nil, fmt.Errorf("load revocation mesh outbox: %w", err)
	}
	if len(data) == 0 {
		return o, nil
	}
	var entries []revocationMeshOutboxEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("decode revocation mesh outbox: %w", err)
	}
	for _, e := range entries {
		if strings.TrimSpace(e.Region) == "" || strings.TrimSpace(e.Identity) == "" {
			continue
		}
		o.pending[revocationMeshOutboxKey(e.Region, e.Identity)] = e
	}
	return o, nil
}

func (o *revocationMeshOutbox) enqueue(e revocationMeshOutboxEntry) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.pending[revocationMeshOutboxKey(e.Region, e.Identity)] = e
	o.persistLocked()
}

func (o *revocationMeshOutbox) ack(region, identity string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, ok := o.pending[revocationMeshOutboxKey(region, identity)]; !ok {
		return
	}
	delete(o.pending, revocationMeshOutboxKey(region, identity))
	o.persistLocked()
}

// snapshot returns the pending entries (stable order) for boot-time resume / observability.
func (o *revocationMeshOutbox) snapshot() []revocationMeshOutboxEntry {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.sortedLocked()
}

func (o *revocationMeshOutbox) sortedLocked() []revocationMeshOutboxEntry {
	out := make([]revocationMeshOutboxEntry, 0, len(o.pending))
	for _, e := range o.pending {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Region != out[j].Region {
			return out[i].Region < out[j].Region
		}
		return out[i].Identity < out[j].Identity
	})
	return out
}

func (o *revocationMeshOutbox) persistLocked() {
	if o.persister == nil {
		return
	}
	data, err := json.Marshal(o.sortedLocked())
	if err != nil {
		log.Printf("revocation mesh outbox: marshal failed: %v", err)
		return
	}
	if err := o.persister.Save(data); err != nil {
		log.Printf("revocation mesh outbox: persist failed (a pending push may not survive a restart): %v", err)
	}
}
