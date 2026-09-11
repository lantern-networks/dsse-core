package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	steerexclusion "github.com/lantern-networks/dsse-core/steerexclusion"
)

// CP→Edge steer-exclusion sync (P-3 of docs/config_persistence_and_rollback.md). The enforcing Edge keeps
// NO durable DB (zero-DB): the control plane owns the durable steer-exclusion store, and the Edge PULLS the
// authoritative set over an authenticated channel and caches it in-memory (steerexclusion.Store.ReplaceTenant)
// to sign for devices. So an Edge restart re-populates its cache from the CP (durability), and Console-authored
// exclusions reach the Edge's devices on the next poll. Fail-safe: a fetch error keeps the last good set.

type steerExclusionSource struct {
	url      string // control-plane admin base, e.g. https://controlplane:9443
	token    string // bearer (the shared -admin-token); the CP scopes the result to this token's tenant
	tenantID string // the Edge's enforcement tenant (must equal the CP's tenant — see J-1)
	interval time.Duration
	client   *http.Client
}

// buildSteerExclusionSourceClient builds an HTTPS client that trusts the control plane's CA (PEM file). An
// empty caFile uses the system roots.
//
// ★ AND IT REFUSES EVERY REDIRECT (2026-08-12, sixth review). This one function builds the client for SIX CP
// pull lanes — steer exclusions, the config bundle, revocations, device-runtime hydrate, fleet config status
// and the agent-rollout halt — and every one of them sets an Authorization header carrying the admin bearer
// token. Go forwards that header across a redirect to the same host or a subdomain of it, which includes a 302
// from https to PLAIN HTTP on the same host: a control plane that has been tampered with, or a proxy in front
// of it, could collect the token by answering one redirect. The update-set lane was fixed for this in the
// fifth review and these five were left behind, which is the more instructive half of the finding — the fix
// belonged where the client is built, not where the first instance was noticed.
//
// Refusing outright rather than stripping the header: a pull that silently follows a redirect somewhere else
// is answering with a different machine's idea of the truth, and for a HALT or a config bundle that is not a
// smaller problem than the leaked token.
func buildSteerExclusionSourceClient(caFile string) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile = strings.TrimSpace(caFile); caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read steer-exclusion source CA %q: %w", caFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("steer-exclusion source CA %q has no usable certificate", caFile)
		}
		tlsCfg.RootCAs = pool
	}
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return fmt.Errorf("the control plane redirected this authenticated pull to %s: refusing to follow it "+
				"with an admin token attached", req.URL.Redacted())
		},
	}, nil
}

// fetchAndReplace pulls the tenant's steer exclusions from the control plane and replaces the local cache.
// Returns the count applied. On any error it returns the error WITHOUT touching the store (fail-safe).
func (s steerExclusionSource) fetchAndReplace(ctx context.Context, store *steerexclusion.Store) (int, error) {
	url := strings.TrimRight(s.url, "/") + "/admin/steer-exclusions"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("control plane returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var payload struct {
		SteerExclusions []steerexclusion.Policy `json:"steer_exclusions"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return 0, fmt.Errorf("decode steer exclusions: %w", err)
	}
	// Bind every policy to the Edge's tenant so a misconfigured source can't inject another tenant's set.
	for i := range payload.SteerExclusions {
		payload.SteerExclusions[i].TenantID = s.tenantID
	}
	store.ReplaceTenant(s.tenantID, payload.SteerExclusions)
	return len(payload.SteerExclusions), nil
}

// run pulls immediately, then every interval, until ctx is cancelled. A failed pull keeps the last cached
// set (the Edge never starts steering an excluded app because the control plane was briefly unreachable).
func (s steerExclusionSource) run(ctx context.Context, store *steerexclusion.Store) {
	if n, err := s.fetchAndReplace(ctx, store); err != nil {
		log.Printf("steer-exclusion sync: initial pull from %s failed (keeping cache): %v", s.url, err)
	} else {
		log.Printf("steer-exclusion sync: pulled %d policy(ies) from the control plane", n)
	}
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := s.fetchAndReplace(ctx, store); err != nil {
				log.Printf("steer-exclusion sync: pull failed (keeping cache): %v", err)
			}
		}
	}
}
