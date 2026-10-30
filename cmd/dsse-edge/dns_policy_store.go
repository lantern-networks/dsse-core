package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	dnsresolver "github.com/lantern-networks/dsse-core/dnsresolver"
	"github.com/lantern-networks/dsse-core/durablefile"
)

// The DNS policy an operator authored, kept across restarts.
//
// It was not. The policy lived only in the resolver's live pointer, so a DNS rule written through the admin
// API survived exactly until the process restarted, and then the deployment quietly went back to whatever its
// environment variables said at boot. That is the failure this codebase already has a name for — operator
// config in a volatile store — and DNS had simply never been wired into the fix.
//
// It cost something real on 2026-07-30. Restarting the control plane dropped the stub that made app.corp
// resolve; the Edge pulled the now-empty policy and lost it too, and what reached a person was a browser
// saying there was no internet. Nothing in that experience points at a DNS rule that stopped existing.
//
// Precedence is: stored policy wins over the boot environment. Anything else defeats the purpose — an
// operator's change would be reverted by a restart, which is the bug. The environment SEEDS the store the
// first time, so a fresh deployment still comes up with the stubs its compose file describes.
type dnsPolicyStore struct {
	path     string
	mu       sync.Mutex
	authored bool
	write    func(string, []byte, os.FileMode) error
}

func newDNSPolicyStore(path string) *dnsPolicyStore {
	return &dnsPolicyStore{path: strings.TrimSpace(path)}
}

// load distinguishes first boot from unreadable or invalid operator state.
// Existing state must never be replaced with a seed just because it cannot be read.
func (s *dnsPolicyStore) load() (dnsresolver.PolicyDTO, bool, error) {
	if s == nil || s.path == "" {
		return dnsresolver.PolicyDTO{}, false, nil
	}
	raw, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return dnsresolver.PolicyDTO{}, false, nil
	}
	if err != nil {
		return dnsresolver.PolicyDTO{}, false, fmt.Errorf("read DNS policy: %w", err)
	}
	var record struct {
		dnsresolver.PolicyDTO
		Authored bool `json:"admin_authored,omitempty"`
	}
	if strings.TrimSpace(string(raw)) == "null" {
		return dnsresolver.PolicyDTO{}, false, fmt.Errorf("DNS policy must be an object")
	}
	if err := json.Unmarshal(raw, &record); err != nil {
		return dnsresolver.PolicyDTO{}, false, fmt.Errorf("decode DNS policy: %w", err)
	}
	if _, err := dnsresolver.PolicyFromDTO(record.PolicyDTO); err != nil {
		return dnsresolver.PolicyDTO{}, false, fmt.Errorf("invalid stored DNS policy: %w", err)
	}
	s.authored = record.Authored
	return record.PolicyDTO, true, nil
}

// save writes atomically: a temp file and a rename, so a crash mid-write leaves the previous policy rather
// than a truncated one. A DNS policy that is half-written is a deployment that resolves half its names.
func (s *dnsPolicyStore) save(dto dnsresolver.PolicyDTO) error { return s.saveSnapshot(dto, false) }

func (s *dnsPolicyStore) saveSnapshot(dto dnsresolver.PolicyDTO, authored bool) error {
	if s == nil || s.path == "" {
		return nil
	}
	raw, err := json.Marshal(struct {
		dnsresolver.PolicyDTO
		Authored bool `json:"admin_authored,omitempty"`
	}{dto, authored})
	if err != nil {
		return fmt.Errorf("encode dns policy: %w", err)
	}
	if dir := filepath.Dir(s.path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create dns policy store directory: %w", err)
		}
	}
	write := s.write
	if write == nil {
		write = durablefile.Write
	}
	return write(s.path, raw, 0o600)
}

// restoreDNSPolicy applies the stored policy over the one built from the environment, and seeds the store when
// there is nothing in it yet. Returns a line describing what happened, for the startup log — a restart that
// silently changes which names resolve is exactly what this is meant to stop being possible.
func restoreDNSPolicy(store *dnsPolicyStore, resolver *dnsresolver.Resolver) (string, error) {
	if store == nil || store.path == "" || resolver == nil {
		return "", nil
	}
	dto, ok, err := store.load()
	if err != nil {
		return "", err
	}
	if ok {
		policy, err := dnsresolver.PolicyFromDTO(dto)
		if err != nil {
			return "", err
		}
		resolver.SetPolicy(policy)
		return fmt.Sprintf("dns policy: restored from %s (%s)", store.path, policy.Summary()), nil
	}
	if err := store.save(dnsresolver.PolicyToDTO(resolver.CurrentPolicy())); err != nil {
		return "", fmt.Errorf("seed DNS policy: %w", err)
	}
	return fmt.Sprintf("dns policy: seeded %s from the boot configuration (%s)", store.path, resolver.CurrentPolicy().Summary()), nil
}

// DNS-policy admin routes (read + durable write-through to the resolver), moved verbatim
// out of newServerWithConfig (Phase 2 route-registration split).
func registerDNSPolicyRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, edgeDNSResolver *dnsresolver.Resolver, edgeDNSPolicyStore *dnsPolicyStore, configSourceURL string) {
	if edgeDNSPolicyStore == nil {
		edgeDNSPolicyStore = newDNSPolicyStore("")
	}
	mux.HandleFunc("GET /admin/dns-policy", adminEndpoint("admin.dns.read", func(w http.ResponseWriter, r *http.Request) {
		if edgeDNSResolver == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("dns resolver not configured"))
			return
		}
		writeJSON(w, http.StatusOK, dnsresolver.PolicyToDTO(edgeDNSResolver.CurrentPolicy()))
	}))
	mux.HandleFunc("PUT /admin/dns-policy", adminEndpoint("admin.dns.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "DNS policy") {
			return
		}
		if edgeDNSResolver == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("dns resolver not configured"))
			return
		}
		var dto dnsresolver.PolicyDTO
		if err := decodeLimitedJSONBody(w, r, &dto, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode dns policy: %w", err))
			return
		}
		policy, err := dnsresolver.PolicyFromDTO(dto)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		edgeDNSPolicyStore.mu.Lock()
		defer edgeDNSPolicyStore.mu.Unlock()
		if err := edgeDNSPolicyStore.saveSnapshot(dnsresolver.PolicyToDTO(policy), true); err != nil {
			if errors.Is(err, durablefile.ErrReplacedNotFlushed) {
				edgeDNSPolicyStore.authored = true
				edgeDNSResolver.SetPolicy(policy)
			}
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("DNS policy could not be saved; reload and retry"))
			return
		}
		edgeDNSPolicyStore.authored = true
		edgeDNSResolver.SetPolicy(policy)
		appliedDTO := dnsresolver.PolicyToDTO(policy)
		logInfof("dns_policy_applied_by_admin deny=%d sinkhole=%d stub=%d ech_strip=%t", len(appliedDTO.Deny), len(appliedDTO.Sinkhole), len(appliedDTO.StubIPv4), policy.ECHStripValue())
		writeJSON(w, http.StatusOK, dnsresolver.PolicyToDTO(edgeDNSResolver.CurrentPolicy()))
	}))
	// Feature entitlements (the license gate). GET returns the tenant's resolved feature flags (e.g. dlp:true);
	// PUT sets them (a license apply / admin override). Drives the Console's show/hide of paid-feature surfaces.
}

// Snapshot couples the authored marker with the DNS policy being distributed.
func (s *dnsPolicyStore) snapshot(resolver *dnsresolver.Resolver) (dnsresolver.PolicyDTO, bool) {
	if s == nil {
		return dnsresolver.PolicyToDTO(resolver.CurrentPolicy()), false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return dnsresolver.PolicyToDTO(resolver.CurrentPolicy()), s.authored
}
