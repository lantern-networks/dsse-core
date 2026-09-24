package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	dnsresolver "github.com/lantern-networks/dsse-core/dnsresolver"
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
	path string
}

func newDNSPolicyStore(path string) *dnsPolicyStore {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	return &dnsPolicyStore{path: strings.TrimSpace(path)}
}

// load returns the stored policy, or ok=false when there is nothing stored yet. A CORRUPT store returns
// ok=false as well: falling back to the boot environment is recoverable, whereas refusing to start over an
// unreadable DNS file would take the datapath down for a resolvable problem.
func (s *dnsPolicyStore) load() (dnsresolver.PolicyDTO, bool) {
	if s == nil {
		return dnsresolver.PolicyDTO{}, false
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return dnsresolver.PolicyDTO{}, false
	}
	var dto dnsresolver.PolicyDTO
	if err := json.Unmarshal(raw, &dto); err != nil {
		log.Printf("dns policy store: %s is unreadable (%v) — starting from the boot configuration instead", s.path, err)
		return dnsresolver.PolicyDTO{}, false
	}
	return dto, true
}

// save writes atomically: a temp file and a rename, so a crash mid-write leaves the previous policy rather
// than a truncated one. A DNS policy that is half-written is a deployment that resolves half its names.
func (s *dnsPolicyStore) save(dto dnsresolver.PolicyDTO) error {
	if s == nil {
		return nil
	}
	raw, err := json.Marshal(dto)
	if err != nil {
		return fmt.Errorf("encode dns policy: %w", err)
	}
	if dir := filepath.Dir(s.path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create dns policy store directory: %w", err)
		}
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("write dns policy: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("commit dns policy: %w", err)
	}
	return nil
}

// restoreDNSPolicy applies the stored policy over the one built from the environment, and seeds the store when
// there is nothing in it yet. Returns a line describing what happened, for the startup log — a restart that
// silently changes which names resolve is exactly what this is meant to stop being possible.
func restoreDNSPolicy(store *dnsPolicyStore, resolver *dnsresolver.Resolver) string {
	if store == nil || resolver == nil {
		return ""
	}
	if dto, ok := store.load(); ok {
		policy, err := dnsresolver.PolicyFromDTO(dto)
		if err != nil {
			log.Printf("dns policy store: stored policy is invalid (%v) — keeping the boot configuration", err)
			return ""
		}
		resolver.SetPolicy(policy)
		return fmt.Sprintf("dns policy: restored from %s (%s)", store.path, policy.Summary())
	}
	// Nothing stored: seed from what the deployment booted with, so the first admin write is an edit rather
	// than a creation, and so the file exists to be inspected.
	if err := store.save(dnsresolver.PolicyToDTO(resolver.CurrentPolicy())); err != nil {
		log.Printf("dns policy store: could not seed %s: %v", store.path, err)
		return ""
	}
	return fmt.Sprintf("dns policy: seeded %s from the boot configuration (%s)", store.path, resolver.CurrentPolicy().Summary())
}

// DNS-policy admin routes (read + durable write-through to the resolver), moved verbatim
// out of newServerWithConfig (Phase 2 route-registration split).
func registerDNSPolicyRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, edgeDNSResolver *dnsresolver.Resolver, edgeDNSPolicyStore *dnsPolicyStore, configSourceURL string) {
	// Serialize durable replacement and live publication for concurrent admin writes.
	var writeMu sync.Mutex
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
		writeMu.Lock()
		defer writeMu.Unlock()
		// Publish only after the durable replacement succeeds. A failed save must
		// leave the running resolver on the last acknowledged policy.
		if err := edgeDNSPolicyStore.save(dnsresolver.PolicyToDTO(policy)); err != nil {
			log.Printf("dns policy: could not persist proposed policy: %v", err)
			writeError(w, http.StatusInternalServerError, fmt.Errorf("could not save DNS policy; active policy was not changed"))
			return
		}
		edgeDNSResolver.SetPolicy(policy)
		appliedDTO := dnsresolver.PolicyToDTO(policy)
		logInfof("dns_policy_applied_by_admin deny=%d sinkhole=%d stub=%d ech_strip=%t", len(appliedDTO.Deny), len(appliedDTO.Sinkhole), len(appliedDTO.StubIPv4), policy.ECHStripValue())
		writeJSON(w, http.StatusOK, dnsresolver.PolicyToDTO(edgeDNSResolver.CurrentPolicy()))
	}))
	// Feature entitlements (the license gate). GET returns the tenant's resolved feature flags (e.g. dlp:true);
	// PUT sets them (a license apply / admin override). Drives the Console's show/hide of paid-feature surfaces.
}
