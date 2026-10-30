package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/grantstore"
	"github.com/lantern-networks/dsse-core/oidcbroker"
)

const authenticationGrantProtocol = "authentication-grants-v2"

type authenticationGrantSnapshot struct {
	Protocol string       `json:"protocol"`
	Nonce    string       `json:"nonce"`
	Version  string       `json:"version"`
	Tenant   string       `json:"tenant"`
	Device   string       `json:"device"`
	Scope    string       `json:"scope"`
	Grants   *grantBundle `json:"grants"`
}

func scopedGrantBundle(store *grantstore.Store, tenant, device, scope string) *grantBundle {
	rows, err := store.ListChecked(tenant)
	if err != nil {
		return &grantBundle{Complete: false}
	}
	filtered := make([]grantstore.Grant, 0)
	for _, grant := range rows {
		if grant.DeviceID == device && grant.Scope == scope {
			filtered = append(filtered, grant)
		}
	}
	ordinary, protected := grantstore.SplitTransport(filtered)
	return &grantBundle{Grants: ordinary, ProtectedGrants: protected, Complete: true}
}

func authenticationGrantVersion(section *grantBundle) string {
	data, _ := json.Marshal(section)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// Same management authorization as the full config endpoint, with only one
// store read. A content version avoids signing/transferring unchanged snapshots.
func registerAuthenticationGrantSnapshot(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, store *grantstore.Store, signer *agentpolicy.Signer, configSourceURL, operatorTenant string) {
	if strings.TrimSpace(configSourceURL) != "" || store == nil {
		return
	}
	mux.HandleFunc("GET /admin/authentication-grants", adminEndpoint("admin.policy.read", func(w http.ResponseWriter, r *http.Request) {
		if !authorizeFleetConfigurationRead(w, r, operatorTenant) {
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		nonce := r.Header.Get("X-DSSE-Grant-Nonce")
		if !validAuthResultRequestID(nonce) {
			writeError(w, 400, fmt.Errorf("invalid grant snapshot nonce"))
			return
		}
		tenant, device, scope := strings.TrimSpace(r.URL.Query().Get("tenant")), strings.TrimSpace(r.URL.Query().Get("device")), strings.TrimSpace(r.URL.Query().Get("scope"))
		if tenant == "" || scope == "" || len(tenant) > 256 || len(device) > 256 || len(scope) > 1024 {
			writeError(w, 400, fmt.Errorf("invalid grant snapshot scope"))
			return
		}
		section := scopedGrantBundle(store, tenant, device, scope)
		if signer == nil || !section.Complete {
			writeError(w, 503, fmt.Errorf("signed grant authority unavailable"))
			return
		}
		version := authenticationGrantVersion(section)
		w.Header().Set("ETag", `"`+version+`"`)
		if r.Header.Get("If-None-Match") == `"`+version+`"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		envelope, err := signer.Sign(authenticationGrantSnapshot{Protocol: authenticationGrantProtocol, Nonce: nonce, Version: version, Tenant: tenant, Device: device, Scope: scope, Grants: section}, time.Now())
		if err != nil {
			writeError(w, 503, fmt.Errorf("grant snapshot signing unavailable"))
			return
		}
		writeJSON(w, 200, envelope)
	}))
}

// Only grant evidence for this tenant, device and destination is refreshed on a
// miss; policy/config stores are never read here. Concurrent decisions for the
// same scope share the in-flight result. A missing snapshot route cannot prove
// a grant miss, so it cannot start a new ceremony. Local grants remain usable.
func newAuthGrantRefresh(source *configBundleSource, store *grantstore.Store) func(string, string, string) bool {
	if source == nil || store == nil {
		return nil
	}
	type refreshCall struct {
		done    chan struct{}
		last    time.Time
		ok      bool
		version string
		busy    bool
	}
	var mu sync.Mutex
	calls := make(map[string]*refreshCall)
	return func(tenant, device, scope string) bool {
		if strings.TrimSpace(tenant) == "" || strings.TrimSpace(scope) == "" {
			return false
		}
		key := tenant + "\x00" + device + "\x00" + scope
		mu.Lock()
		call := calls[key]
		if call != nil && call.busy {
			waiting := call.done
			mu.Unlock()
			select {
			case <-waiting:
				mu.Lock()
				ok := call.ok
				mu.Unlock()
				return ok
			case <-time.After(3 * time.Second):
				return false
			}
		}
		if call != nil && time.Since(call.last) < time.Second {
			ok := call.ok
			mu.Unlock()
			return ok
		}
		if call == nil {
			call = &refreshCall{}
			calls[key] = call
		}
		previous := call.version
		call.busy, call.done, call.ok = true, make(chan struct{}), false
		// Expired cache entries never retain per-user scope data indefinitely.
		if len(calls) > 512 {
			for k, old := range calls {
				if !old.busy && time.Since(old.last) > 2*time.Second {
					delete(calls, k)
				}
			}
		}
		mu.Unlock()
		defer func() { mu.Lock(); call.last = time.Now(); call.busy = false; close(call.done); mu.Unlock() }()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		base := source.baseURL()
		if strings.TrimSpace(base) == "" || source.client == nil || len(source.acceptedVerifyKeys()) == 0 {
			return false
		}
		// Fresh nonce prevents replaying a signed snapshot from before a revocation.
		nonce, err := oidcbroker.NewOpaqueToken()
		if err != nil {
			return false
		}
		query := url.Values{"tenant": {tenant}, "device": {device}, "scope": {scope}}
		req, err := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(base, "/")+"/admin/authentication-grants?"+query.Encode(), nil)
		if err != nil {
			return false
		}
		req.Header.Set("Authorization", "Bearer "+source.token)
		req.Header.Set("X-DSSE-Grant-Nonce", nonce)
		if previous != "" {
			req.Header.Set("If-None-Match", `"`+previous+`"`)
		}
		client := *source.client
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		resp, err := client.Do(req)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNotModified && previous != "" && resp.Header.Get("ETag") == `"`+previous+`"` {
			mu.Lock()
			call.ok = true
			mu.Unlock()
			return true
		}
		if resp.StatusCode != http.StatusOK {
			return false
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, (16<<20)+1))
		if err != nil || len(data) > 16<<20 {
			return false
		}
		var envelope agentpolicy.Envelope
		if json.Unmarshal(data, &envelope) != nil {
			return false
		}
		verified, err := agentpolicy.VerifyAny(envelope, source.acceptedVerifyKeys())
		if err != nil {
			return false
		}
		var snapshot authenticationGrantSnapshot
		if json.Unmarshal(verified, &snapshot) != nil || snapshot.Protocol != authenticationGrantProtocol || snapshot.Nonce != nonce || snapshot.Tenant != tenant || snapshot.Device != device || snapshot.Scope != scope || snapshot.Grants == nil || snapshot.Version != authenticationGrantVersion(snapshot.Grants) {
			return false
		}
		if _, _, err := applyGrantBundleEvidence(store, snapshot.Grants, time.Now().UTC(), true); err == nil {
			mu.Lock()
			call.version = snapshot.Version
			call.ok = true
			mu.Unlock()
			return true
		}
		return false
	}
}
