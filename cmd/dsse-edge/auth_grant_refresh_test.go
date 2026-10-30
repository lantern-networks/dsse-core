package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/grantstore"
	"github.com/lantern-networks/dsse-core/oidcbroker"
)

func TestGrantMissRefreshesSignedAuthorityBeforeNewCeremony(t *testing.T) {
	for _, mode := range []string{"signed", "signed-empty", "unsigned", "wrong-signer", "wrong-nonce", "wrong-version", "wrong-protocol", "incomplete", "unavailable", "old-cp"} {
		t.Run(mode, func(t *testing.T) {
			signer, err := agentpolicy.LoadOrGenerateSigner("", true)
			if err != nil {
				t.Fatal(err)
			}
			authority := grantstore.NewStore()
			edge := grantstore.NewStore()
			gate := &federatedAuthGate{grants: edge}
			now := time.Now().UTC().Truncate(time.Second)
			grant := authTestBindGrant(t, gate, grantstore.Grant{GrantID: "fresh-at-another-portal", TenantID: "tenant", DeviceID: "device", UserID: "user", IdPID: "corp", Scope: "app:22", AuthTime: now.Format(time.RFC3339)})
			if _, err := authority.Mint(grant, 5*time.Minute, now); err != nil {
				t.Fatal(err)
			}
			payload := authenticationGrantSnapshot{Protocol: authenticationGrantProtocol, Grants: grantBundleSection(authority)}
			if mode == "signed-empty" {
				payload.Grants = grantBundleSection(grantstore.NewStore())
			}
			if mode == "incomplete" {
				payload.Grants.Complete = false
			}
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.Path != "/admin/authentication-grants" || r.Header.Get("Authorization") != "Bearer test-admin" {
					t.Error("wrong authority request")
				}
				if mode == "unavailable" {
					w.WriteHeader(503)
					return
				}
				if mode == "old-cp" {
					w.WriteHeader(404)
					return
				}
				payload.Nonce = r.Header.Get("X-DSSE-Grant-Nonce")
				payload.Tenant, payload.Device, payload.Scope = r.URL.Query().Get("tenant"), r.URL.Query().Get("device"), r.URL.Query().Get("scope")
				payload.Version = authenticationGrantVersion(payload.Grants)
				if mode == "wrong-nonce" {
					payload.Nonce = "a-prior-response"
				}
				if mode == "wrong-version" {
					payload.Version = "a-prior-version"
				}
				if mode == "wrong-protocol" {
					payload.Protocol = "config-bundle"
				}
				if mode == "unsigned" {
					_ = json.NewEncoder(w).Encode(payload)
					return
				}
				issuer := signer
				if mode == "wrong-signer" {
					issuer, _ = agentpolicy.LoadOrGenerateSigner("", true)
				}
				envelope, err := issuer.Sign(payload, now)
				if err != nil {
					t.Error(err)
					w.WriteHeader(500)
					return
				}
				_ = json.NewEncoder(w).Encode(envelope)
			}))
			defer server.Close()
			source := &configBundleSource{url: server.URL, token: "test-admin", client: server.Client(), verifyPubKeyHex: signer.PublicKeyHex(), requireSigned: true}
			gate.refreshGrants = newAuthGrantRefresh(source, edge)
			req := federatedRequirements{IdP: "corp", Scope: "app:22", OSPrincipal: testAuthPrincipal, OSSession: testAuthSession}
			if got := gate.hasLiveGrantWithRequirements("tenant", "device", req); got != (mode == "signed") {
				t.Fatalf("authorization=%v mode=%s", got, mode)
			}
			_, _, statusErr := gate.liveGrantStatusWithRequirements("tenant", "device", req)
			if unavailable := mode != "signed" && mode != "signed-empty"; (statusErr != nil) != unavailable {
				t.Fatalf("authority status error=%v mode=%s", statusErr, mode)
			}
			if mode == "signed" {
				if gate.hasLiveGrantWithRequirements("other-tenant", "device", req) || gate.hasLiveGrantWithRequirements("tenant", "other-device", req) {
					t.Fatal("imported evidence escaped tenant/device binding")
				}
				changed := req
				changed.OSSession = "different-session"
				if gate.hasLiveGrantWithRequirements("tenant", "device", changed) {
					t.Fatal("imported evidence escaped OS session binding")
				}
				expired := req
				// Verify importing evidence does not bypass current policy checks.
				expired.GrantTTLSeconds = new(int64)
				if gate.hasLiveGrantWithRequirements("tenant", "device", expired) {
					t.Fatal("import bypassed current policy cap")
				}
			}
			before := calls.Load()
			var wg sync.WaitGroup
			for i := 0; i < 20; i++ {
				wg.Add(1)
				go func() { defer wg.Done(); gate.refreshGrants("tenant", "device", "app:22") }()
			}
			wg.Wait()
			if calls.Load() > before+1 {
				t.Fatal("held-flow polls caused duplicate authority reads")
			}
		})
	}
}

func TestGrantRefreshConcurrentMissesShareSlowCPResult(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-release; w.WriteHeader(503) }))
	defer server.Close()
	signer, _ := agentpolicy.LoadOrGenerateSigner("", true)
	refresh := newAuthGrantRefresh(&configBundleSource{url: server.URL, client: server.Client(), verifyPubKeyHex: signer.PublicKeyHex()}, grantstore.NewStore())
	done := make(chan struct{})
	go func() { defer close(done); refresh("tenant", "device", "app:22") }()
	<-entered
	concurrent := make(chan struct{})
	go func() { defer close(concurrent); refresh("tenant", "device", "app:22") }()
	select {
	case <-concurrent:
		close(release)
		t.Fatal("concurrent grant miss did not wait for the in-flight authority result")
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	select {
	case <-concurrent:
	case <-time.After(time.Second):
		t.Fatal("concurrent grant miss did not finish after authority response")
	}
	<-done
}

func TestGrantSnapshotNotModifiedMustMatchVerifiedVersion(t *testing.T) {
	signer, err := agentpolicy.LoadOrGenerateSigner("", true)
	if err != nil {
		t.Fatal(err)
	}
	section := grantBundleSection(grantstore.NewStore())
	version := authenticationGrantVersion(section)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch calls.Add(1) {
		case 1:
			snapshot := authenticationGrantSnapshot{Protocol: authenticationGrantProtocol, Nonce: r.Header.Get("X-DSSE-Grant-Nonce"), Version: version, Tenant: r.URL.Query().Get("tenant"), Device: r.URL.Query().Get("device"), Scope: r.URL.Query().Get("scope"), Grants: section}
			envelope, signErr := signer.Sign(snapshot, time.Now())
			if signErr != nil {
				t.Error(signErr)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(envelope)
		case 2:
			w.Header().Set("ETag", `"wrong-version"`)
			w.WriteHeader(http.StatusNotModified)
		default:
			if r.Header.Get("If-None-Match") != `"`+version+`"` {
				t.Error("conditional request lost verified version")
			}
			w.Header().Set("ETag", `"`+version+`"`)
			w.WriteHeader(http.StatusNotModified)
		}
	}))
	defer server.Close()
	refresh := newAuthGrantRefresh(&configBundleSource{url: server.URL, client: server.Client(), verifyPubKeyHex: signer.PublicKeyHex()}, grantstore.NewStore())
	if !refresh("tenant", "device", "app:22") {
		t.Fatal("signed empty authority was not accepted")
	}
	time.Sleep(1100 * time.Millisecond)
	if refresh("tenant", "device", "app:22") {
		t.Fatal("304 with a different ETag reused prior authority evidence")
	}
	time.Sleep(1100 * time.Millisecond)
	if !refresh("tenant", "device", "app:22") || calls.Load() != 3 {
		t.Fatal("matching 304 did not preserve verified authority evidence")
	}
}

func TestMissingGrantStoreDoesNotStartAnotherCeremony(t *testing.T) {
	gate := &federatedAuthGate{brokerBaseURL: "https://portal.example"}
	_, _, err := gate.liveGrantStatusWithRequirements("tenant", "device", federatedRequirements{Scope: "app:22"})
	if !errors.Is(err, errAuthenticationGrantAuthorityUnavailable) {
		t.Fatalf("missing grant store was treated as an ordinary grant miss: %v", err)
	}
}

func TestConfirmedLocalGrantIsNotDiscardedByFocusedAuthorityOutage(t *testing.T) {
	store := grantstore.NewStore()
	gate := &federatedAuthGate{grants: store, refreshGrants: func(string, string, string) bool {
		t.Fatal("a matching live grant must not trigger an authority refresh")
		return false
	}}
	if _, err := store.Mint(grantstore.Grant{GrantID: "existing", TenantID: "tenant", UserID: "user", IdPID: "corp", Scope: "app:22"}, time.Minute, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, matched, err := gate.liveGrantStatusWithRequirements("tenant", "", federatedRequirements{Scope: "app:22"}); !matched || err != nil {
		t.Fatalf("confirmed local grant lost during authority outage: matched=%v err=%v", matched, err)
	}
}

func TestGrantSnapshotConditionalVersionAndManagementAuthorization(t *testing.T) {
	signer, _ := agentpolicy.LoadOrGenerateSigner("", true)
	store := grantstore.NewStore()
	if _, err := store.Mint(grantstore.Grant{GrantID: "one", TenantID: "tenant", DeviceID: "device", Scope: "app:22"}, time.Minute, time.Now()); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerAuthenticationGrantSnapshot(mux, func(permission string, h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if permission != "admin.policy.read" || r.Header.Get("Authorization") != "Bearer fixture" {
				w.WriteHeader(403)
				return
			}
			h(w, r)
		}
	}, store, signer, "", "")
	var prior string
	blocked := httptest.NewRecorder()
	dataPlaneOnlyMiddleware(mux).ServeHTTP(blocked, httptest.NewRequest("GET", "/admin/authentication-grants", nil))
	if blocked.Code != 404 {
		t.Fatal("grant snapshot exposed on data listener")
	}
	for _, status := range []int{403, 200, 304, 200} {
		req := httptest.NewRequest("GET", "/admin/authentication-grants?tenant=tenant&device=device&scope=app%3A22", nil)
		nonce, _ := oidcbroker.NewOpaqueToken()
		req.Header.Set("X-DSSE-Grant-Nonce", nonce)
		if status != 403 {
			req.Header.Set("Authorization", "Bearer fixture")
		}
		if prior != "" {
			req.Header.Set("If-None-Match", prior)
		}
		if status == 200 && prior != "" {
			if _, _, err := store.RequireReauthenticationForTenantContext(context.Background(), "tenant", "one", time.Now()); err != nil {
				t.Fatal(err)
			}
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != status {
			t.Fatalf("status=%d want=%d", w.Code, status)
		}
		if status == 200 {
			var envelope agentpolicy.Envelope
			if json.Unmarshal(w.Body.Bytes(), &envelope) != nil {
				t.Fatal("unsigned snapshot")
			}
			data, err := agentpolicy.VerifyAny(envelope, []string{signer.PublicKeyHex()})
			if err != nil {
				t.Fatal(err)
			}
			var snapshot authenticationGrantSnapshot
			if json.Unmarshal(data, &snapshot) != nil || snapshot.Protocol != authenticationGrantProtocol || snapshot.Nonce != nonce || snapshot.Version != authenticationGrantVersion(snapshot.Grants) {
				t.Fatal("snapshot is not bound to read")
			}
			prior = w.Header().Get("ETag")
		}
		if status == 304 && w.Body.Len() != 0 {
			t.Fatal("unchanged grants transferred full body")
		}
	}
	pulling := http.NewServeMux()
	registerAuthenticationGrantSnapshot(pulling, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, store, signer, "https://cp.example", "")
	w := httptest.NewRecorder()
	pulling.ServeHTTP(w, httptest.NewRequest("GET", "/admin/authentication-grants", nil))
	if w.Code != 404 {
		t.Fatal("Edge exposed authority snapshot")
	}
}

func TestGrantMissSnapshotStaysScopedWithLargeAuthority(t *testing.T) {
	signer, err := agentpolicy.LoadOrGenerateSigner("", true)
	if err != nil {
		t.Fatal(err)
	}
	authority, edge := grantstore.NewStore(), grantstore.NewStore()
	now := time.Now().UTC()
	grants := make([]grantstore.Grant, 0, 30001)
	for i := 0; i < 30000; i++ {
		grants = append(grants, grantstore.Grant{GrantID: fmt.Sprintf("other-%d", i), TenantID: "tenant", DeviceID: "other-device", Scope: "app:other", IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
	}
	grants = append(grants, grantstore.Grant{GrantID: "target", TenantID: "tenant", DeviceID: "device", Scope: "app:22", IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
	if _, _, err := authority.MergeAuthorityEvidence(grants, now); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerAuthenticationGrantSnapshot(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, authority, signer, "", "")
	server := httptest.NewServer(mux)
	defer server.Close()
	refresh := newAuthGrantRefresh(&configBundleSource{url: server.URL, client: server.Client(), verifyPubKeyHex: signer.PublicKeyHex()}, edge)
	if !refresh("tenant", "device", "app:22") {
		t.Fatal("large unrelated authority prevented focused login check")
	}
	if !refresh("tenant", "new-device", "app:new") {
		t.Fatal("large unrelated authority prevented a new user's empty-grant check")
	}
	rows, err := edge.ListChecked("tenant")
	if err != nil || len(rows) != 1 || rows[0].GrantID != "target" {
		t.Fatalf("focused evidence imported %d grants: %v", len(rows), err)
	}
}
