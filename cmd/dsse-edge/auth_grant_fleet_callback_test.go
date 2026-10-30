package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/grantstore"
	"github.com/lantern-networks/dsse-core/idpregistry"
)

func TestSignedStartCannotRemintAfterShortGrantExpiry(t *testing.T) {
	store := grantstore.NewStore()
	id := newDeviceBindingSignerFromSecret("fleet-test-signing-key").grantIDForRequest("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	now := time.Now().UTC()
	if _, err := store.Mint(grantstore.Grant{GrantID: id, TenantID: "tenant"}, time.Second, now); err != nil {
		t.Fatal(err)
	}
	// A start accepted near its two-minute deadline can finish a further ten
	// minutes later. Even a one-second grant must retain its expired row through
	// that full horizon, so a restarted Portal cannot mint it again.
	lateCallback := now.Add(authStartTTL + pendingAuthTTL + time.Second)
	if _, err := store.PruneExpired(context.Background(), lateCallback); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Mint(grantstore.Grant{GrantID: id, TenantID: "tenant"}, time.Hour, lateCallback); !errors.Is(err, grantstore.ErrConflict) {
		t.Fatalf("expired grant was reissued while the signed start may be in flight: %v", err)
	}
}

// A browser can open the same signed start on another Portal after a restart.
// Both callbacks may validate, but the shared authority must issue one grant.
func TestSignedStartAcrossPortalsIssuesOneGrant(t *testing.T) {
	key, jwks := brokerTestKeyJWKS(t)
	var issuer string
	nonces := map[string]string{}
	idp := http.NewServeMux()
	idp.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		code := q.Get("state")
		nonces[code] = q.Get("nonce")
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(code), http.StatusFound)
	})
	idp.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		claims := map[string]any{
			"iss": issuer, "aud": "client", "sub": "user", "nonce": nonces[r.Form.Get("code")],
			"email": "user@example.com", "email_verified": true,
			"exp": time.Now().Add(time.Hour).Unix(), "acr": "AAL2",
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": brokerSignJWT(t, key, claims), "token_type": "Bearer"})
	})
	idp.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(jwks) })
	server := httptest.NewServer(idp)
	defer server.Close()
	issuer = server.URL

	registry := idpregistry.NewStore()
	if _, err := registry.Upsert(idpregistry.Connection{
		IdPID: "corp", TenantID: "tenant", Type: "oidc", Issuer: issuer,
		AuthorizationEndpoint: issuer + "/authorize", TokenEndpoint: issuer + "/token", JWKSURI: issuer + "/jwks",
		ClientID: "client", VerifiedDomains: []string{"example.com"}, DomainMode: "email_domain",
	}); err != nil {
		t.Fatal(err)
	}
	authTestAssign(t, registry, "tenant", "device", "user", "corp")
	signer := newDeviceBindingSignerFromSecret("fleet-test-signing-key")
	store := grantstore.NewStore()
	gate := &federatedAuthGate{registry: registry, signer: signer, brokerBaseURL: "https://portal.example", tenantID: "tenant", grants: store}
	link := authTestSignedLink(gate, gate.stepUpURLFor("app.example:22", "corp", "", "device", "tenant"))
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	wantID := signer.grantIDForRequest(parsed.Query().Get("request_id"))
	portals := []*clientlessBroker{
		newClientlessBroker(registry, store, server.Client(), "https://portal.example", "tenant", time.Hour, signer),
		newClientlessBroker(registry, store, server.Client(), "https://portal.example", "tenant", time.Hour, signer),
	}
	var cookie *http.Cookie
	var callbacks []*http.Request
	for i, portal := range portals {
		request := httptest.NewRequest(http.MethodGet, link, nil)
		if cookie != nil {
			request.AddCookie(cookie)
		}
		start := httptest.NewRecorder()
		portal.startForTest(start, request)
		if start.Code != http.StatusFound {
			t.Fatalf("portal %d start: %d %s", i, start.Code, start.Body.String())
		}
		if cookie == nil {
			for _, c := range start.Result().Cookies() {
				if c.Name == authSessionCookie {
					cookie = c
				}
			}
			if cookie == nil {
				t.Fatal("browser session cookie missing")
			}
		}
		noRedirect := *server.Client()
		noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		response, err := noRedirect.Get(start.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		callback, err := url.Parse(response.Header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		request = httptest.NewRequest(http.MethodGet, "https://portal.example/clientless/auth/callback?"+callback.RawQuery, nil)
		request.AddCookie(cookie)
		callbacks = append(callbacks, request)
	}
	misrouted := httptest.NewRecorder()
	portals[1].handleCallback(misrouted, callbacks[0])
	if misrouted.Code == http.StatusOK || len(store.ListAll()) != 0 {
		t.Fatal("a callback from another Portal's in-memory ceremony must not issue a grant")
	}
	for i, portal := range portals {
		result := httptest.NewRecorder()
		portal.handleCallback(result, callbacks[i])
		want := http.StatusOK
		if i == 1 {
			want = http.StatusServiceUnavailable
		}
		if result.Code != want {
			t.Fatalf("portal %d callback: got %d, want %d: %s", i, result.Code, want, result.Body.String())
		}
	}
	rows := store.ListAll()
	if len(rows) != 1 || rows[0].GrantID != wantID {
		t.Fatalf("same signed request produced %d grants or the wrong grant ID", len(rows))
	}
}
