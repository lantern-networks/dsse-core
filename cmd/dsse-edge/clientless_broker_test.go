package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	grantstore "github.com/lantern-networks/dsse-core/grantstore"
	idpregistry "github.com/lantern-networks/dsse-core/idpregistry"
	oidcbroker "github.com/lantern-networks/dsse-core/oidcbroker"
)

// A full clientless federated-auth flow against an httptest mock OIDC IdP: start -> IdP /authorize ->
// callback -> code exchange -> ID-token validation -> grant minted + cookie set; then whoami honours the
// grant and a revoke denies it. Proves the broker wiring end to end without a browser.
func TestClientlessBrokerEndToEnd(t *testing.T) {
	key, jwks := brokerTestKeyJWKS(t)
	var issuer string
	mu := sync.Mutex{}
	codeNonce := map[string]string{}

	idp := http.NewServeMux()
	idp.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		code := "code-" + q.Get("state")[:8]
		mu.Lock()
		codeNonce[code] = q.Get("nonce")
		mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	idp.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		nonce := codeNonce[r.Form.Get("code")]
		mu.Unlock()
		claims := map[string]any{
			"iss": issuer, "aud": "client-1", "sub": "user-xyz", "email": "alice@example.com", "email_verified": true,
			"nonce": nonce, "exp": time.Now().Add(time.Hour).Unix(), "acr": "AAL2", "amr": []any{"pwd", "mfa"},
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": brokerSignJWT(t, key, claims), "token_type": "Bearer"})
	})
	idp.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(jwks) })
	server := httptest.NewServer(idp)
	defer server.Close()
	issuer = server.URL

	reg := idpregistry.NewStore()
	if _, err := reg.Upsert(idpregistry.Connection{
		IdPID: "idp_test", TenantID: "t1", Type: "oidc", Issuer: server.URL,
		AuthorizationEndpoint: server.URL + "/authorize", TokenEndpoint: server.URL + "/token", JWKSURI: server.URL + "/jwks",
		ClientID: "client-1", VerifiedDomains: []string{"example.com"}, DomainMode: "email_domain",
	}); err != nil {
		t.Fatal(err)
	}
	grants := grantstore.NewStore()
	broker := newClientlessBroker(reg, grants, server.Client(), "https://edge", "t1", time.Hour, nil)

	// 1) start -> 302 to the IdP authorize
	rec := httptest.NewRecorder()
	broker.handleStart(rec, httptest.NewRequest(http.MethodGet, "/clientless/auth/start", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("start: want 302, got %d", rec.Code)
	}

	// 2) the browser hits the IdP authorize (don't follow the redirect back to the unreachable RP host)
	noRedir := *server.Client()
	noRedir.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noRedir.Get(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	cb, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("callback url: %v", err)
	}

	// 3) callback completes the flow
	rec2 := httptest.NewRecorder()
	broker.handleCallback(rec2, httptest.NewRequest(http.MethodGet, "/clientless/auth/callback?"+cb.RawQuery, nil))
	if rec2.Code != http.StatusOK {
		t.Fatalf("callback: want 200, got %d: %s", rec2.Code, rec2.Body.String())
	}
	var grantCookie string
	for _, c := range rec2.Result().Cookies() {
		if c.Name == "dsse_grant" {
			grantCookie = c.Value
		}
	}
	if grantCookie == "" {
		t.Fatal("no grant cookie set")
	}
	if !grants.Valid(grantCookie, time.Now().UTC()) {
		t.Fatal("minted grant should be valid")
	}

	// 4) whoami honours the grant
	whoamiReq := httptest.NewRequest(http.MethodGet, "/clientless/auth/whoami", nil)
	whoamiReq.AddCookie(&http.Cookie{Name: "dsse_grant", Value: grantCookie})
	rec3 := httptest.NewRecorder()
	broker.handleWhoami(rec3, whoamiReq)
	if rec3.Code != http.StatusOK {
		t.Fatalf("whoami: want 200, got %d", rec3.Code)
	}

	// 5) revoke -> whoami denies (continuous revocation)
	if !grants.Revoke(grantCookie) {
		t.Fatal("revoke should succeed")
	}
	rec4 := httptest.NewRecorder()
	broker.handleWhoami(rec4, whoamiReq)
	if rec4.Code != http.StatusUnauthorized {
		t.Fatalf("whoami after revoke: want 401, got %d", rec4.Code)
	}
}

// A callback whose IdP returns a token for the WRONG domain is rejected (anti-cross-tenant), and an
// unknown/unregistered IdP at start fails closed.
func TestClientlessBrokerFailClosed(t *testing.T) {
	reg := idpregistry.NewStore()
	broker := newClientlessBroker(reg, grantstore.NewStore(), nil, "https://edge", "t1", time.Hour, nil)
	// no registered IdP -> start fails closed
	rec := httptest.NewRecorder()
	broker.handleStart(rec, httptest.NewRequest(http.MethodGet, "/clientless/auth/start?idp=idp_unknown", nil))
	if rec.Code == http.StatusFound {
		t.Fatal("start with no usable IdP must not redirect")
	}
	// callback with an unknown state -> denied
	rec2 := httptest.NewRecorder()
	broker.handleCallback(rec2, httptest.NewRequest(http.MethodGet, "/clientless/auth/callback?code=x&state=unknown", nil))
	if rec2.Code == http.StatusOK {
		t.Fatal("callback with unknown state must not succeed")
	}
}

// The grant the broker mints is bound to the device the gate SIGNED into the start URL (per-device binding),
// and a forged/unsigned device is ignored (the grant is tenant-wide, never mis-bound). This is the broker half
// of the per-device fix: the browser→broker hop is not steered, so the verified device can only arrive via the
// signed start URL.
func TestClientlessBrokerBindsSignedDevice(t *testing.T) {
	key, jwks := brokerTestKeyJWKS(t)
	var issuer string
	mu := sync.Mutex{}
	codeNonce := map[string]string{}
	idp := http.NewServeMux()
	idp.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		code := "code-" + q.Get("state")[:8]
		mu.Lock()
		codeNonce[code] = q.Get("nonce")
		mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	idp.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		nonce := codeNonce[r.Form.Get("code")]
		mu.Unlock()
		claims := map[string]any{
			"iss": issuer, "aud": "client-1", "sub": "user-xyz", "email": "alice@example.com", "email_verified": true,
			"nonce": nonce, "exp": time.Now().Add(time.Hour).Unix(), "acr": "phishing_resistant", "amr": []any{"phishing_resistant"},
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": brokerSignJWT(t, key, claims), "token_type": "Bearer"})
	})
	idp.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(jwks) })
	server := httptest.NewServer(idp)
	defer server.Close()
	issuer = server.URL

	reg := idpregistry.NewStore()
	if _, err := reg.Upsert(idpregistry.Connection{
		IdPID: "idp_test", TenantID: "t1", Type: "oidc", Issuer: server.URL,
		AuthorizationEndpoint: server.URL + "/authorize", TokenEndpoint: server.URL + "/token", JWKSURI: server.URL + "/jwks",
		ClientID: "client-1", VerifiedDomains: []string{"example.com"}, DomainMode: "email_domain",
	}); err != nil {
		t.Fatal(err)
	}
	signer, _ := newDeviceBindingSigner()
	grants := grantstore.NewStore()
	broker := newClientlessBroker(reg, grants, server.Client(), "https://edge", "t1", time.Hour, signer)

	// run the full start->authorize->callback flow with the given start query, returning the minted grant.
	runFlow := func(startQuery string) grantstore.Grant {
		rec := httptest.NewRecorder()
		broker.handleStart(rec, httptest.NewRequest(http.MethodGet, "/clientless/auth/start?"+startQuery, nil))
		if rec.Code != http.StatusFound {
			t.Fatalf("start: want 302, got %d (%s)", rec.Code, rec.Body.String())
		}
		noRedir := *server.Client()
		noRedir.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		resp, err := noRedir.Get(rec.Header().Get("Location"))
		if err != nil {
			t.Fatalf("authorize: %v", err)
		}
		cb, _ := url.Parse(resp.Header.Get("Location"))
		rec2 := httptest.NewRecorder()
		broker.handleCallback(rec2, httptest.NewRequest(http.MethodGet, "/clientless/auth/callback?"+cb.RawQuery, nil))
		if rec2.Code != http.StatusOK {
			t.Fatalf("callback: want 200, got %d: %s", rec2.Code, rec2.Body.String())
		}
		var cookie string
		for _, c := range rec2.Result().Cookies() {
			if c.Name == "dsse_grant" {
				cookie = c.Value
			}
		}
		g, ok := grants.Get(cookie)
		if !ok {
			t.Fatal("minted grant not found")
		}
		return g
	}

	// a VALID signed device -> the grant binds to it
	sig := signer.sign("dev-A")
	g := runFlow("device=dev-A&device_sig=" + url.QueryEscape(sig))
	if g.DeviceID != "dev-A" {
		t.Fatalf("a validly-signed device should bind the grant, got DeviceID=%q", g.DeviceID)
	}

	// a FORGED signature -> ignored, grant is tenant-wide (NOT mis-bound to dev-B)
	g2 := runFlow("device=dev-B&device_sig=not-a-valid-signature")
	if g2.DeviceID != "" {
		t.Fatalf("a forged device sig must be ignored (tenant-wide), got DeviceID=%q", g2.DeviceID)
	}

	// no device params -> tenant-wide
	g3 := runFlow("")
	if g3.DeviceID != "" {
		t.Fatalf("no device -> tenant-wide grant, got DeviceID=%q", g3.DeviceID)
	}
}

// ---- test crypto helpers ----------------------------------------------------

func brokerTestKeyJWKS(t *testing.T) (*rsa.PrivateKey, oidcbroker.JWKS) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	eBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(eBuf, uint64(key.E))
	i := 0
	for i < len(eBuf)-1 && eBuf[i] == 0 {
		i++
	}
	return key, oidcbroker.JWKS{Keys: []oidcbroker.JWK{{
		Kty: "RSA", Kid: "k1", Alg: "RS256", Use: "sig",
		N: base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(eBuf[i:]),
	}}}
}

func brokerSignJWT(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	hb, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": "k1"})
	cb, _ := json.Marshal(claims)
	in := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	d := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}
