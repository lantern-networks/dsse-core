package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/grantstore"
	"github.com/lantern-networks/dsse-core/idpregistry"
)

func TestSealedCeremonySurvivesPortalLoss(t *testing.T) {
	cap := int64(15)
	t.Run("legacy-default-lifetime", func(t *testing.T) { testSealedCeremonySurvivesPortalLoss(t, nil) })
	t.Run("policy-capped-lifetime", func(t *testing.T) { testSealedCeremonySurvivesPortalLoss(t, &cap) })
}

func testSealedCeremonySurvivesPortalLoss(t *testing.T, grantTTL *int64, origins ...string) {
	origin := "https://portal.example"
	if len(origins) != 0 {
		origin = origins[0]
	}
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
	signer := newDeviceBindingSignerFromSecret("same-deployment-secret")
	store := grantstore.NewStore()
	gate := &federatedAuthGate{registry: registry, signer: signer, brokerBaseURL: origin, tenantID: "tenant", grants: store}
	startURL := authTestSignedLink(gate, gate.stepUpURLWithRequirements("app.example:22", "device", "tenant", federatedRequirements{IdP: "corp", GrantTTLSeconds: grantTTL, OSPrincipal: testAuthPrincipal, OSSession: testAuthSession}))
	makePortal := func(origin string, key *deviceBindingSigner) *clientlessBroker {
		b := newClientlessBroker(registry, store, server.Client(), origin, "tenant", time.Hour, key)
		b.recoverySharedKey = true
		return b
	}
	first := makePortal(origin, signer)
	second := makePortal(origin, signer)
	start := httptest.NewRecorder()
	first.startForTest(start, httptest.NewRequest(http.MethodGet, startURL, nil))
	if start.Code != http.StatusFound {
		t.Fatalf("start: %d %s", start.Code, start.Body.String())
	}
	var cookie *http.Cookie
	for _, c := range start.Result().Cookies() {
		if c.Name == authSessionCookie {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("browser binding missing")
	}
	noRedirect := *server.Client()
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := noRedirect.Get(start.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	callback := response.Header.Get("Location")
	if !strings.Contains(callback, sealedAuthStatePrefix) {
		t.Fatal("signed start did not use sealed state")
	}
	call := func(portal *clientlessBroker, withCookie bool, rawURL string) int {
		r := httptest.NewRequest(http.MethodGet, rawURL, nil)
		if withCookie {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		portal.handleCallback(w, r)
		return w.Code
	}
	if got := call(second, false, callback); got != http.StatusBadRequest {
		t.Fatalf("unbound browser callback: %d", got)
	}
	if got := call(makePortal("https://other.example", signer), true, callback); got != http.StatusBadRequest {
		t.Fatalf("different Portal origin: %d", got)
	}
	if got := call(makePortal(origin, newDeviceBindingSignerFromSecret("wrong-key")), true, callback); got != http.StatusBadRequest {
		t.Fatalf("different deployment key: %d", got)
	}
	bad, err := url.Parse(callback)
	if err != nil {
		t.Fatal(err)
	}
	q := bad.Query()
	q.Set("state", q.Get("state")+"A")
	bad.RawQuery = q.Encode()
	if got := call(second, true, bad.String()); got != http.StatusBadRequest {
		t.Fatalf("tampered state: %d", got)
	}
	if got := call(second, true, callback); got != http.StatusOK {
		t.Fatalf("new Portal could not finish ceremony: %d", got)
	}
	if got := call(first, true, callback); got == http.StatusOK {
		t.Fatal("old Portal replay minted another grant")
	}
	if got := call(first, true, callback); got != http.StatusBadRequest {
		t.Fatalf("finished local ceremony fell back to sealed state: %d", got)
	}
	if got := call(second, true, callback); got == http.StatusOK {
		t.Fatal("new Portal replay minted another grant")
	}
	rows := store.ListAll()
	if len(rows) != 1 {
		t.Fatalf("expected one grant, got %d", len(rows))
	}
	issued, _ := time.Parse(time.RFC3339, rows[0].IssuedAt)
	expires, _ := time.Parse(time.RFC3339, rows[0].ExpiresAt)
	wantTTL := time.Hour
	if grantTTL != nil {
		wantTTL = time.Duration(*grantTTL) * time.Second
	}
	if expires.Sub(issued) != wantTTL {
		t.Fatalf("recovered grant lifetime = %v, want %v", expires.Sub(issued), wantTTL)
	}
	if rows[0].Scope != "app.example:22" || !slices.Contains(rows[0].RequiredFeatures, grantstore.FeatureDeviceUser) || !slices.Contains(rows[0].RequiredFeatures, grantstore.FeatureScopedAuthorization) {
		t.Fatal("recovered callback lost the original scope or owner binding")
	}
	if !gate.hasLiveGrantWithRequirements("tenant", "device", federatedRequirements{
		IdP: "corp", Scope: "app.example:22", OSPrincipal: testAuthPrincipal, OSSession: testAuthSession,
	}) {
		t.Fatal("recovered sign-in could not satisfy its original destination")
	}
	if gate.hasLiveGrantWithRequirements("tenant", "device", federatedRequirements{
		IdP: "corp", Scope: "other.example:22", OSPrincipal: testAuthPrincipal, OSSession: testAuthSession,
	}) {
		t.Fatal("recovered sign-in authorized another destination")
	}
}
