package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	grantstore "github.com/lantern-networks/dsse-core/grantstore"
)

func htmlReq() *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://accounts.google.com/", nil)
	r.Header.Set("Accept", "text/html,application/xhtml+xml")
	return r
}

func TestFederatedAuthGateRedirectCase(t *testing.T) {
	g := &federatedAuthGate{grants: grantstore.NewStore(), brokerBaseURL: "https://edge:8443", tenantID: "t1"}

	// an authenticate decision on a browser nav is a redirect case
	if !g.isAuthRedirectCase(htmlReq(), "require_reauthentication") {
		t.Fatal("authenticate + html should be a redirect case")
	}
	// a plain deny is not
	if g.isAuthRedirectCase(htmlReq(), "deny") {
		t.Fatal("deny must not be an auth redirect case")
	}
	// a non-browser flow cannot follow a redirect
	nonBrowser := httptest.NewRequest(http.MethodGet, "https://api.example.com/", nil)
	nonBrowser.Header.Set("Accept", "application/json")
	if g.isAuthRedirectCase(nonBrowser, "require_reauthentication") {
		t.Fatal("non-browser must not be a redirect case")
	}
	// no broker configured -> never
	if (&federatedAuthGate{}).isAuthRedirectCase(htmlReq(), "require_reauthentication") {
		t.Fatal("no broker base url must disable the gate")
	}
}

func TestFederatedAuthGateGrantGate(t *testing.T) {
	store := grantstore.NewStore()
	g := &federatedAuthGate{grants: store, brokerBaseURL: "https://edge:8443", tenantID: "t1"}
	now := time.Now().UTC()
	if g.hasLiveGrant("", "") {
		t.Fatal("no grant -> not authenticated")
	}
	if _, err := store.Mint(grantstore.Grant{GrantID: "g1", TenantID: "t1", UserID: "u1", IdPID: "idp_a"}, time.Hour, now); err != nil {
		t.Fatal(err)
	}
	if !g.hasLiveGrant("", "") {
		t.Fatal("a live grant -> authenticated")
	}
	store.Revoke("g1")
	if g.hasLiveGrant("", "") {
		t.Fatal("a revoked grant -> not authenticated")
	}
}

func TestFederatedAuthGatePerDeviceBinding(t *testing.T) {
	store := grantstore.NewStore()
	g := &federatedAuthGate{grants: store, brokerBaseURL: "https://edge:8443", tenantID: "t1"}
	now := time.Now().UTC()
	// a grant bound to device A
	if _, err := store.Mint(grantstore.Grant{GrantID: "gA", TenantID: "t1", UserID: "u1", IdPID: "idp_a", DeviceID: "dev-A"}, time.Hour, now); err != nil {
		t.Fatal(err)
	}
	if !g.hasLiveGrant("dev-A", "") {
		t.Fatal("device A's grant should satisfy device A")
	}
	if g.hasLiveGrant("dev-B", "") {
		t.Fatal("device A's grant must NOT satisfy device B (per-device binding)")
	}
}

func TestFederatedAuthGateStepUpACRGate(t *testing.T) {
	store := grantstore.NewStore()
	g := &federatedAuthGate{grants: store, brokerBaseURL: "https://edge:8443", tenantID: "t1"}
	now := time.Now().UTC()
	// a baseline grant (no acr) is minted
	if _, err := store.Mint(grantstore.Grant{GrantID: "gBase", TenantID: "t1", UserID: "u1", IdPID: "idp_a"}, time.Hour, now); err != nil {
		t.Fatal(err)
	}
	// presence-only (no step-up required) is satisfied
	if !g.hasLiveGrant("", "") {
		t.Fatal("a live grant should satisfy a resource with no step-up requirement")
	}
	// a step-up-gated resource (requires phr) is NOT satisfied by the baseline grant
	if g.hasLiveGrant("", "phr") {
		t.Fatal("a baseline grant (no acr) must NOT satisfy a phr-gated resource")
	}
	// a grant minted at the required assurance satisfies it
	if _, err := store.Mint(grantstore.Grant{GrantID: "gPhr", TenantID: "t1", UserID: "u1", IdPID: "idp_a", ACR: "phr"}, time.Hour, now); err != nil {
		t.Fatal(err)
	}
	if !g.hasLiveGrant("", "phr") {
		t.Fatal("a grant with acr=phr must satisfy a phr-gated resource")
	}
	// a different required acr is not satisfied by acr=phr (exact match, mirrors mint-time validation)
	if g.hasLiveGrant("", "urn:okta:loa:2fa:any") {
		t.Fatal("acr=phr must not satisfy a different required acr (exact match)")
	}
}

func TestDeviceBindingSigner(t *testing.T) {
	s, err := newDeviceBindingSigner()
	if err != nil {
		t.Fatal(err)
	}
	sig := s.sign("dev-A")
	if sig == "" {
		t.Fatal("signing a device should produce a signature")
	}
	if got := s.verifiedDevice("dev-A", sig); got != "dev-A" {
		t.Fatalf("a valid signature should verify the device, got %q", got)
	}
	if got := s.verifiedDevice("dev-B", sig); got != "" {
		t.Fatal("a signature for dev-A must NOT verify dev-B")
	}
	if got := s.verifiedDevice("dev-A", sig+"x"); got != "" {
		t.Fatal("a tampered signature must NOT verify")
	}
	if got := s.verifiedDevice("dev-A", ""); got != "" {
		t.Fatal("an empty signature must NOT verify (unsigned -> tenant-wide)")
	}
	// a DIFFERENT signer (different key) must reject the first signer's signature
	s2, _ := newDeviceBindingSigner()
	if got := s2.verifiedDevice("dev-A", sig); got != "" {
		t.Fatal("a foreign signer must not verify another signer's signature")
	}
	// nil signer signs/verifies nothing (tenant-wide fallback)
	var nilSigner *deviceBindingSigner
	if nilSigner.sign("dev-A") != "" || nilSigner.verifiedDevice("dev-A", "x") != "" {
		t.Fatal("nil signer must be inert")
	}
}

func TestStepUpURLCarriesSignedDevice(t *testing.T) {
	s, _ := newDeviceBindingSigner()
	g := &federatedAuthGate{brokerBaseURL: "https://edge:8443", signer: s}
	u := g.stepUpURL("10.0.0.7:445", "idp_corp", "phishing_resistant", "dev-A")
	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatal(err)
	}
	q := parsed.Query()
	if q.Get("device") != "dev-A" {
		t.Fatalf("start url should carry the device, got %q", q.Get("device"))
	}
	if s.verifiedDevice(q.Get("device"), q.Get("device_sig")) != "dev-A" {
		t.Fatal("the device_sig in the start url should verify against the signer")
	}
	// no device -> no device params (tenant-wide)
	u2 := g.stepUpURL("10.0.0.7:445", "idp_corp", "phishing_resistant", "")
	if strings.Contains(u2, "device=") {
		t.Fatalf("no device should mean no device param, got %s", u2)
	}
}

func TestFederatedAuthGateRedirectWrites302(t *testing.T) {
	g := &federatedAuthGate{grants: grantstore.NewStore(), brokerBaseURL: "https://edge:8443", tenantID: "t1"}
	rec := httptest.NewRecorder()
	g.redirectToIdP(rec, htmlReq(), "https://accounts.google.com/foo", "idp_priv", "phishing_resistant", "", "t1")
	if rec.Code != http.StatusFound {
		t.Fatalf("want 302, got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://edge:8443/clientless/auth/start?") {
		t.Fatalf("redirect to the broker start expected, got %s", loc)
	}
	if !strings.Contains(loc, "accounts.google.com") {
		t.Fatalf("return_to should carry the original resource, got %s", loc)
	}
	if !strings.Contains(loc, "idp=idp_priv") || !strings.Contains(loc, "acr=phishing_resistant") {
		t.Fatalf("redirect should carry the required idp + step-up acr, got %s", loc)
	}
}
