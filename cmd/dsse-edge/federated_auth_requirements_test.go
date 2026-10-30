package main

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/grantstore"
	"github.com/lantern-networks/dsse-core/idpregistry"
	"github.com/lantern-networks/dsse-core/model"
)

func TestFederatedRequirementsMethodsAgeDestination(t *testing.T) {
	now := time.Now().UTC()
	age := int64(300)
	req := federatedRequirements{OSPrincipal: testAuthPrincipal, OSSession: testAuthSession, IdP: "corp", ACR: "2", AMR: []string{"pwd", "otp"}, MaxAgeSeconds: &age, Scope: "https://app.example:443"}
	store := grantstore.NewStore()
	gate := &federatedAuthGate{tenantID: "operator", grants: store}
	grant := grantstore.Grant{GrantID: "g", TenantID: "customer", DeviceID: "device", UserID: "user", IdPID: "corp", ACR: "2", AMR: []string{"pwd", "otp"}, AuthTime: now.Add(-time.Minute).Format(time.RFC3339), Scope: req.Scope}
	if _, err := store.Mint(authTestBindGrant(t, gate, grant), time.Hour, now); err != nil {
		t.Fatal(err)
	}
	if !gate.hasLiveGrantWithRequirements("customer", "device", req) {
		t.Fatal("matching fresh grant should release customer flow")
	}
	for _, change := range []func(*federatedRequirements){func(r *federatedRequirements) { r.IdP = "other" }, func(r *federatedRequirements) { r.AMR = []string{"phr"} }, func(r *federatedRequirements) { v := int64(30); r.MaxAgeSeconds = &v }, func(r *federatedRequirements) { r.Scope = "https://other.example:443" }, func(r *federatedRequirements) { r.Invalid = true }} {
		other := req
		change(&other)
		if gate.hasLiveGrantWithRequirements("customer", "device", other) {
			t.Fatal("insufficient requirement admitted")
		}
	}
	if gate.hasLiveGrantWithRequirements("operator", "device", req) {
		t.Fatal("held flow must use the customer's tenant")
	}
	if requirementsMatchGrant(grant.AMR, "", grant.Scope, req, now) {
		t.Fatal("mint time cannot substitute for unknown auth_time")
	}
	if requirementsMatchGrant(grant.AMR, now.Add(time.Minute).Format(time.RFC3339), grant.Scope, req, now) {
		t.Fatal("future authentication must not extend age")
	}
}

func TestFederatedSignedRequirementsCannotBeChanged(t *testing.T) {
	signer, _ := newDeviceBindingSigner()
	reg := idpregistry.NewStore()
	_, err := reg.Upsert(idpregistry.Connection{IdPID: "corp", TenantID: "customer", Type: "oidc", Issuer: "https://idp.example", AuthorizationEndpoint: "https://idp.example/auth", ClientID: "client", VerifiedDomains: []string{"example"}})
	if err != nil {
		t.Fatal(err)
	}
	gate := &federatedAuthGate{brokerBaseURL: "https://portal.example", tenantID: "operator", signer: signer}
	age := int64(300)
	req := federatedRequirements{OSPrincipal: testAuthPrincipal, OSSession: testAuthSession, IdP: "corp", ACR: "2", AMR: []string{"pwd", "otp"}, MaxAgeSeconds: &age, GrantTTLSeconds: &age, Scope: "app:22"}
	link := gate.stepUpURLWithRequirements("app:22", "device", "customer", req)
	u, _ := url.Parse(link)
	authTestAssign(t, reg, "customer", "device", "user", "corp")
	broker := newClientlessBroker(reg, grantstore.NewStore(), nil, "https://portal.example", "operator", time.Hour, signer)
	rec := httptest.NewRecorder()
	broker.startForTest(rec, httptest.NewRequest("GET", link, nil))
	if rec.Code != 302 {
		t.Fatalf("valid signed request failed: %d %s", rec.Code, rec.Body.String())
	}
	idp, _ := url.Parse(rec.Header().Get("Location"))
	if idp.Query().Get("max_age") != "300" {
		t.Fatal("must request IdP freshness")
	}
	for _, key := range []string{"idp", "acr", "amr", "max_age", "grant_ttl", "return_to", "requirements_sig"} {
		q := u.Query()
		q.Set(key, "tampered")
		rec = httptest.NewRecorder()
		broker.startForTest(rec, httptest.NewRequest("GET", "/clientless/auth/start?"+q.Encode(), nil))
		if rec.Code != 401 {
			t.Fatalf("%s tampering admitted: %d", key, rec.Code)
		}
		q = u.Query()
		q.Del(key)
		rec = httptest.NewRecorder()
		broker.startForTest(rec, httptest.NewRequest("GET", "/clientless/auth/start?"+q.Encode(), nil))
		if rec.Code != 401 {
			t.Fatalf("%s removal admitted: %d", key, rec.Code)
		}
	}
	if len(broker.pending) != 1 {
		t.Fatal("tampered requests must not create pending state")
	}
}

func TestFederatedRequirementsReadPolicyMetadata(t *testing.T) {
	dec := model.AccessDecision{Actions: []model.DecisionAction{{Type: "prompt_reauthentication", Metadata: map[string]any{"required_amr": []any{"pwd", "otp"}, "max_age_seconds": float64(60)}}}}
	req := authFlowRequirements(dec, "https://APP.example/path?private=value")
	if req.Invalid || req.Scope != "https://app.example:443" || len(req.AMR) != 2 || req.MaxAgeSeconds == nil || *req.MaxAgeSeconds != 60 {
		t.Fatalf("requirements lost: %+v", req)
	}
	dec.Actions[0].Metadata["max_age_seconds"] = 1.5
	if !authFlowRequirements(dec, "app:22").Invalid {
		t.Fatal("fractional metadata must fail closed")
	}
}

func TestFreshAuthenticationEvidenceRequiresOriginalRequest(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	zero := int64(0)
	req := federatedRequirements{OSPrincipal: testAuthPrincipal, OSSession: testAuthSession, IdP: "corp", Scope: "app:22", MaxAgeSeconds: &zero}
	s := grantstore.NewStore()
	g := &federatedAuthGate{grants: s}
	ordinary := grantstore.Grant{GrantID: "ordinary", TenantID: "tenant", DeviceID: "device", UserID: "user", IdPID: "corp", Scope: req.Scope, AuthTime: now.Add(-time.Minute).Format(time.RFC3339), Issuer: "https://idp.example", ProviderConfigSHA256: strings.Repeat("a", 64)}
	if _, err := s.Mint(authTestBindGrant(t, g, ordinary), time.Hour, now); err != nil {
		t.Fatal(err)
	}
	if g.hasLiveGrantWithRequirements("tenant", "device", req) {
		t.Fatal("ordinary SSO satisfied fresh-auth requirement")
	}
	fresh := ordinary
	fresh.GrantID = "fresh"
	fresh.ReauthenticationStartedAt = now.Add(-2 * time.Minute).Format(time.RFC3339)
	fresh.AuthenticationRequestID = "original-request"
	if _, err := s.Mint(authTestBindGrant(t, g, fresh), time.Hour, now); err != nil {
		t.Fatal(err)
	}
	if g.hasLiveGrantWithRequirements("tenant", "device", req) {
		t.Fatal("unbound request accepted")
	}
	req.RequestID = "original-request"
	if !g.hasLiveGrantWithRequirements("tenant", "device", req) {
		t.Fatal("original request refused")
	}
	reconnect := req
	reconnect.RequestID = "new-request"
	if g.hasLiveGrantWithRequirements("tenant", "device", reconnect) {
		t.Fatal("new request borrowed old evidence")
	}
	other := req
	other.Scope = "other:22"
	if g.hasLiveGrantWithRequirements("tenant", "device", other) {
		t.Fatal("fresh result escaped its scope")
	}
	s.Revoke("fresh")
	if g.hasLiveGrantWithRequirements("tenant", "device", req) {
		t.Fatal("revoked freshness reused")
	}
	bad := ordinary
	bad.GrantID = "bad"
	bad.ReauthenticationStartedAt = now.Format(time.RFC3339)
	if _, err := s.Mint(bad, time.Hour, now); err == nil {
		t.Fatal("old auth_time relabeled fresh")
	}
}
