package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/authrollout"
	"github.com/lantern-networks/dsse-core/grantstore"
	"github.com/lantern-networks/dsse-core/idpregistry"
)

func TestAuthIdentityGateSeparatesUserSessionAndAssignment(t *testing.T) {
	b, g := ceremonyFixture(t)
	grant := authTestBindGrant(t, g, grantstore.Grant{GrantID: "identity", TenantID: "tenant", DeviceID: "device", UserID: "alice", IdPID: "corp", Scope: "app:22"})
	if _, e := b.grants.Mint(grant, time.Hour, time.Now()); e != nil {
		t.Fatal(e)
	}
	req := federatedRequirements{IdP: "corp", Scope: "app:22", OSPrincipal: testAuthPrincipal, OSSession: testAuthSession}
	if !g.hasLiveGrantWithRequirements("tenant", "device", req) {
		t.Fatal("matching owner rejected")
	}
	for _, mutate := range []func(*federatedRequirements){func(r *federatedRequirements) { r.OSSession = strings.Repeat("b", 64) }, func(r *federatedRequirements) { r.OSPrincipal = "windows:S-1-5-21-100-200-300-1002" }, func(r *federatedRequirements) { r.OSPrincipal = "" }, func(r *federatedRequirements) { r.OSSession = "" }} {
		wrong := req
		mutate(&wrong)
		if g.hasLiveGrantWithRequirements("tenant", "device", wrong) {
			t.Fatal("different/missing owner authorized")
		}
	}
	if g.hasLiveGrantWithRequirements("other", "device", req) || g.hasLiveGrantWithRequirements("tenant", "other", req) {
		t.Fatal("tenant/device boundary crossed")
	}
	// A correctly signed token from a different subject cannot satisfy the gate.
	wrong := grant
	wrong.GrantID = "wrong-subject"
	wrong.UserID = "bob"
	if _, e := b.grants.Mint(wrong, time.Hour, time.Now()); e != nil {
		t.Fatal(e)
	}
	b.grants.Revoke(grant.GrantID)
	if g.hasLiveGrantWithRequirements("tenant", "device", req) {
		t.Fatal("different IdP subject authorized")
	}
	// Removing/recreating the same assignment must not reactivate old grants.
	grant.GrantID = "old-assignment"
	if _, e := b.grants.Mint(grant, time.Hour, time.Now()); e != nil {
		t.Fatal(e)
	}
	c, _ := b.registry.Get("tenant", "corp")
	c.DeviceUserBindings = []idpregistry.DeviceUserBinding{}
	if _, e := b.registry.Upsert(c); e != nil {
		t.Fatal(e)
	}
	authTestAssign(t, b.registry, "tenant", "device", "alice", "corp")
	if g.hasLiveGrantWithRequirements("tenant", "device", req) {
		t.Fatal("recreated assignment revived old grant")
	}
}

func TestAuthIdentityCallbackRejectsOtherSubjectAndChangedAssignment(t *testing.T) {
	for _, mode := range []string{"matching", "different-subject", "assignment-changed", "assignment-recreated", "unrelated-assignment-changed"} {
		t.Run(mode, func(t *testing.T) {
			key, jwks := brokerTestKeyJWKS(t)
			var issuer, nonce string
			subject := "alice"
			if mode == "different-subject" {
				subject = "bob"
			}
			mux := http.NewServeMux()
			mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]string{"id_token": brokerSignJWT(t, key, map[string]any{"iss": issuer, "aud": "client", "sub": subject, "email": subject + "@example.com", "email_verified": true, "nonce": nonce, "exp": time.Now().Add(time.Hour).Unix()})})
			})
			mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(jwks) })
			server := httptest.NewTLSServer(mux)
			defer server.Close()
			issuer = server.URL
			registry := idpregistry.NewStore()
			if _, e := registry.Upsert(idpregistry.Connection{IdPID: "corp", TenantID: "tenant", Issuer: issuer, AuthorizationEndpoint: issuer + "/authorize", TokenEndpoint: issuer + "/token", JWKSURI: issuer + "/jwks", ClientID: "client", VerifiedDomains: []string{"example.com"}}); e != nil {
				t.Fatal(e)
			}
			authTestAssign(t, registry, "tenant", "device", "alice", "corp")
			signer, _ := newDeviceBindingSigner()
			store := grantstore.NewStore()
			b := newClientlessBroker(registry, store, server.Client(), "https://portal.example", "tenant", time.Hour, signer)
			g := &federatedAuthGate{registry: registry, grants: store, signer: signer, tenantID: "tenant", brokerBaseURL: "https://portal.example"}
			link := g.stepUpURLWithRequirements("app:22", "device", "tenant", federatedRequirements{OSPrincipal: testAuthPrincipal, OSSession: testAuthSession, IdP: "corp"})
			start := httptest.NewRecorder()
			b.startForTest(start, httptest.NewRequest("GET", link, nil))
			if start.Code != 302 {
				t.Fatalf("start %d", start.Code)
			}
			auth, _ := url.Parse(start.Header().Get("Location"))
			nonce = auth.Query().Get("nonce")
			if mode == "assignment-changed" {
				authTestAssign(t, registry, "tenant", "device", "bob", "corp")
			} else if mode == "assignment-recreated" {
				current, _ := registry.Get("tenant", "corp")
				current.DeviceUserBindings = []idpregistry.DeviceUserBinding{}
				if _, err := registry.Upsert(current); err != nil {
					t.Fatal(err)
				}
				authTestAssign(t, registry, "tenant", "device", "alice", "corp")
			} else if mode == "unrelated-assignment-changed" {
				authTestAssign(t, registry, "tenant", "another-device", "bob", "corp")
			}
			request := httptest.NewRequest("GET", "https://portal.example/clientless/auth/callback?code=synthetic&state="+url.QueryEscape(auth.Query().Get("state")), nil)
			for _, cookie := range start.Result().Cookies() {
				request.AddCookie(cookie)
			}
			response := httptest.NewRecorder()
			b.handleCallback(response, request)
			if mode == "matching" || mode == "unrelated-assignment-changed" {
				if response.Code != 200 || len(store.ListAll()) != 1 {
					t.Fatalf("matching callback: %d", response.Code)
				}
			} else if response.Code == 200 || len(store.ListAll()) != 0 {
				t.Fatalf("wrong person or changed assignment minted: %d", response.Code)
			}
		})
	}
}

func TestAuthIdentityActivationPreservesMixedVersionBoundary(t *testing.T) {
	b, g := ceremonyFixture(t)
	r, m := rolloutFixture(t)
	g.rollout = r
	b.rollout = r
	if e := r.authority.Configure(context.Background(), 0, m); e != nil {
		t.Fatal(e)
	}
	completeRollout(t, r, m)
	features := []string{authrollout.EvidenceFeature, authrollout.SingleRequestFeature, authrollout.DeviceUserFeature}
	if e := r.authority.Activate(context.Background(), m.Generation, features, time.Now()); e == nil {
		t.Fatal("enabled without all member support")
	}
	c, _ := b.registry.Get("tenant", "corp")
	legacy := grantstore.Grant{GrantID: "pre-identity", TenantID: "tenant", DeviceID: "device", UserID: "user", IdPID: "corp", Issuer: c.Issuer, ProviderConfigSHA256: authEvidenceProviderDigest(c), Scope: "app:22"}
	if _, e := b.grants.Mint(legacy, time.Hour, time.Now()); e != nil {
		t.Fatal(e)
	}
	req := federatedRequirements{Scope: "app:22", IdP: "corp"}
	if !g.hasLiveGrantWithRequirements("tenant", "device", req) {
		t.Fatal("existing evidence interrupted before activation")
	}
	link := g.stepUpURLWithRequirements("app:22", "device", "tenant", req)
	if strings.Contains(link, "os_principal") {
		t.Fatal("identity sent to pre-activation portal")
	}
	for _, n := range m.Members {
		if e := r.authority.Record(context.Background(), n.CertificateSHA256, authrollout.Report{NodeID: n.ID, Generation: m.Generation, Version: "identity", Features: features}, time.Now()); e != nil {
			t.Fatal(e)
		}
	}
	if r.featureEnabled(authrollout.DeviceUserFeature) {
		t.Fatal("advertisement auto-activated binding")
	}
	if e := r.authority.Activate(context.Background(), m.Generation, features, time.Now()); e != nil {
		t.Fatal(e)
	}
	if g.hasLiveGrantWithRequirements("tenant", "device", req) || g.stepUpURLWithRequirements("app:22", "device", "tenant", req) != "" {
		t.Fatal("unbound owner accepted after activation")
	}
}

func TestAuthOwnerMetadataAndSignedLinkCannotBeSubstituted(t *testing.T) {
	b, g := ceremonyFixture(t)
	authority := "app:22\x00u=Alice op=" + testAuthPrincipal + " ls=" + testAuthSession
	if o := authOwnerFromAuthority(authority); o.Principal != testAuthPrincipal || o.Session != testAuthSession {
		t.Fatal("owner absent")
	}
	for _, bad := range []string{authority + " op=" + testAuthPrincipal, authority + " ls=" + testAuthSession, "app:22\x00op=Alice ls=" + testAuthSession, "app:22"} {
		if authOwnerFromAuthority(bad).Principal != "" {
			t.Fatal("ambiguous owner accepted")
		}
	}
	link := g.stepUpURLWithRequirements("app:22", "device", "tenant", federatedRequirements{IdP: "corp", OSPrincipal: testAuthPrincipal, OSSession: testAuthSession})
	for _, field := range []string{"os_principal", "os_session"} {
		for _, mode := range []string{"changed", "removed", "duplicate"} {
			u, _ := url.Parse(link)
			q := u.Query()
			switch mode {
			case "changed":
				q.Set(field, "other")
			case "removed":
				q.Del(field)
			case "duplicate":
				q.Add(field, q.Get(field))
			}
			u.RawQuery = q.Encode()
			w := httptest.NewRecorder()
			b.startForTest(w, httptest.NewRequest("GET", u.String(), nil))
			if w.Code == 302 {
				t.Fatal("modified owner link accepted")
			}
		}
	}
}

type identityUnavailableStore struct{}

func (identityUnavailableStore) Load() ([]byte, error) {
	return nil, fmt.Errorf("synthetic read failure")
}
func (identityUnavailableStore) Save([]byte) error { return fmt.Errorf("synthetic write failure") }
func TestAuthIdentityUnknownStateCannotDowngradeToDeviceOnly(t *testing.T) {
	b, g := ceremonyFixture(t)
	r, m := rolloutFixture(t)
	g.rollout = r
	b.rollout = r
	if e := r.authority.Configure(context.Background(), 0, m); e != nil {
		t.Fatal(e)
	}
	completeRollout(t, r, m)
	c, _ := b.registry.Get("tenant", "corp")
	if _, e := b.grants.Mint(grantstore.Grant{GrantID: "old", TenantID: "tenant", DeviceID: "device", UserID: "user", IdPID: "corp", Issuer: c.Issuer, ProviderConfigSHA256: authEvidenceProviderDigest(c), Scope: "app:22"}, time.Hour, time.Now()); e != nil {
		t.Fatal(e)
	}
	req := federatedRequirements{Scope: "app:22"}
	link := g.stepUpURLWithRequirements("app:22", "device", "tenant", req)
	if link == "" || !g.hasLiveGrantWithRequirements("tenant", "device", req) {
		t.Fatal("preactivation baseline failed")
	}
	r.authority = authrollout.NewStore(identityUnavailableStore{})
	if g.hasLiveGrantWithRequirements("tenant", "device", req) || g.stepUpURLWithRequirements("app:22", "device", "tenant", req) != "" {
		t.Fatal("unavailable authority allowed fallback")
	}
	w := httptest.NewRecorder()
	b.startForTest(w, httptest.NewRequest("GET", link, nil))
	if w.Code != 503 {
		t.Fatalf("unknown state admitted sign-in: %d", w.Code)
	}
}
