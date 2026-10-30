package main

import (
	"github.com/lantern-networks/dsse-core/grantstore"
	"github.com/lantern-networks/dsse-core/idpregistry"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAuthProviderTrustBoundaryChangesInvalidateEvidence(t *testing.T) {
	b, _ := ceremonyFixture(t)
	base, _ := b.registry.Resolve("tenant", "corp")
	for name, change := range map[string]func(*idpregistry.Connection){
		"trust-anchor":          func(c *idpregistry.Connection) { c.CAPEM = "replacement CA" },
		"domain-admission":      func(c *idpregistry.Connection) { c.VerifiedDomains = []string{"other.example"} },
		"token-endpoint":        func(c *idpregistry.Connection) { c.TokenEndpoint = "https://other.example/token" },
		"signing-keys-endpoint": func(c *idpregistry.Connection) { c.JWKSURI = "https://other.example/jwks" },
		"client-audience":       func(c *idpregistry.Connection) { c.ClientID = "other-client" },
		"group-interpretation":  func(c *idpregistry.Connection) { c.GroupsClaim = "other_groups" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			change(&changed)
			if authEvidenceProviderDigest(changed) == authEvidenceProviderDigest(base) {
				t.Fatal("trust boundary changed without invalidating evidence")
			}
		})
	}
}

func TestAuthEvidenceDoesNotSurviveProviderReplacement(t *testing.T) {
	b, g := ceremonyFixture(t)
	g.registry = b.registry
	conn, ok := b.registry.Resolve("tenant", "corp")
	if !ok {
		t.Fatal("missing provider")
	}
	conn = authTestAssign(t, b.registry, "tenant", "device", "subject", "corp")
	grant := grantstore.Grant{GrantID: "bound", TenantID: "tenant", DeviceID: "device", UserID: "subject", IdPID: "corp", Issuer: conn.Issuer, ProviderConfigSHA256: authEvidenceProviderDigest(conn), Scope: "app:22"}
	if _, err := b.grants.Mint(authTestBindGrant(t, g, grant), time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	req := federatedRequirements{OSPrincipal: testAuthPrincipal, OSSession: testAuthSession, IdP: "corp", Scope: "app:22"}
	if !g.hasLiveGrantWithRequirements("tenant", "device", req) {
		t.Fatal("matching evidence rejected")
	}
	whoami := func() int {
		r := httptest.NewRequest("GET", "https://portal.example/clientless/auth/whoami", nil)
		r.AddCookie(&http.Cookie{Name: b.cookieName, Value: "bound"})
		w := httptest.NewRecorder()
		b.handleWhoami(w, r)
		return w.Code
	}
	if whoami() != http.StatusOK {
		t.Fatal("current identity was not reported")
	}
	changed := conn
	changed.ClientSecret = "replacement-secret"
	changed.DisplayName = "New display label"
	if authEvidenceProviderDigest(changed) != authEvidenceProviderDigest(conn) {
		t.Fatal("secret or label leaked into evidence digest")
	}
	changed = conn
	changed.Issuer = "https://other-idp.example"
	if _, err := b.registry.Upsert(changed); err != nil {
		t.Fatal(err)
	}
	if g.hasLiveGrantWithRequirements("tenant", "device", req) {
		t.Fatal("new issuer inherited old subject")
	}
	if whoami() != http.StatusUnauthorized {
		t.Fatal("whoami reported stale provider identity")
	}
	changed = conn
	changed.ACRClaim = "different_claim"
	if _, err := b.registry.Upsert(changed); err != nil {
		t.Fatal(err)
	}
	if g.hasLiveGrantWithRequirements("tenant", "device", req) {
		t.Fatal("new assurance interpretation inherited old evidence")
	}
}

func TestAuthGateRejectsLegacyUnidentifiedProviderEvidence(t *testing.T) {
	b, g := ceremonyFixture(t)
	g.registry = b.registry
	_, err := b.grants.Mint(grantstore.Grant{GrantID: "legacy", TenantID: "tenant", DeviceID: "device", UserID: "subject", IdPID: "corp", Scope: "app:22"}, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if g.hasLiveGrantWithRequirements("tenant", "device", federatedRequirements{OSPrincipal: testAuthPrincipal, OSSession: testAuthSession, IdP: "corp", Scope: "app:22"}) {
		t.Fatal("legacy evidence was silently trusted")
	}
}
