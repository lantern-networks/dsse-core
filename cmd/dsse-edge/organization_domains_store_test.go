package main

import (
	"testing"

	"github.com/lantern-networks/dsse-core/idpregistry"
)

func TestOrganizationDomainsStore(t *testing.T) {
	s := newOrganizationDomainsStore()
	// Normalize: lowercase, strip @/*., de-dup.
	got := s.SetDomains("acme", []string{"Acme.com", "@acme.co.jp", "*.acme.com", "acme.com", "  "})
	set := map[string]bool{}
	for _, d := range got {
		set[d] = true
	}
	if !set["acme.com"] || !set["acme.co.jp"] || len(got) != 2 {
		t.Fatalf("normalized domains = %v, want {acme.com, acme.co.jp}", got)
	}
	if len(s.Domains("other")) != 0 {
		t.Fatal("tenant isolation broken")
	}
	// Empty clears.
	s.SetDomains("acme", nil)
	if len(s.Domains("acme")) != 0 {
		t.Fatal("empty SetDomains should clear")
	}
}

// The corporate-domain resolver is the UNION of organization domains + IdP verified_domains.
func TestCorporateDomainsResolverUnion(t *testing.T) {
	org := newOrganizationDomainsStore()
	org.SetDomains("acme", []string{"acme.com"})
	idp := idpregistry.NewStore()
	idp.Upsert(idpregistry.Connection{
		TenantID: "acme", IdPID: "okta", Type: "oidc",
		Issuer: "https://okta.example", AuthorizationEndpoint: "https://okta.example/a", ClientID: "cid",
		VerifiedDomains: []string{"acme.co.jp"},
	})
	resolver := corporateDomainsResolver(org, idp)
	got := resolver("acme")
	set := map[string]bool{}
	for _, d := range got {
		set[d] = true
	}
	if !set["acme.com"] || !set["acme.co.jp"] || len(got) != 2 {
		t.Fatalf("union = %v, want {acme.com (org), acme.co.jp (idp)}", got)
	}
	// Org-only classification works even with NO IdP (the point of S6).
	orgOnly := corporateDomainsResolver(org, nil)
	if got := dlpInstanceClass("tanaka@acme.com", orgOnly("acme")); got != "corporate" {
		t.Fatalf("org-only corporate classification = %q, want corporate", got)
	}
	if got := dlpInstanceClass("x@gmail.com", orgOnly("acme")); got != "personal" {
		t.Fatalf("non-org domain = %q, want personal", got)
	}
	if corporateDomainsResolver(nil, nil) != nil {
		t.Fatal("nil+nil should yield a nil resolver")
	}
}
