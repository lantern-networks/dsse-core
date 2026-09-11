package main

import (
	"testing"

	"github.com/lantern-networks/dsse-core/idpregistry"
	"github.com/lantern-networks/dsse-core/model"
)

func TestDLPInstanceClass(t *testing.T) {
	corp := []string{"acme.co.jp", "acme.com"}
	cases := []struct {
		email string
		want  string
	}{
		{"tanaka@acme.co.jp", "corporate"},
		{"TANAKA@ACME.COM", "corporate"}, // case-insensitive
		{"someone@gmail.com", "personal"},
		{"partner@othercorp.com", "personal"}, // a real but non-corporate domain = external/personal
		{"", ""},                              // no signal
		{"noatsign", ""},
		{"trailing@", ""},
	}
	for _, tc := range cases {
		if got := dlpInstanceClass(tc.email, corp); got != tc.want {
			t.Errorf("dlpInstanceClass(%q) = %q, want %q", tc.email, got, tc.want)
		}
	}
	// No corporate domains configured → cannot classify (fail open, scoped rules inert).
	if got := dlpInstanceClass("tanaka@acme.co.jp", nil); got != "" {
		t.Errorf("with no corporate domains, class = %q, want \"\"", got)
	}
}

func TestDLPInstanceScopeApplies(t *testing.T) {
	cases := []struct {
		scope, class string
		want         bool
	}{
		{"", "personal", true}, // any scope always applies
		{"any", "corporate", true},
		{"corporate", "corporate", true},
		{"corporate", "personal", false},
		{"personal", "personal", true},
		{"personal", "corporate", false},
		{"corporate", "", false}, // unknown class → scoped rule inert
		{"personal", "", false},
	}
	for _, tc := range cases {
		if got := dlpInstanceScopeApplies(tc.scope, tc.class); got != tc.want {
			t.Errorf("dlpInstanceScopeApplies(%q,%q) = %v, want %v", tc.scope, tc.class, got, tc.want)
		}
	}
}

func TestDLPKnownInstanceScope(t *testing.T) {
	for _, s := range []string{"", "any", "corporate", "personal"} {
		if !dlpKnownInstanceScope(s) {
			t.Errorf("dlpKnownInstanceScope(%q) = false", s)
		}
	}
	if dlpKnownInstanceScope("nonprofit") {
		t.Error("dlpKnownInstanceScope(nonprofit) = true, want false")
	}
}

func TestCorporateDomainsForTenant(t *testing.T) {
	store := idpregistry.NewStore()
	conn := func(id string, domains []string) idpregistry.Connection {
		return idpregistry.Connection{
			TenantID: "acme", IdPID: id, Type: "oidc",
			Issuer: "https://" + id + ".example", AuthorizationEndpoint: "https://" + id + ".example/authorize",
			ClientID: "cid", VerifiedDomains: domains,
		}
	}
	if _, err := store.Upsert(conn("okta", []string{"acme.com", "acme.co.jp"})); err != nil {
		t.Fatalf("upsert okta: %v", err)
	}
	if _, err := store.Upsert(conn("azuread", []string{"acme.com"})); err != nil { // dup collapses
		t.Fatalf("upsert azuread: %v", err)
	}
	resolver := corporateDomainsForTenant(store)
	got := resolver("acme")
	set := map[string]bool{}
	for _, d := range got {
		set[d] = true
	}
	if !set["acme.com"] || !set["acme.co.jp"] || len(got) != 2 {
		t.Errorf("corporate domains = %v, want {acme.com, acme.co.jp}", got)
	}
	if len(resolver("other")) != 0 {
		t.Errorf("other tenant should have no corporate domains")
	}
	if corporateDomainsForTenant(nil) != nil {
		t.Error("nil store must yield a nil resolver")
	}
}

// The dlp_inspect directive is honored or skipped by the destination's instance class.
func TestDLPPolicyFromDecisionInstanceScope(t *testing.T) {
	mk := func(scope string) model.AccessDecision {
		return model.AccessDecision{TenantID: "acme", Actions: []model.DecisionAction{{
			Type: "dlp_inspect",
			Metadata: map[string]any{
				"dlp_rule_id": "r1", "action": "block", "identifiers": []string{"my_number"}, "instance_scope": scope,
			},
		}}}
	}
	// personal-scoped rule fires on a personal destination, not on a corporate one.
	if _, ok := dlpPolicyFromDecision(mk("personal"), "personal", nil); !ok {
		t.Error("personal-scoped rule should apply to a personal destination")
	}
	if _, ok := dlpPolicyFromDecision(mk("personal"), "corporate", nil); ok {
		t.Error("personal-scoped rule must NOT apply to a corporate destination")
	}
	// Unknown class → scoped rule inert.
	if _, ok := dlpPolicyFromDecision(mk("personal"), "", nil); ok {
		t.Error("scoped rule must be inert when the instance class is unknown")
	}
	// An unscoped rule always applies.
	if _, ok := dlpPolicyFromDecision(mk(""), "", nil); !ok {
		t.Error("unscoped rule should always apply")
	}
}
