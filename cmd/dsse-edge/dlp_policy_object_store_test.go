package main

import (
	"testing"

	"github.com/lantern-networks/dsse-core/dlp"
	"github.com/lantern-networks/dsse-core/model"
)

func TestDLPPolicyObjectStoreCRUDAndResolve(t *testing.T) {
	s := newDLPPolicyObjectStore()
	s.Upsert(model.DLPPolicyObject{ID: "dlpp_1", TenantID: "acme", Name: "block-pii", Identifiers: []string{"my_number"}, OnMatch: "block", InstanceScope: "personal", Status: "active"})
	if got := s.List("acme"); len(got) != 1 || got[0].Name != "block-pii" {
		t.Fatalf("List = %+v, want one block-pii", got)
	}
	if _, ok := s.Get("acme", "dlpp_1"); !ok {
		t.Fatal("Get should find dlpp_1")
	}
	// Tenant isolation.
	if _, ok := s.Get("other", "dlpp_1"); ok {
		t.Fatal("policy leaked across tenants")
	}
	if !s.Delete("acme", "dlpp_1") || len(s.List("acme")) != 0 {
		t.Fatal("Delete failed")
	}
}

// A dlp_inspect directive that REFERENCES a named policy resolves to that policy's detectors/action/scope (S5).
func TestDLPPolicyFromDecisionResolvesNamedPolicy(t *testing.T) {
	store := newDLPPolicyObjectStore()
	store.Upsert(model.DLPPolicyObject{ID: "dlpp_pii", TenantID: "acme", Name: "pii", Identifiers: []string{"my_number", "credit_card"}, OnMatch: "block", InstanceScope: "personal", Status: "active"})

	// The directive carries ONLY a policy reference (no inline identifiers/action) — the edge resolves it.
	dec := model.AccessDecision{TenantID: "acme", Actions: []model.DecisionAction{{
		Type:     "dlp_inspect",
		Metadata: map[string]any{"dlp_rule_id": "rule-1", "dlp_policy_id": "dlpp_pii", "action": "observe"},
	}}}

	// personal-scoped policy applies to a personal destination and yields its detectors + block action.
	p, ok := dlpPolicyFromDecision(dec, "personal", store)
	if !ok {
		t.Fatal("referenced policy should apply to a personal destination")
	}
	if len(p.Rules) != 1 || p.Rules[0].Action != dlp.ActionBlock {
		t.Fatalf("resolved action = %v, want block (from the named policy, not the inline observe)", p.Rules)
	}
	got := map[dlp.IdentifierType]bool{}
	for _, id := range p.Rules[0].Identifiers {
		got[id] = true
	}
	if !got["my_number"] || !got["credit_card"] {
		t.Fatalf("resolved identifiers = %v, want my_number + credit_card from the named policy", p.Rules[0].Identifiers)
	}
	// The same policy is instance-scoped to personal → inert on a corporate destination.
	if _, ok := dlpPolicyFromDecision(dec, "corporate", store); ok {
		t.Fatal("personal-scoped named policy must not apply to a corporate destination")
	}
	// An unresolvable reference falls back to the inline directive fields (here: observe, no identifiers → applies).
	decMissing := model.AccessDecision{TenantID: "acme", Actions: []model.DecisionAction{{
		Type:     "dlp_inspect",
		Metadata: map[string]any{"dlp_rule_id": "r", "dlp_policy_id": "nope", "action": "observe", "identifiers": []string{"my_number"}},
	}}}
	if p, ok := dlpPolicyFromDecision(decMissing, "", store); !ok || p.Rules[0].Action != dlp.ActionObserve {
		t.Fatalf("unresolvable reference should fall back to inline fields: ok=%v rules=%v", ok, p.Rules)
	}
}
