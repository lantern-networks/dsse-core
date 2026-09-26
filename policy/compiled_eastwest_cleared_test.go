package policy

import (
	"testing"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

// ★★ THE EAST-WEST HALF OF THE SAME DEFECT (2026-08-17). The recompile loop walked the organizations that have
// authored rules; an organization whose only rules are east-west leaves that list when its last one is
// deleted, so nothing rebuilt its compiled set and the node kept enforcing it. Proved on the egress side end
// to end on the lab — a deleted deny still answered DENY across two config pulls — and this is the sibling
// path, which is cleared differently:
//
//   - the egress compiled set is derived and node-local, so an emptied one DROPS its key;
//   - the east-west compiled set is distributed, where an absent value reads as "keep what you
//     have" — so an emptied one stays as an EXPLICIT empty, and must still be nameable so the loop walks it.
func TestAnOrganizationWithOnlyEastWestRulesIsStillWalkedAfterItsLastOneGoes(t *testing.T) {
	store := NewStore(nil)
	store.SetCompiledEastWestRules("tenant_ew", []decision.EastWestRule{
		{ID: "authored-1", Destinations: []string{"db.internal"}, Mode: "deny"},
	})

	named := false
	for _, tenant := range store.CompiledRuleTenants() {
		if tenant == "tenant_ew" {
			named = true
		}
	}
	if !named {
		t.Fatal("an organization with compiled east-west rules must be nameable, or a recompile never walks it " +
			"and its deleted rules go on enforcing")
	}

	// What a recompile does once the last rule is deleted.
	store.SetCompiledEastWestRules("tenant_ew", nil)
	if rules := store.EffectiveEastWestRules("tenant_ew"); len(rules) != 0 {
		t.Fatalf("the cleared set is still enforcing %d rule(s)", len(rules))
	}
	// Still nameable, on purpose: the empty is explicit because this set is distributed, and an absent value
	// downstream reads as "keep what you have" — which would turn the deletion into a no-op.
	stillNamed := false
	for _, tenant := range store.CompiledRuleTenants() {
		if tenant == "tenant_ew" {
			stillNamed = true
		}
	}
	if !stillNamed {
		t.Fatal("the east-west entry must remain as an explicit empty set so the deletion is carried, not inferred")
	}

	// And the evaluator agrees.
	eval := store.RuntimeEvaluator(decision.Evaluator{PolicyBundle: model.PolicyBundle{TenantID: "tenant_ew"}})
	if len(eval.EastWestRules) != 0 {
		t.Fatalf("the evaluator still holds %d east-west rule(s) after the set was cleared", len(eval.EastWestRules))
	}
}
