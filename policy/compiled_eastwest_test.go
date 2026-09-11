package policy

import (
	"testing"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

// Compiled (authored) east-west rules are unioned with the legacy admin rules in the runtime evaluator,
// without either clobbering the other, and only apply when east-west enforcement is enabled.
func TestCompiledEastWestRulesUnion(t *testing.T) {
	store := NewStore(nil)
	store.SetEastWestEnabled("acme", true)
	store.SetEastWestRules("acme", []decision.EastWestRule{{ID: "legacy-1", Destinations: []string{"dc.internal"}, Mode: "deny"}})
	store.SetCompiledEastWestRules("acme", []decision.EastWestRule{{ID: "authored-1", SourceDevices: []string{"dev-alice"}, Destinations: []string{"db.internal"}, Protocols: []string{"smb"}, Mode: "authenticate"}})

	base := decision.Evaluator{PolicyBundle: model.PolicyBundle{TenantID: "acme"}}
	eval := store.RuntimeEvaluator(base)
	if !eval.EastWestEnabled {
		t.Fatalf("east-west should be enabled")
	}
	ids := map[string]bool{}
	for _, r := range eval.EastWestRules {
		ids[r.ID] = true
	}
	if !ids["legacy-1"] || !ids["authored-1"] {
		t.Fatalf("runtime east-west rules = %v, want both legacy-1 and authored-1", eval.EastWestRules)
	}

	// Replacing the legacy set does not drop the compiled set, and vice versa.
	store.SetEastWestRules("acme", nil)
	eval = store.RuntimeEvaluator(base)
	if len(eval.EastWestRules) != 1 || eval.EastWestRules[0].ID != "authored-1" {
		t.Fatalf("after clearing legacy, runtime rules = %v, want only authored-1", eval.EastWestRules)
	}

	// Enablement is NOT implied by having compiled rules — a tenant with rules but enforcement off stays off.
	store2 := NewStore(nil)
	store2.SetCompiledEastWestRules("beta", []decision.EastWestRule{{ID: "a", Destinations: []string{"x"}, Mode: "deny"}})
	if store2.RuntimeEvaluator(decision.Evaluator{PolicyBundle: model.PolicyBundle{TenantID: "beta"}}).EastWestEnabled {
		t.Fatalf("authoring a rule must not auto-enable east-west enforcement")
	}
}
