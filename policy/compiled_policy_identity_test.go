package policy

import (
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
	"testing"
)

func TestCompiledPolicyIDIsNamespacedByTenant(t *testing.T) {
	conditions := map[string]any{"fqdn": "example.com"}
	for _, tc := range []string{"base collision", "compiled collision"} {
		t.Run(tc, func(t *testing.T) {
			own := model.Policy{ID: "same-id", TenantID: "a", Status: "active", Priority: 10, Conditions: conditions, Action: model.PolicyAction{Decision: "allow"}}
			other := own
			other.TenantID = "b"
			other.Action.Decision = "deny"
			fallback := other
			fallback.ID = "fallback"
			fallback.Priority = 100
			fallback.Action.Decision = "allow"
			var store *Store
			if tc == "base collision" {
				store = NewStore([]model.Policy{own, fallback})
			} else {
				store = NewStore([]model.Policy{fallback})
				store.SetCompiledPolicies("a", []model.Policy{own})
			}
			store.SetCompiledPolicies("b", []model.Policy{other})
			eval := store.RuntimeEvaluator(decision.Evaluator{PolicyBundle: model.PolicyBundle{TenantID: "b"}})
			got := eval.Evaluate(model.DecisionRequest{TenantID: "b", FQDN: "example.com"})
			if got.Decision != "deny" || got.PolicyID != "same-id" {
				t.Fatalf("tenant B's deny vanished: decision=%q policy=%q", got.Decision, got.PolicyID)
			}
		})
	}
}
