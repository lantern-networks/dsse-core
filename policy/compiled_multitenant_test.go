package policy

import (
	"testing"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

// ★★★ AN AUTHORED RULE FOR ANY ORGANIZATION BUT THE NODE'S OWN DECIDED NOTHING (2026-08-17, measured on the
// lab). RuntimeEvaluator read the tenant from the BASE evaluator's bundle — this node's — and merged only that
// organization's compiled policies. A rule authored for another organization through the Console was stored,
// listed, and displayed as "active · enforce" while no decision was ever taken by it.
//
// Merging every organization's compiled set is safe because matching gates on tenant equality; this asserts
// both halves, since merging without that gate would be a worse defect than the one being fixed.
func TestCompiledPoliciesOfEveryOrganizationReachTheRuntimeEvaluator(t *testing.T) {
	store := NewStore(nil)
	store.SetCompiledPolicies("tenant_node", []model.Policy{{
		ID: "pol_node", TenantID: "tenant_node", Status: "active", Priority: 100,
		Conditions: map[string]any{"fqdn": "node.example"},
		Action:     model.PolicyAction{Decision: "deny"},
	}})
	store.SetCompiledPolicies("tenant_other", []model.Policy{{
		ID: "pol_other", TenantID: "tenant_other", Status: "active", Priority: 100,
		Conditions: map[string]any{"fqdn": "other.example"},
		Action:     model.PolicyAction{Decision: "deny"},
	}})

	// The base evaluator is the NODE's, which is exactly the state that used to hide the second organization.
	eval := store.RuntimeEvaluator(decision.Evaluator{PolicyBundle: model.PolicyBundle{TenantID: "tenant_node"}})
	ids := map[string]bool{}
	for _, p := range eval.Policies {
		ids[p.ID] = true
	}
	if !ids["pol_node"] {
		t.Fatalf("the node's own compiled policy must still be there: %+v", eval.Policies)
	}
	if !ids["pol_other"] {
		t.Fatalf("another organization's compiled policy never reached the evaluator: %+v", eval.Policies)
	}

	// And it can only ever decide for the organization it belongs to.
	other := eval.Evaluate(model.DecisionRequest{
		TenantID: "tenant_other", Destination: "other.example", DestinationPort: 443,
		Protocol: "tcp", ServiceFamily: "https", ActorType: "human",
	})
	if other.Decision != "deny" {
		t.Fatalf("the second organization's own rule must decide its own request, got %q", other.Decision)
	}
	crossed := eval.Evaluate(model.DecisionRequest{
		TenantID: "tenant_node", Destination: "other.example", DestinationPort: 443,
		Protocol: "tcp", ServiceFamily: "https", ActorType: "human",
	})
	if crossed.PolicyID == "pol_other" {
		t.Fatalf("one organization's rule decided another's request: %+v", crossed)
	}
}
