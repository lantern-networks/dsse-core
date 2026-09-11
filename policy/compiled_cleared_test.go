package policy

import (
	"testing"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

// ★★ DELETING THE LAST RULE MUST STOP ENFORCING IT (2026-08-17, measured end to end on the lab).
//
// The recompile loop walked the organizations that HAVE authored rules. An organization whose LAST rule is
// deleted leaves that list, so nothing ever rebuilt its compiled set to empty and the Edge went on enforcing
// it: the customer deleted a deny rule, the rules screen showed none, the control plane had dropped the
// policy, and the policy checker still answered DENY for that destination across two further config pulls.
//
// The store has to be able to say which organizations it holds compiled policies FOR, so a recompile can
// cover the ones with something to clear rather than only the ones with something to build.
func TestTheStoreNamesEveryOrganizationItHoldsCompiledPoliciesFor(t *testing.T) {
	store := NewStore(nil)
	store.SetCompiledPolicies("tenant_a", []model.Policy{{ID: "pol_a", TenantID: "tenant_a", Status: "active"}})
	store.SetCompiledPolicies("tenant_b", []model.Policy{{ID: "pol_b", TenantID: "tenant_b", Status: "active"}})

	owners := store.CompiledRuleTenants()
	if len(owners) != 2 {
		t.Fatalf("both organizations must be nameable, got %v", owners)
	}

	// Clearing one — what a recompile does after the last rule is deleted — actually removes it from the
	// evaluator. This is the assertion the defect failed.
	store.SetCompiledPolicies("tenant_a", nil)
	eval := store.RuntimeEvaluator(decision.Evaluator{PolicyBundle: model.PolicyBundle{TenantID: "tenant_a"}})
	for _, policy := range eval.Policies {
		if policy.ID == "pol_a" {
			t.Fatal("the cleared organization's compiled policy is still being evaluated — a deleted rule is still enforcing")
		}
	}
	// And the other organization is untouched by that clear.
	found := false
	for _, policy := range eval.Policies {
		if policy.ID == "pol_b" {
			found = true
		}
	}
	if !found {
		t.Fatal("clearing one organization removed another's compiled policies")
	}
	// It also stops being named, so a later recompile does not walk it forever.
	if owners := store.CompiledRuleTenants(); len(owners) != 1 || owners[0] != "tenant_b" {
		t.Fatalf("after clearing, only the remaining organization is named, got %v", owners)
	}
}
