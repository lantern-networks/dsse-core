package policy

import (
	"testing"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

// ★★ ONE RULE, ONE POLICY (2026-08-17, measured on the lab). Both planes compile the same authored rule: the
// control plane compiles it and ships the result in the config bundle, where it lands in this store's ordinary
// policy set; the Edge then compiles the rule itself into compiledPolicies. The union gave every authored rule
// a twin — the control plane listed 5 policies for an organization and the Edge listed 7, the extra two being
// the same ids again. Every decision trace showed each rule twice.
//
// The noise was the visible half. The hazard is that two policies sharing an ID stay identical only while both
// compilers see the same asset catalog; when they diverge, this node evaluates two versions of one rule and
// the winner is a sort tie-break.
func TestACompiledPolicyAlreadyInTheBundleIsNotAddedTwice(t *testing.T) {
	// What the config authority published, carrying the compiled rule — seeded exactly as a bundle would.
	published := model.Policy{ID: "rule-egress-rule-6-0-fqdn", TenantID: "tenant_customer", Priority: 4100,
		Status: "active", Action: model.PolicyAction{Decision: "deny"}}
	store := NewStore([]model.Policy{published})
	// What this node compiled from the same rule, plus one the bundle did not carry.
	store.SetCompiledPolicies("tenant_customer", []model.Policy{
		published,
		{ID: "rule-egress-rule-6-0-sni", TenantID: "tenant_customer", Priority: 4100,
			Status: "active", Action: model.PolicyAction{Decision: "deny"}},
	})

	base := decision.Evaluator{PolicyBundle: model.PolicyBundle{TenantID: "tenant_customer"}}
	got := store.RuntimeEvaluator(base)

	seen := map[string]int{}
	for _, policy := range got.Policies {
		seen[policy.ID]++
	}
	if seen["rule-egress-rule-6-0-fqdn"] != 1 {
		t.Fatalf("the policy the bundle already carried appears %d time(s); one rule is one policy",
			seen["rule-egress-rule-6-0-fqdn"])
	}
	// And the locally compiled one the bundle did NOT carry must still arrive, or this fix would silently
	// remove enforcement — which is the failure the union exists to prevent.
	if seen["rule-egress-rule-6-0-sni"] != 1 {
		t.Fatalf("a compiled policy absent from the bundle must still reach the evaluator, got %d",
			seen["rule-egress-rule-6-0-sni"])
	}
}
