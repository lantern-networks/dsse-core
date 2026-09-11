package decision

import (
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

// TestEgressRiskGateBitesOnlyWhenHighRisk pins the MATCHING half of the egress (internet-access) risk gate:
// an authored egress rule "deny <dest> when risk>=high" compiles to a `risk_state_severity: [high, critical]`
// condition (see policyrule.TestCompileEgressRiskAtLeast). This test proves the evaluator applies that
// condition correctly — the rule must bite ONLY when the request's risk is high/critical, and must NOT bite
// when the device carries no risk. (Regression guard for the "does egress evaluate device risk?" question.)
func TestEgressRiskGateBitesOnlyWhenHighRisk(t *testing.T) {
	// The condition a compiled "risk>=high" egress rule carries.
	gated := model.Policy{
		ID:         "rule-egress-deny-high",
		Priority:   100,
		Status:     "active",
		Conditions: map[string]any{"risk_state_severity": []any{"high", "critical"}},
		Action:     model.PolicyAction{Decision: "deny"},
	}
	for _, tc := range []struct {
		severity string
		wantHit  bool
	}{
		{"", false},        // no risk -> gate must NOT bite (device is not high-risk => egress allowed)
		{"none", false},    // explicit none -> must NOT bite
		{"medium", false},  // below the threshold -> must NOT bite
		{"high", true},     // at threshold -> bites (egress denied)
		{"critical", true}, // above -> bites
	} {
		ok, _ := matchPolicy(gated, model.DecisionRequest{RiskStateSeverity: tc.severity}, "human")
		if ok != tc.wantHit {
			t.Errorf("egress risk gate at severity %q matched = %v, want %v (a rule gated risk>=high must bite iff risk is high/critical)", tc.severity, ok, tc.wantHit)
		}
	}
}
