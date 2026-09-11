package decision

import (
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

// TestEastWestRuleRiskGate pins the matching half of the east-west risk gate: a gated rule must bite ONLY at
// or above its threshold, and an ungated rule must keep matching regardless of risk (no behavior change for
// every rule authored before the gate existed). Regression guard: the east-west plane once had no risk gate at
// all, so an authored "risk>=high / deny" bit at every risk level.
func TestEastWestRuleRiskGate(t *testing.T) {
	gated := EastWestRule{
		ID: "gated", Priority: 100, Destinations: []string{"db.internal"}, Protocols: []string{"ssh"},
		Mode: EastWestModeDeny, RiskSeverities: []string{"high", "critical"},
	}
	ungated := EastWestRule{
		ID: "ungated", Priority: 200, Destinations: []string{"db.internal"}, Protocols: []string{"ssh"},
		Mode: EastWestModeAllow,
	}

	req := func(severity string) model.DecisionRequest {
		return model.DecisionRequest{Destination: "db.internal", ServiceFamily: "ssh", RiskStateSeverity: severity}
	}

	for _, tc := range []struct {
		severity  string
		gatedHits bool
	}{
		{"", false},
		{"none", false},
		{"low", false},
		{"medium", false},
		{"high", true},
		{"critical", true},
	} {
		if got := gated.matches(req(tc.severity)); got != tc.gatedHits {
			t.Errorf("gated rule at severity %q matched = %v, want %v", tc.severity, got, tc.gatedHits)
		}
		// The ungated rule is unaffected by risk in every case — empty gate stays wildcard.
		if !ungated.matches(req(tc.severity)) {
			t.Errorf("ungated rule at severity %q did not match; an empty gate must be wildcard", tc.severity)
		}
	}
}

// TestEastWestRiskGatedRuleLosesToUngatedBelowThreshold is the end-to-end precedence check an operator would
// actually author: "deny SSH when the device is high-risk, otherwise allow". Below the threshold the gated
// deny must not match, so the lower-precedence allow wins; at/above it, the deny takes over.
func TestEastWestRiskGatedRuleLosesToUngatedBelowThreshold(t *testing.T) {
	rules := []EastWestRule{
		{ID: "deny-high-risk", Priority: 100, Protocols: []string{"ssh"}, Mode: EastWestModeDeny,
			RiskSeverities: []string{"high", "critical"}},
		{ID: "allow-otherwise", Priority: 200, Protocols: []string{"ssh"}, Mode: EastWestModeAllow},
	}
	for _, tc := range []struct{ severity, wantID string }{
		{"", "allow-otherwise"},
		{"medium", "allow-otherwise"},
		{"high", "deny-high-risk"},
		{"critical", "deny-high-risk"},
	} {
		got, ok := MatchedEastWestRule(rules, model.DecisionRequest{ServiceFamily: "ssh", RiskStateSeverity: tc.severity})
		if !ok || got.ID != tc.wantID {
			t.Errorf("severity %q matched %q (ok=%v), want %q", tc.severity, got.ID, ok, tc.wantID)
		}
	}
}
