package decision

import (
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

// At equal priority, the more restrictive decision wins the tie, so an authored override beats a built-in
// allow sharing its priority. This reproduces the live bug: a base SaaS allow policy (ID "pol_...") and an
// authored egress rule (ID "rule-egress-...") both at priority 100, where the authored rule must win whether
// it is Deny or Authenticate (require_reauthentication) — previously only Deny did, because the tie-break
// privileged "deny" alone and otherwise fell to ID order (where "pol_..." < "rule-egress-...").
func TestEqualPriorityRestrictiveDecisionWinsTie(t *testing.T) {
	baseAllow := model.Policy{
		ID: "pol_google_workspace_swg_allow_001", Status: "active", Priority: 100,
		Conditions: map[string]any{"sni": "accounts.google.com"},
		Action:     model.PolicyAction{Decision: "allow"},
	}
	req := model.DecisionRequest{SNI: "accounts.google.com"}

	cases := []struct {
		name     string
		authored string
		wantWin  string // expected matched policy ID
		wantDec  string
	}{
		{"deny overrides base allow", "deny", "rule-egress-rule-15-0-sni", "deny"},
		{"require_reauthentication overrides base allow", "require_reauthentication", "rule-egress-rule-15-0-sni", "require_reauthentication"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			authored := model.Policy{
				ID: "rule-egress-rule-15-0-sni", Status: "active", Priority: 100,
				Conditions: map[string]any{"sni": "accounts.google.com"},
				Action:     model.PolicyAction{Decision: tc.authored},
			}
			// Order them so the base allow is FIRST in the slice (as it is loaded before compiled rules live):
			// the tie-break, not slice order, must decide.
			e := Evaluator{Policies: []model.Policy{baseAllow, authored}}
			dec := e.Evaluate(req)
			if dec.PolicyID != tc.wantWin {
				t.Fatalf("matched policy = %q, want %q (decision=%q)", dec.PolicyID, tc.wantWin, dec.Decision)
			}
			if dec.Decision != tc.wantDec {
				t.Fatalf("decision = %q, want %q", dec.Decision, tc.wantDec)
			}
		})
	}
}

// A genuinely less-restrictive authored decision at equal priority must NOT leapfrog a base allow purely by
// rank when it is also an allow — equal rank falls back to deterministic ID order (unchanged behaviour).
func TestEqualPriorityEqualRankFallsBackToID(t *testing.T) {
	a := model.Policy{ID: "aaa", Status: "active", Priority: 100, Conditions: map[string]any{"sni": "x"}, Action: model.PolicyAction{Decision: "allow"}}
	b := model.Policy{ID: "zzz", Status: "active", Priority: 100, Conditions: map[string]any{"sni": "x"}, Action: model.PolicyAction{Decision: "allow"}}
	e := Evaluator{Policies: []model.Policy{b, a}}
	if dec := e.Evaluate(model.DecisionRequest{SNI: "x"}); dec.PolicyID != "aaa" {
		t.Fatalf("equal rank should pick lowest ID 'aaa', got %q", dec.PolicyID)
	}
}
