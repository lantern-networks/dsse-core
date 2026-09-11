package decision

import (
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

// ★★★ MEASURED BY WALKING THE GETTING-STARTED PATH AS SOMEBODY WHO HAD NEVER SEEN THIS PRODUCT (2026-09-05).
//
// One policy, written by hand, loaded, active, in the right organization, visible through the admin API — and
// every request denied with "No active policy matched the request." The cause was that actor_type is derived
// at the trust boundary and never taken from the caller, so it is "human" on every request and a rule written
// for "user" cannot match anything. Correct behaviour, and invisible: the operator sees a rule they can read,
// in a list that says active, denying.
func TestARuleThatCannotFireSaysWhichConditionStoppedIt(t *testing.T) {
	e := Evaluator{Policies: []model.Policy{{
		ID: "pol-allow-users", TenantID: "acme", Status: "active", Priority: 100,
		Conditions: map[string]any{"actor_type": "user"},
		Action:     model.PolicyAction{Decision: "allow"},
	}}}
	d := e.Evaluate(model.DecisionRequest{TenantID: "acme"})
	if d.Decision != "deny" {
		t.Fatalf("decision = %q, want deny — the diagnosis must not change the decision", d.Decision)
	}
	reason := ""
	if d.Reason != nil {
		reason = *d.Reason
	}
	for _, want := range []string{"pol-allow-users", `actor_type="user"`, `"human"`} {
		if !strings.Contains(reason, want) {
			t.Fatalf("the refusal must name the rule, what it requires and what the request carried.\nwant %q in: %s", want, reason)
		}
	}
}

// It must not send the reader to a rule that belongs to somebody else, or to one an operator switched off.
// Those are not near misses, and naming them would point at the wrong rule.
func TestTheDiagnosisNamesOnlyARuleThatCouldHaveApplied(t *testing.T) {
	e := Evaluator{Policies: []model.Policy{
		{ID: "someone-elses", TenantID: "other-org", Status: "active", Priority: 1,
			Conditions: map[string]any{"actor_type": "user"}, Action: model.PolicyAction{Decision: "allow"}},
		{ID: "switched-off", TenantID: "acme", Status: "inactive", Priority: 2,
			Conditions: map[string]any{"actor_type": "user"}, Action: model.PolicyAction{Decision: "allow"}},
	}}
	d := e.Evaluate(model.DecisionRequest{TenantID: "acme"})
	reason := ""
	if d.Reason != nil {
		reason = *d.Reason
	}
	if strings.Contains(reason, "someone-elses") {
		t.Fatalf("named another organization's rule: %s", reason)
	}
	if strings.Contains(reason, "switched-off") {
		t.Fatalf("named a rule an operator had switched off: %s", reason)
	}
}

// And a request that genuinely matches is untouched.
func TestAMatchingRuleIsUnaffected(t *testing.T) {
	e := Evaluator{Policies: []model.Policy{{
		ID: "pol-allow-humans", TenantID: "acme", Status: "active", Priority: 100,
		Conditions: map[string]any{"actor_type": "human"},
		Action:     model.PolicyAction{Decision: "allow"},
	}}}
	if d := e.Evaluate(model.DecisionRequest{TenantID: "acme"}); d.Decision != "allow" {
		t.Fatalf("decision = %q, want allow", d.Decision)
	}
}
