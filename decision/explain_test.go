package decision

import (
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

// ExplainDecision surfaces the precedence-ordered basis the operator could not see in the 2026-06-23 bug: a
// built-in allow and an authored override at the same priority both match, one wins, the other is marked
// shadowed. This is the engine primitive behind the Effective-Policy "Why" view.
func TestExplainDecisionShowsShadowedCompetitors(t *testing.T) {
	builtinAllow := model.Policy{
		ID: "pol_google_workspace_swg_allow_001", Status: "active", Priority: 100,
		Conditions: map[string]any{"sni": "accounts.google.com"},
		Action:     model.PolicyAction{Decision: "allow"},
	}
	authored := model.Policy{
		ID: "rule-egress-rule-15-0-sni", Status: "active", Priority: 100,
		Conditions: map[string]any{"sni": "accounts.google.com"},
		Action:     model.PolicyAction{Decision: "require_reauthentication"},
	}
	disabled := model.Policy{
		ID: "rule-egress-old", Status: "disabled", Priority: 100,
		Conditions: map[string]any{"sni": "accounts.google.com"},
		Action:     model.PolicyAction{Decision: "deny"},
	}
	unrelated := model.Policy{
		ID: "pol_other", Status: "active", Priority: 50,
		Conditions: map[string]any{"sni": "example.com"},
		Action:     model.PolicyAction{Decision: "deny"},
	}
	// Put the built-in allow FIRST in the slice to prove ordering comes from precedence, not slice order.
	e := Evaluator{Policies: []model.Policy{builtinAllow, unrelated, disabled, authored}}

	exp := e.ExplainDecision(model.DecisionRequest{SNI: "accounts.google.com"})

	if exp.WinnerPolicyID != "rule-egress-rule-15-0-sni" || exp.WinnerDecision != "require_reauthentication" {
		t.Fatalf("winner = %q/%q, want authored require_reauthentication", exp.WinnerPolicyID, exp.WinnerDecision)
	}
	if exp.FinalDecision != "require_reauthentication" {
		t.Fatalf("final decision = %q, want require_reauthentication", exp.FinalDecision)
	}
	byID := map[string]PolicyTraceEntry{}
	for _, tr := range exp.Trace {
		byID[tr.PolicyID] = tr
	}
	// The built-in allow matched but was shadowed by the authored rule (this is the invisible competition the
	// operator needs to see).
	if a := byID["pol_google_workspace_swg_allow_001"]; !a.Matched || a.Winner || !a.Shadowed {
		t.Fatalf("built-in allow trace = %+v, want matched+shadowed+not-winner", a)
	}
	if w := byID["rule-egress-rule-15-0-sni"]; !w.Winner || w.Shadowed {
		t.Fatalf("authored rule trace = %+v, want winner", w)
	}
	// A disabled policy must appear in the trace but as not-matched (so the operator sees it exists yet is off).
	if d := byID["rule-egress-old"]; d.Matched || d.Status != "disabled" {
		t.Fatalf("disabled policy trace = %+v, want present+not-matched", d)
	}
	// An unrelated policy is present but not matched.
	if u := byID["pol_other"]; u.Matched {
		t.Fatalf("unrelated policy should not match, got %+v", u)
	}
	// Precedence order: priority 50 (unrelated) must come before the priority-100 group.
	if exp.Trace[0].PolicyID != "pol_other" {
		t.Fatalf("trace[0] = %q, want lowest-priority pol_other first", exp.Trace[0].PolicyID)
	}
}

// With no policy matching, ExplainDecision reports an empty winner (default deny) but still lists the basis.
func TestExplainDecisionDefaultDeny(t *testing.T) {
	e := Evaluator{Policies: []model.Policy{
		{ID: "p1", Status: "active", Priority: 10, Conditions: map[string]any{"sni": "a.com"}, Action: model.PolicyAction{Decision: "allow"}},
	}}
	exp := e.ExplainDecision(model.DecisionRequest{SNI: "b.com"})
	if exp.WinnerPolicyID != "" {
		t.Fatalf("winner = %q, want empty (no match)", exp.WinnerPolicyID)
	}
	if len(exp.Trace) != 1 || exp.Trace[0].Matched {
		t.Fatalf("trace = %+v, want one non-matching entry", exp.Trace)
	}
}
