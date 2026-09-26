package decision

import (
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

func TestDefaultDenyDoesNotAttributeUnmatchedPolicy(t *testing.T) {
	foreign := model.Policy{ID: "foreign-policy", TenantID: "tenant-a", Priority: 1, Status: "active", Action: model.PolicyAction{Decision: "allow"}}
	near := model.Policy{ID: "near-policy", TenantID: "tenant-b", Priority: 20, Status: "active", Conditions: map[string]any{"fqdn": "other.invalid"}, Action: model.PolicyAction{Decision: "allow"}}
	disabled := model.Policy{ID: "disabled-policy", TenantID: "tenant-b", Priority: 0, Status: "disabled", Action: model.PolicyAction{Decision: "deny"}}
	for _, tc := range []struct {
		name     string
		policies []model.Policy
	}{
		{"empty", nil}, {"foreign", []model.Policy{foreign}}, {"near", []model.Policy{near}},
		{"disabled", []model.Policy{disabled}}, {"mixed", []model.Policy{foreign, near, disabled}},
		{"reordered", []model.Policy{near, disabled, foreign}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev := Evaluator{Policies: tc.policies}
			req := model.DecisionRequest{TenantID: "tenant-b", ActorType: "human", FQDN: "request.invalid", Protocol: "tcp", DestinationPort: 443}
			dec := ev.Evaluate(req)
			if dec.Decision != "deny" || dec.PolicyID != "" || !contains(dec.ReasonCodes, "no_policy_match") || len(dec.MatchedConditions) != 0 {
				t.Fatalf("unmatched decision = %+v", dec)
			}
			reason := ""
			if dec.Reason != nil {
				reason = *dec.Reason
			}
			if strings.Contains(reason, foreign.ID) || strings.Contains(reason, disabled.ID) {
				t.Fatalf("ineligible policy in diagnosis: %s", reason)
			}
			if tc.name == "near" && !strings.Contains(reason, near.ID) {
				t.Fatalf("lost helpful nearest-candidate diagnosis: %s", reason)
			}
			exp := ev.ExplainDecision(req)
			if exp.WinnerPolicyID != "" || exp.FinalPolicyID != "" || exp.FinalDecision != "deny" {
				t.Fatalf("unmatched explanation = %+v", exp)
			}
			if got := AccessLogFromDecision(dec).PolicyID; got != nil {
				t.Fatalf("unmatched access log policy = %q, want null", *got)
			}
			if got := DecisionTraceFromDecision(dec).PolicyID; got != "" {
				t.Fatalf("unmatched legacy trace policy = %q", got)
			}
		})
	}
}

func TestMatchedPolicyAttributionSurvivesDecisionRestrictions(t *testing.T) {
	for _, action := range []string{"allow", "deny", "require_reauthentication", ""} {
		t.Run("action_"+action, func(t *testing.T) {
			policy := model.Policy{ID: "matched-policy", TenantID: "tenant-b", Status: "active", Action: model.PolicyAction{Decision: action}}
			ev := Evaluator{Policies: []model.Policy{policy}}
			dec := ev.Evaluate(model.DecisionRequest{TenantID: "tenant-b", ActorType: "human"})
			want := action
			if want == "" {
				want = "deny"
			}
			if dec.PolicyID != policy.ID || dec.Decision != want || !contains(dec.ReasonCodes, "policy_matched") {
				t.Fatalf("matched decision = %+v", dec)
			}
			if p := AccessLogFromDecision(dec).PolicyID; p == nil || *p != policy.ID {
				t.Fatalf("matched access log policy = %v", p)
			}
		})
	}
	policy := model.Policy{ID: "attestation-policy", TenantID: "tenant-b", Status: "active", RequiredWorkloadAttestation: true, Action: model.PolicyAction{Decision: "allow"}}
	ev := Evaluator{Policies: []model.Policy{policy}}
	if dec := ev.Evaluate(model.DecisionRequest{TenantID: "tenant-b", ActorType: "human"}); dec.PolicyID != policy.ID || dec.Decision != "require_workload_attestation" {
		t.Fatalf("attestation restriction lost attribution: %+v", dec)
	}
}
