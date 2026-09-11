package decision

import (
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

// TestEvaluateEmptyDecisionFailsClosed pins fail-open review finding #16: a matched active policy whose
// action.decision is EMPTY is a misconfiguration and must fail CLOSED with a visible reason — not silently allow.
// (The authoring paths already reject an empty decision; this is the defense-in-depth behind that guard.)
func TestEvaluateEmptyDecisionFailsClosed(t *testing.T) {
	empty := model.Policy{
		ID: "pol_empty_decision", TenantID: "tenant_lab_001", Priority: 100, Status: "active",
		Conditions: map[string]any{"actor_type": "human", "application_id": "app_x", "service_family": "https"},
		Action:     model.PolicyAction{Decision: ""}, // misconfigured: no decision
	}
	ev := testEvaluatorWithPolicies([]model.Policy{empty})
	dec := ev.Evaluate(model.DecisionRequest{
		TenantID: "tenant_lab_001", ActorType: "human", ApplicationID: "app_x", ServiceFamily: "https",
		SubjectUserID: "u1", ConnectionInitiator: "client",
	})
	// The security behavior is fail-CLOSED: an empty decision must resolve to deny, never allow. (The misconfig is
	// additionally surfaced via a log line; the fine-grained reason codes are regenerated downstream from the
	// resolved decision, so we assert the decision itself, which is what gates the flow.)
	if dec.Decision == "allow" {
		t.Fatalf("empty action.decision must NOT resolve to allow (fail-open #16); got %q", dec.Decision)
	}
	if dec.Decision != "deny" {
		t.Fatalf("empty action.decision must fail closed to deny; got %q", dec.Decision)
	}
}
