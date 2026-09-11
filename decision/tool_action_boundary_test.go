package decision

import (
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

// TestToolActionBoundaryEnforcement verifies / : a matched allow policy that declares an
// agentic tool boundary (AllowedToolIDs / AllowedToolActions) denies any tool call outside that
// boundary before execution, while an in-boundary call is allowed. An empty allowlist is unconstrained.
func TestToolActionBoundaryEnforcement(t *testing.T) {
	policy := model.Policy{
		ID: "pol_agent_tool", TenantID: "t", Status: "active", Priority: 10,
		Conditions:         map[string]any{"actor_type": "non_human", "service_family": "https"},
		Action:             model.PolicyAction{Decision: "allow"},
		AllowedToolIDs:     []string{"tool_repo_reader", "tool_ticket_reader"},
		AllowedToolActions: []string{"read", "execute"},
	}
	ev := Evaluator{Policies: []model.Policy{policy}, PolicyBundle: model.PolicyBundle{TenantID: "t"}}
	base := model.DecisionRequest{TenantID: "t", ActorType: "non_human", ServiceFamily: "https", Destination: "app", DestinationPort: 443}

	// In-boundary tool + action -> allow.
	in := base
	in.ToolID = "tool_repo_reader"
	in.ToolActionType = "read"
	if d := ev.Evaluate(in); d.Decision != "allow" {
		t.Fatalf("in-boundary tool call should allow, got %q (codes=%v)", d.Decision, d.ReasonCodes)
	}

	// Case-insensitive match still in-boundary.
	ci := base
	ci.ToolID = "Tool_Repo_Reader"
	ci.ToolActionType = "READ"
	if d := ev.Evaluate(ci); d.Decision != "allow" {
		t.Fatalf("case-insensitive in-boundary call should allow, got %q", d.Decision)
	}

	// Out-of-boundary tool ID -> deny.
	badTool := base
	badTool.ToolID = "tool_repo_writer"
	badTool.ToolActionType = "read"
	if d := ev.Evaluate(badTool); d.Decision != "deny" {
		t.Fatalf("out-of-boundary tool id should deny, got %q", d.Decision)
	} else if !hasReasonCode(d.ReasonCodes, "tool_id_not_allowed") || !hasReasonCode(d.ReasonCodes, "tool_action_out_of_boundary") {
		t.Fatalf("expected tool_id_not_allowed + tool_action_out_of_boundary, got %v", d.ReasonCodes)
	}

	// In-boundary tool but out-of-boundary action (delete) -> deny.
	badAction := base
	badAction.ToolID = "tool_repo_reader"
	badAction.ToolActionType = "delete"
	if d := ev.Evaluate(badAction); d.Decision != "deny" {
		t.Fatalf("out-of-boundary action should deny, got %q", d.Decision)
	} else if !hasReasonCode(d.ReasonCodes, "tool_action_not_allowed") {
		t.Fatalf("expected tool_action_not_allowed, got %v", d.ReasonCodes)
	}

	// Tool-scoped policy + request without a tool id -> denied (zero-trust default).
	noTool := base
	if d := ev.Evaluate(noTool); d.Decision != "deny" {
		t.Fatalf("tool-scoped policy with no tool id should deny, got %q", d.Decision)
	}

	// Unconstrained policy (no allowlists) -> any tool call allowed.
	open := policy
	open.AllowedToolIDs = nil
	open.AllowedToolActions = nil
	evOpen := Evaluator{Policies: []model.Policy{open}, PolicyBundle: model.PolicyBundle{TenantID: "t"}}
	anyCall := base
	anyCall.ToolID = "tool_anything"
	anyCall.ToolActionType = "admin"
	if d := evOpen.Evaluate(anyCall); d.Decision != "allow" {
		t.Fatalf("unconstrained policy should allow any tool call, got %q", d.Decision)
	}
}
