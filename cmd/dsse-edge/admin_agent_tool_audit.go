package main

import (
	"time"

	agenttool "github.com/lantern-networks/dsse-core/agenttool"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

// adminAgentToolAuditLog builds the audit record for an agent-tool registry upsert. Kept in cmd/edge (not the
// internal/agenttool package) because it depends on the decision.Evaluator binding + the shared audit-id mint.
func adminAgentToolAuditLog(tool agenttool.Tool, evaluator decision.Evaluator, now time.Time) model.AuditLog {
	action := "upsert"
	result := "success"
	reason := "Agent tool registry metadata upserted."
	targetType := "admin_agent_tool"
	return model.AuditLog{
		ID:             randomEdgeID("audit_", now),
		TenantID:       tool.TenantID,
		EventType:      "admin_agent_tool_upserted",
		TargetType:     &targetType,
		TargetID:       &tool.ToolID,
		Action:         &action,
		Result:         &result,
		Reason:         &reason,
		PolicyBundleID: &evaluator.PolicyBundle.ID,
		EdgeRegionID:   &evaluator.EdgeRegionID,
		EdgeClusterID:  &evaluator.EdgeClusterID,
		Timestamp:      now.UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"action_type":                       tool.ActionType,
			"status":                            tool.Status,
			"signature_state":                   tool.SignatureState,
			"publisher_present":                 tool.Publisher != "",
			"permission_profile_present":        tool.PermissionProfile != "",
			"mcp_server_id_present":             tool.MCPServerID != "",
			"runtime_environment_id_present":    tool.RuntimeEnvironmentID != "",
			"allowed_application_count":         len(tool.AllowedApplicationIDs),
			"allowed_data_classification_count": len(tool.AllowedDataClassifications),
			"human_approval_required":           tool.HumanApprovalRequired,
			"metadata_key_count":                tool.MetadataKeyCount,
			"tool_metadata_recorded_scope":      "none",
			"tool_payload_recorded":             false,
			"tool_secret_recorded":              false,
			"tool_credentials_recorded":         false,
			"mcp_token_brokered":                false,
			"runtime_hot_reload":                false,
			"reason_codes":                      []string{"admin_agent_tool_registry_upsert"},
		},
	}
}
