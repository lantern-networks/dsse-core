package main

import (
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
	toolcallaudit "github.com/lantern-networks/dsse-core/toolcallaudit"
)

// adminToolCallEventAuditLog builds the audit record for a tool-call-event audit upsert. Kept in cmd/edge for
// the decision.Evaluator binding + the shared audit-id mint (randomEdgeID) and stringPtrValue.
func adminToolCallEventAuditLog(event toolcallaudit.Event, evaluator decision.Evaluator, now time.Time) model.AuditLog {
	action := event.ActionType
	result := stringPtrValue(event.Status)
	if result == "" {
		result = stringPtrValue(event.Decision)
	}
	if result == "" {
		result = "recorded"
	}
	reason := "ToolCallEvent Audit admin metadata updated."
	targetType := "admin_tool_call_event"
	return model.AuditLog{
		ID:             randomEdgeID("audit_", now),
		TenantID:       event.TenantID,
		EventType:      "admin_tool_call_event_upserted",
		TargetType:     &targetType,
		TargetID:       &event.ID,
		Action:         &action,
		Result:         &result,
		Reason:         &reason,
		PolicyBundleID: &evaluator.PolicyBundle.ID,
		EdgeRegionID:   &evaluator.EdgeRegionID,
		EdgeClusterID:  &evaluator.EdgeClusterID,
		Timestamp:      now.UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"status_present":                    event.Status != nil && *event.Status != "",
			"decision_present":                  event.Decision != nil && *event.Decision != "",
			"agent_task_session_id_present":     event.AgentTaskSessionID != nil && *event.AgentTaskSessionID != "",
			"actor_nhi_id_present":              event.ActorNHIID != "",
			"subject_user_id_present":           event.SubjectUserIDPresent,
			"delegated_access_grant_id_present": event.DelegatedAccessGrantID != nil && *event.DelegatedAccessGrantID != "",
			"tool_id_present":                   event.ToolID != "",
			"mcp_server_id_present":             event.MCPServerID != nil && *event.MCPServerID != "",
			"runtime_environment_id_present":    event.RuntimeEnvironmentID != nil && *event.RuntimeEnvironmentID != "",
			"application_id_present":            event.ApplicationID != nil && *event.ApplicationID != "",
			"context_boundary_id_present":       event.ContextBoundaryID != nil && *event.ContextBoundaryID != "",
			"destination_present":               event.DestinationPresent,
			"token_audience_present":            event.TokenAudiencePresent,
			"human_approval_event_id_present":   event.HumanApprovalEventID != nil && *event.HumanApprovalEventID != "",
			"access_decision_id_present":        event.AccessDecisionID != nil && *event.AccessDecisionID != "",
			"inspection_event_id_present":       event.InspectionEventID != nil && *event.InspectionEventID != "",
			"policy_id_present":                 event.PolicyID != nil && *event.PolicyID != "",
			"result_summary_present":            event.ResultSummaryPresent,
			"result_summary_scope":              event.ResultSummaryScope,
			"masked":                            event.Masked,
			"payload_ref_present":               event.PayloadRefPresent,
			"retention_policy_present":          event.RetentionPolicy != nil && *event.RetentionPolicy != "",
			"metadata_key_count":                event.MetadataKeyCount,
			"tool_call_metadata_recorded_scope": "none",
			"runtime_hot_reload":                false,
			"reason_codes":                      []string{"admin_tool_call_event_audit_lifecycle"},
		},
	}
}
