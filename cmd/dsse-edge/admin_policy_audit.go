package main

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

// The store has already accepted the change. Snapshot publication is a separate
// outcome and may have written some files before failing.
func adminPolicyMutationAuditLog(r *http.Request, item model.Policy, evaluator decision.Evaluator, now time.Time, operation, snapshotStatus string) model.AuditLog {
	audit := adminPolicyAuditLog(item, evaluator, now)
	audit.ActorUserID = auditActorPrincipal(r)
	audit.Metadata["allowed_tool_id_count"] = len(item.AllowedToolIDs)
	audit.Metadata["applied"] = true
	audit.Metadata["ne_snapshot_status"] = snapshotStatus
	if operation == "delete" {
		audit.EventType = "admin_policy_deleted"
		audit.Action = stringPtr("delete")
		audit.Reason = stringPtr("Admin policy removed from this server.")
	}
	if operation == "status" {
		audit.EventType = "admin_policy_status_changed"
		audit.Action = stringPtr("status")
		audit.Reason = stringPtr("Admin policy status changed on this server.")
	}
	if snapshotStatus == "unconfirmed" {
		audit.Result = stringPtr("partial")
		audit.Reason = stringPtr("Policy change applied on this server; Network Extension snapshot publication is unconfirmed.")
	}
	if identity, ok := adminIdentityFromRequest(r); ok && strings.TrimSpace(identity.TenantID) != "" && !strings.EqualFold(identity.TenantID, item.TenantID) {
		stampOperatorActor(audit.Metadata, identity)
	}
	return audit
}

// adminPolicyAuditLog builds the audit record for a policy upsert. Kept in cmd/edge (not the policy store
// package) because it depends on the decision.Evaluator binding + the shared audit-id mint (randomEdgeID) and
// the stringValue metadata reader.
func adminPolicyAuditLog(policy model.Policy, evaluator decision.Evaluator, now time.Time) model.AuditLog {
	action := "upsert"
	result := "success"
	reason := "Policy Engine admin policy upserted."
	targetType := "admin_policy"
	conditionKeys := sortedStringAnyKeys(policy.Conditions)
	metadata := map[string]any{
		"status":                         policy.Status,
		"decision":                       policy.Action.Decision,
		"condition_keys":                 conditionKeys,
		"condition_count":                len(conditionKeys),
		"required_human_approval":        policy.RequiredHumanApproval,
		"required_workload_attestation":  policy.RequiredWorkloadAttestation,
		"required_token_binding":         policy.RequiredTokenBinding,
		"break_glass_policy":             policy.BreakGlassPolicy,
		"policy_metadata_recorded_scope": "none",
		"reason_codes":                   []string{"admin_policy_lifecycle"},
	}
	if strings.TrimSpace(stringValue(policy.Metadata["source"])) == "admin_console_policy_candidate_handoff" {
		metadata["policy_metadata_recorded_scope"] = "candidate_handoff_nonsecret_trace"
		metadata["policy_candidate_handoff_source"] = "admin_console_policy_candidate_handoff"
		metadata["policy_candidate_handoff_metadata_key_count"] = len(policy.Metadata)
		metadata["policy_candidate_id_present"] = strings.TrimSpace(stringValue(policy.Metadata["policy_candidate_id"])) != ""
		metadata["policy_candidate_type"] = adminPolicyCandidateAuditEnum(stringValue(policy.Metadata["policy_candidate_type"]), []string{"private_app", "allow_policy", "deny_policy"})
		metadata["proposed_action"] = adminPolicyCandidateAuditEnum(stringValue(policy.Metadata["proposed_action"]), []string{"allow", "deny", "observe"})
		metadata["application_id_present"] = strings.TrimSpace(stringValue(policy.Metadata["application_id"])) != ""
		metadata["review_reason_code_present"] = strings.TrimSpace(stringValue(policy.Metadata["review_reason_code"])) != ""
		metadata["runtime_policy_materialization_claimed"] = false
		metadata["policy_bundle_compilation_claimed"] = false
	}
	return model.AuditLog{
		ID:             randomEdgeID("audit_", now),
		TenantID:       policy.TenantID,
		EventType:      "admin_policy_upserted",
		TargetType:     &targetType,
		TargetID:       &policy.ID,
		Action:         &action,
		Result:         &result,
		Reason:         &reason,
		PolicyID:       &policy.ID,
		PolicyBundleID: &evaluator.PolicyBundle.ID,
		EdgeRegionID:   &evaluator.EdgeRegionID,
		EdgeClusterID:  &evaluator.EdgeClusterID,
		Timestamp:      now.UTC().Format(time.RFC3339),
		Metadata:       metadata,
	}
}

func adminPolicyCandidateAuditEnum(value string, allowed []string) string {
	value = strings.TrimSpace(value)
	for _, candidate := range allowed {
		if value == candidate {
			return value
		}
	}
	return "other"
}

func sortedStringAnyKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
