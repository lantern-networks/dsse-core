package main

import (
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
	policycandidate "github.com/lantern-networks/dsse-core/policycandidate"
)

// adminPolicyCandidateAuditLog builds the audit record for a policy-candidate lifecycle event. Kept in
// cmd/edge for the decision.Evaluator binding + the shared audit-id mint.
func adminPolicyCandidateAuditLog(eventType string, candidate policycandidate.Candidate, evaluator decision.Evaluator, now time.Time) model.AuditLog {
	action := "upsert"
	if eventType == "admin_policy_candidate_reviewed" {
		action = "review"
	}
	result := "success"
	reason := "Policy candidate lifecycle event."
	targetType := "admin_policy_candidate"
	return model.AuditLog{
		ID:             randomEdgeID("audit_", now),
		TenantID:       candidate.TenantID,
		EventType:      eventType,
		TargetType:     &targetType,
		TargetID:       &candidate.CandidateID,
		Action:         &action,
		Result:         &result,
		Reason:         &reason,
		PolicyBundleID: &evaluator.PolicyBundle.ID,
		EdgeRegionID:   &evaluator.EdgeRegionID,
		EdgeClusterID:  &evaluator.EdgeClusterID,
		Timestamp:      now.UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"candidate_type":                    candidate.CandidateType,
			"source":                            candidate.Source,
			"proposed_action":                   candidate.ProposedAction,
			"status":                            candidate.Status,
			"application_id_present":            candidate.ApplicationID != "",
			"service_family":                    candidate.ServiceFamily,
			"reason_code_count":                 len(candidate.ReasonCodes),
			"review_reason_code_present":        candidate.ReviewReasonCode != "",
			"candidate_metadata_recorded_scope": "none",
			"policy_materialized":               false,
			"runtime_hot_reload":                false,
			"reason_codes":                      []string{"admin_policy_candidate_lifecycle"},
		},
	}
}
