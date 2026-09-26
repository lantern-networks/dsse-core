package main

import (
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
	policycandidate "github.com/lantern-networks/dsse-core/policycandidate"
)

// adminPolicyCandidateAuditLog builds the audit record for a policy-candidate lifecycle event. Kept in
// cmd/edge for the decision.Evaluator binding + the shared audit-id mint.
type policyCandidateAuditOutcome struct {
	actor                              *string
	result, failedStage, ruleOperation string
	ruleConfirmed, applied             bool
}

func adminPolicyCandidateAuditLog(eventType string, candidate policycandidate.Candidate, evaluator decision.Evaluator, now time.Time, outcomes ...policyCandidateAuditOutcome) model.AuditLog {
	action := "upsert"
	if eventType == "admin_policy_candidate_reviewed" {
		action = "review"
	}
	if eventType == "admin_policy_candidate_materialized" {
		action = "materialize"
	}
	if eventType == "admin_cert_pin_bypass_added" {
		action = "register_bypass"
	}
	result := "success"
	reason := "Policy candidate lifecycle event."
	targetType := "admin_policy_candidate"
	record := model.AuditLog{
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
	if len(outcomes) > 0 {
		o := outcomes[0]
		record.ActorUserID = o.actor
		if o.result != "" {
			record.Result = &o.result
		}
		record.Metadata["candidate_saved"] = true
		record.Metadata["failed_stage"] = o.failedStage
		record.Metadata["rule_operation"] = o.ruleOperation
		record.Metadata["rule_state_confirmed"] = o.ruleConfirmed
		record.Metadata["policy_materialized"] = o.ruleOperation == "upsert" && o.ruleConfirmed
		record.Metadata["runtime_hot_reload"] = o.applied
		record.Metadata["local_apply_requested"] = o.applied
		record.Metadata["enforcement_scope"] = "local_callback_only"
		if candidate.Source == policycandidate.SourceCertPinningDetection {
			if _, highRisk, err := policycandidate.CertPinBypassTarget(candidate); err == nil {
				kind := "hostname"
				if highRisk {
					kind = "ip"
				}
				record.Metadata["bypass_target_kind"] = kind
				record.Metadata["high_risk_override_used"] = highRisk && o.ruleConfirmed && o.ruleOperation == "upsert"
			}
		}
	}
	return record
}
