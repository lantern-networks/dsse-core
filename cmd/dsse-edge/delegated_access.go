package main

import (
	"fmt"
	_ "net/http/pprof" // DIAGNOSTIC: registers /debug/pprof on http.DefaultServeMux; served only when -pprof-listen is set
	"time"

	// The IANA timezone database, compiled in. The runtime image is FROM scratch, so there is no
	// /usr/share/zoneinfo and time.LoadLocation would fail for EVERY zone — including the ones an operator
	// just typed into the Console. Validation that passes on a developer's machine and rejects everything in
	// the container is worse than no validation, because it looks like the operator's mistake.
	_ "time/tzdata"

	"github.com/lantern-networks/dsse-core/model"
)

const (
	maxHumanApprovalTTL  = 24 * time.Hour
	maxDelegatedGrantTTL = 24 * time.Hour
)

type delegatedGrantRevokeRequest struct {
	RevocationReason string `json:"revocation_reason"`
	RevokedBy        string `json:"revoked_by"`
}

func isDelegatedActorType(actorType string) bool {
	return actorType == "delegated_agent" || actorType == "nhi"
}

func validateDelegatedGrantContext(grant model.DelegatedAccessGrant, req model.DecisionRequest) error {
	if req.ActorNHIID != "" && grant.ActorNHIID != req.ActorNHIID {
		return fmt.Errorf("Delegated Access Grant actor_nhi_id does not match the request")
	}
	if req.SubjectUserID != "" && grant.SubjectUserID != req.SubjectUserID {
		return fmt.Errorf("Delegated Access Grant subject_user_id does not match the request")
	}
	if grant.DeviceID != nil && *grant.DeviceID != "" && req.DeviceID != "" && *grant.DeviceID != req.DeviceID {
		return fmt.Errorf("Delegated Access Grant device_id does not match the request")
	}
	if grant.ApplicationID != nil && *grant.ApplicationID != "" && req.ApplicationID != "" && *grant.ApplicationID != req.ApplicationID {
		return fmt.Errorf("Delegated Access Grant application_id does not match the request")
	}
	if len(grant.ToolIDs) > 0 && req.ToolID != "" && !stringSliceContains(grant.ToolIDs, req.ToolID) {
		return fmt.Errorf("Delegated Access Grant does not allow the requested tool")
	}
	return nil
}

func validateHumanApprovalContext(approval model.HumanApprovalEvent, grant model.DelegatedAccessGrant, req model.DecisionRequest) error {
	if approval.ActorNHIID != nil && *approval.ActorNHIID != "" && req.ActorNHIID != "" && *approval.ActorNHIID != req.ActorNHIID {
		return fmt.Errorf("Human Approval Event actor_nhi_id does not match the request")
	}
	if approval.SubjectUserID != nil && *approval.SubjectUserID != "" && req.SubjectUserID != "" && *approval.SubjectUserID != req.SubjectUserID {
		return fmt.Errorf("Human Approval Event subject_user_id does not match the request")
	}
	if approval.DelegatedAccessGrantID != nil && *approval.DelegatedAccessGrantID != "" && *approval.DelegatedAccessGrantID != grant.ID {
		return fmt.Errorf("Human Approval Event delegated_access_grant_id does not match the grant")
	}
	if grant.ApprovalEventID != nil && *grant.ApprovalEventID != "" && *grant.ApprovalEventID != approval.ID {
		return fmt.Errorf("Delegated Access Grant approval_event_id does not match the approval")
	}
	if approval.ApplicationID != nil && *approval.ApplicationID != "" && req.ApplicationID != "" && *approval.ApplicationID != req.ApplicationID {
		return fmt.Errorf("Human Approval Event application_id does not match the request")
	}
	if approval.ActionType != nil && *approval.ActionType != "" && req.ToolActionType != "" && *approval.ActionType != req.ToolActionType {
		return fmt.Errorf("Human Approval Event action_type does not match the request")
	}
	return nil
}

func markRuntimeEvidenceAllowed(dec *model.AccessDecision, grant model.DelegatedAccessGrant, approval *model.HumanApprovalEvent) {
	if dec.Metadata == nil {
		dec.Metadata = map[string]any{}
	}
	dec.Metadata["runtime_evidence_result"] = "valid"
	dec.Metadata["delegated_grant_status"] = grant.Status
	dec.Metadata["delegated_grant_expires_at"] = grant.ExpiresAt
	if approval != nil {
		dec.Metadata["approval_result"] = approval.ApprovalResult
		dec.Metadata["approval_expires_at"] = approval.ExpiresAt
	}
}

func delegatedAccessDecisionAuditRequired(dec model.AccessDecision) bool {
	return dec.ActorType == "delegated_agent" || stringPtrValue(dec.DelegatedAccessGrantID) != ""
}

func normalizeDelegatedAccessGrant(grant *model.DelegatedAccessGrant, expectedTenantID string, now time.Time) error {
	if grant.ID == "" {
		grant.ID = randomEdgeID("dag_", now)
	}
	if grant.TenantID == "" {
		grant.TenantID = expectedTenantID
	}
	if expectedTenantID != "" && grant.TenantID != expectedTenantID {
		return fmt.Errorf("delegated access grant tenant_id %s does not match edge tenant_id %s", grant.TenantID, expectedTenantID)
	}
	if grant.SubjectUserID == "" {
		return fmt.Errorf("delegated access grant subject_user_id is required")
	}
	if grant.ActorNHIID == "" {
		return fmt.Errorf("delegated access grant actor_nhi_id is required")
	}
	if grant.Status == "" {
		grant.Status = "active"
	}
	if !validDelegatedGrantStatus(grant.Status) {
		return fmt.Errorf("delegated access grant status %s is invalid", grant.Status)
	}
	if grant.CreatedAt == nil || *grant.CreatedAt == "" {
		grant.CreatedAt = stringPtr(now.UTC().Format(time.RFC3339))
	}
	if grant.ExpiresAt == "" {
		ttl := 1800
		if grant.MaxSessionDuration != nil && *grant.MaxSessionDuration > 0 {
			ttl = *grant.MaxSessionDuration
		}
		if time.Duration(ttl)*time.Second > maxDelegatedGrantTTL {
			ttl = int(maxDelegatedGrantTTL / time.Second)
		}
		grant.ExpiresAt = now.UTC().Add(time.Duration(ttl) * time.Second).Format(time.RFC3339)
	}
	if grant.Scopes == nil {
		grant.Scopes = []string{}
	}
	if grant.ToolIDs == nil {
		grant.ToolIDs = []string{}
	}
	if grant.Metadata == nil {
		grant.Metadata = map[string]any{}
	}
	return nil
}

func validDelegatedGrantStatus(value string) bool {
	switch value {
	case "active", "expired", "revoked":
		return true
	default:
		return false
	}
}
