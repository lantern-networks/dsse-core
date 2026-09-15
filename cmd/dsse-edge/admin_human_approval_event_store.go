package main

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	humanapproval "github.com/lantern-networks/dsse-core/humanapproval"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

type adminHumanApprovalEventListOptions struct {
	ApprovalResult         string
	ActorNHIID             string
	SubjectUserID          string
	DelegatedAccessGrantID string
	Limit                  int
}

type adminHumanApprovalEventListResponse struct {
	Approvals []adminHumanApprovalEvent `json:"approvals"`
	Count     int                       `json:"count"`
	Limit     int                       `json:"limit"`
}

type adminHumanApprovalEvent struct {
	ID                     string   `json:"id"`
	TenantID               string   `json:"tenant_id"`
	ApprovalSource         string   `json:"approval_source"`
	ApproverUserID         *string  `json:"approver_user_id"`
	SubjectUserID          *string  `json:"subject_user_id"`
	ActorNHIID             *string  `json:"actor_nhi_id"`
	DelegatedAccessGrantID *string  `json:"delegated_access_grant_id"`
	AgentTaskSessionID     *string  `json:"agent_task_session_id"`
	ApplicationID          *string  `json:"application_id"`
	Audience               *string  `json:"audience"`
	Resource               *string  `json:"resource"`
	ActionType             *string  `json:"action_type"`
	TaskID                 *string  `json:"task_id"`
	RunID                  *string  `json:"run_id"`
	RequestedScopes        []string `json:"requested_scopes"`
	ReasonCode             *string  `json:"reason_code"`
	ApprovalResult         string   `json:"approval_result"`
	ActivatedAt            *string  `json:"activated_at"`
	ExpiresAt              *string  `json:"expires_at"`
	CreatedAt              string   `json:"created_at"`
}

type adminHumanApprovalEventRevokeRequest struct {
	ReasonCode string `json:"reason_code"`
}

func adminListHumanApprovalEvent(s *humanapproval.Store, _ context.Context, tenantID string, options adminHumanApprovalEventListOptions) (adminHumanApprovalEventListResponse, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return adminHumanApprovalEventListResponse{}, fmt.Errorf("tenant_id is required")
	}
	result := strings.TrimSpace(options.ApprovalResult)
	if result != "" && !validHumanApprovalResult(result) {
		return adminHumanApprovalEventListResponse{}, fmt.Errorf("approval_result %s is invalid", result)
	}
	actorNHIID := strings.TrimSpace(options.ActorNHIID)
	if actorNHIID != "" && !safeAdminDelegatedGrantRef(actorNHIID) {
		return adminHumanApprovalEventListResponse{}, fmt.Errorf("actor_nhi_id is invalid")
	}
	subjectUserID := strings.TrimSpace(options.SubjectUserID)
	if subjectUserID != "" && !safeAdminDelegatedGrantRef(subjectUserID) {
		return adminHumanApprovalEventListResponse{}, fmt.Errorf("subject_user_id is invalid")
	}
	delegatedAccessGrantID := strings.TrimSpace(options.DelegatedAccessGrantID)
	if delegatedAccessGrantID != "" && !safeAdminDelegatedGrantRef(delegatedAccessGrantID) {
		return adminHumanApprovalEventListResponse{}, fmt.Errorf("delegated_access_grant_id is invalid")
	}
	limit := options.Limit
	if limit <= 0 {
		limit = 100
	}

	rows := []adminHumanApprovalEvent{}
	for _, approval := range s.Snapshot() {
		if approval.TenantID != tenantID {
			continue
		}
		if result != "" && approval.ApprovalResult != result {
			continue
		}
		if actorNHIID != "" && stringPtrValue(approval.ActorNHIID) != actorNHIID {
			continue
		}
		if subjectUserID != "" && stringPtrValue(approval.SubjectUserID) != subjectUserID {
			continue
		}
		if delegatedAccessGrantID != "" && stringPtrValue(approval.DelegatedAccessGrantID) != delegatedAccessGrantID {
			continue
		}
		rows = append(rows, adminHumanApprovalEventFromModel(approval))
	}
	sortAdminHumanApprovalEvents(rows)
	count := len(rows)
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return adminHumanApprovalEventListResponse{
		Approvals: rows,
		Count:     count,
		Limit:     limit,
	}, nil
}

func adminGetHumanApprovalEvent(s *humanapproval.Store, _ context.Context, tenantID, approvalID string) (adminHumanApprovalEvent, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	approvalID = strings.TrimSpace(approvalID)
	if tenantID == "" {
		return adminHumanApprovalEvent{}, false, fmt.Errorf("tenant_id is required")
	}
	if approvalID == "" {
		return adminHumanApprovalEvent{}, false, fmt.Errorf("approval_id is required")
	}
	if strings.Contains(approvalID, "/") {
		return adminHumanApprovalEvent{}, false, fmt.Errorf("approval_id cannot contain slash")
	}

	approval, ok := s.GetForTenant(tenantID, approvalID)
	if !ok || approval.TenantID != tenantID {
		return adminHumanApprovalEvent{}, false, nil
	}
	return adminHumanApprovalEventFromModel(approval), true, nil
}

func adminUpsertHumanApprovalEvent(s *humanapproval.Store, _ context.Context, approval adminHumanApprovalEvent, tenantID string, now time.Time) (adminHumanApprovalEvent, error) {
	modelApproval, err := normalizeAdminHumanApprovalEvent(approval, tenantID, now)
	if err != nil {
		return adminHumanApprovalEvent{}, err
	}
	stored, err := s.Upsert(modelApproval)
	if err != nil {
		return adminHumanApprovalEvent{}, err
	}
	return adminHumanApprovalEventFromModel(stored), nil
}

func adminRevokeHumanApprovalEvent(s *humanapproval.Store, _ context.Context, tenantID, approvalID string, request adminHumanApprovalEventRevokeRequest, now time.Time) (adminHumanApprovalEvent, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	approvalID = strings.TrimSpace(approvalID)
	if tenantID == "" {
		return adminHumanApprovalEvent{}, false, fmt.Errorf("tenant_id is required")
	}
	if approvalID == "" {
		return adminHumanApprovalEvent{}, false, fmt.Errorf("approval_id is required")
	}
	if strings.Contains(approvalID, "/") {
		return adminHumanApprovalEvent{}, false, fmt.Errorf("approval_id cannot contain slash")
	}
	reasonCode := strings.TrimSpace(request.ReasonCode)
	if reasonCode != "" && !safeAdminDelegatedGrantRef(reasonCode) {
		return adminHumanApprovalEvent{}, false, fmt.Errorf("reason_code is invalid")
	}

	revoked, found, err := s.RevokeForTenant(tenantID, approvalID, reasonCode)
	if !found {
		return adminHumanApprovalEvent{}, false, err
	}
	return adminHumanApprovalEventFromModel(revoked), true, err
}

func normalizeAdminHumanApprovalEvent(approval adminHumanApprovalEvent, tenantID string, now time.Time) (model.HumanApprovalEvent, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return model.HumanApprovalEvent{}, fmt.Errorf("tenant_id is required")
	}
	approval.ID = strings.TrimSpace(approval.ID)
	if approval.ID == "" {
		return model.HumanApprovalEvent{}, fmt.Errorf("id is required")
	}
	if strings.Contains(approval.ID, "/") {
		return model.HumanApprovalEvent{}, fmt.Errorf("id cannot contain slash")
	}
	approval.TenantID = strings.TrimSpace(approval.TenantID)
	if approval.TenantID == "" {
		approval.TenantID = tenantID
	}
	if approval.TenantID != tenantID {
		return model.HumanApprovalEvent{}, fmt.Errorf("human approval event tenant_id %s does not match authenticated tenant_id %s", approval.TenantID, tenantID)
	}
	approval.ApprovalSource = strings.TrimSpace(approval.ApprovalSource)
	if approval.ApprovalSource == "" {
		approval.ApprovalSource = "admin_console"
	}
	if !safeAdminDelegatedGrantRef(approval.ApprovalSource) {
		return model.HumanApprovalEvent{}, fmt.Errorf("approval_source is invalid")
	}
	for _, item := range []struct {
		value **string
		field string
	}{
		{&approval.ApproverUserID, "approver_user_id"},
		{&approval.SubjectUserID, "subject_user_id"},
		{&approval.ActorNHIID, "actor_nhi_id"},
		{&approval.DelegatedAccessGrantID, "delegated_access_grant_id"},
		{&approval.AgentTaskSessionID, "agent_task_session_id"},
		{&approval.ApplicationID, "application_id"},
		{&approval.Audience, "audience"},
		{&approval.Resource, "resource"},
		{&approval.ActionType, "action_type"},
		{&approval.TaskID, "task_id"},
		{&approval.RunID, "run_id"},
		{&approval.ReasonCode, "reason_code"},
	} {
		if err := normalizeAdminDelegatedGrantStringPtr(item.value, item.field); err != nil {
			return model.HumanApprovalEvent{}, err
		}
	}
	if approval.ActorNHIID == nil || *approval.ActorNHIID == "" {
		return model.HumanApprovalEvent{}, fmt.Errorf("actor_nhi_id is required")
	}
	if approval.ActionType == nil || *approval.ActionType == "" {
		return model.HumanApprovalEvent{}, fmt.Errorf("action_type is required")
	}
	approval.RequestedScopes = normalizedStringList(approval.RequestedScopes)
	for _, scope := range approval.RequestedScopes {
		if !safeAdminDelegatedGrantRef(scope) {
			return model.HumanApprovalEvent{}, fmt.Errorf("requested_scopes contains invalid identifier")
		}
	}
	approval.ApprovalResult = strings.TrimSpace(approval.ApprovalResult)
	if approval.ApprovalResult == "" {
		approval.ApprovalResult = "approved"
	}
	if !validHumanApprovalResult(approval.ApprovalResult) {
		return model.HumanApprovalEvent{}, fmt.Errorf("approval_result %s is invalid", approval.ApprovalResult)
	}
	if approval.ActivatedAt != nil {
		if err := normalizeAdminRFC3339StringPtr(&approval.ActivatedAt, "activated_at"); err != nil {
			return model.HumanApprovalEvent{}, err
		}
	}
	if approval.ExpiresAt != nil {
		if err := normalizeAdminRFC3339StringPtr(&approval.ExpiresAt, "expires_at"); err != nil {
			return model.HumanApprovalEvent{}, err
		}
	}
	approval.CreatedAt = strings.TrimSpace(approval.CreatedAt)
	if approval.CreatedAt != "" {
		if _, err := time.Parse(time.RFC3339, approval.CreatedAt); err != nil {
			return model.HumanApprovalEvent{}, fmt.Errorf("created_at must be RFC3339")
		}
	}

	modelApproval := model.HumanApprovalEvent{
		ID:                     approval.ID,
		TenantID:               approval.TenantID,
		ApprovalSource:         approval.ApprovalSource,
		ApproverUserID:         approval.ApproverUserID,
		SubjectUserID:          approval.SubjectUserID,
		ActorNHIID:             approval.ActorNHIID,
		DelegatedAccessGrantID: approval.DelegatedAccessGrantID,
		AgentTaskSessionID:     approval.AgentTaskSessionID,
		ApplicationID:          approval.ApplicationID,
		Audience:               approval.Audience,
		Resource:               approval.Resource,
		ActionType:             approval.ActionType,
		TaskID:                 approval.TaskID,
		RunID:                  approval.RunID,
		RequestedScopes:        approval.RequestedScopes,
		Reason:                 approval.ReasonCode,
		ApprovalResult:         approval.ApprovalResult,
		ActivatedAt:            approval.ActivatedAt,
		ExpiresAt:              approval.ExpiresAt,
		CreatedAt:              approval.CreatedAt,
		Metadata:               map[string]any{},
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := normalizeHumanApprovalEvent(&modelApproval, tenantID, now); err != nil {
		return model.HumanApprovalEvent{}, err
	}
	return modelApproval, nil
}

func normalizeAdminRFC3339StringPtr(value **string, field string) error {
	if value == nil || *value == nil {
		return nil
	}
	trimmed := strings.TrimSpace(**value)
	if trimmed == "" {
		*value = nil
		return nil
	}
	if _, err := time.Parse(time.RFC3339, trimmed); err != nil {
		return fmt.Errorf("%s must be RFC3339", field)
	}
	*value = &trimmed
	return nil
}

func adminHumanApprovalEventFromModel(approval model.HumanApprovalEvent) adminHumanApprovalEvent {
	return adminHumanApprovalEvent{
		ID:                     approval.ID,
		TenantID:               approval.TenantID,
		ApprovalSource:         approval.ApprovalSource,
		ApproverUserID:         copyStringPtr(approval.ApproverUserID),
		SubjectUserID:          copyStringPtr(approval.SubjectUserID),
		ActorNHIID:             copyStringPtr(approval.ActorNHIID),
		DelegatedAccessGrantID: copyStringPtr(approval.DelegatedAccessGrantID),
		AgentTaskSessionID:     copyStringPtr(approval.AgentTaskSessionID),
		ApplicationID:          copyStringPtr(approval.ApplicationID),
		Audience:               copyStringPtr(approval.Audience),
		Resource:               copyStringPtr(approval.Resource),
		ActionType:             copyStringPtr(approval.ActionType),
		TaskID:                 copyStringPtr(approval.TaskID),
		RunID:                  copyStringPtr(approval.RunID),
		RequestedScopes:        append([]string(nil), approval.RequestedScopes...),
		ReasonCode:             copyStringPtr(approval.Reason),
		ApprovalResult:         approval.ApprovalResult,
		ActivatedAt:            copyStringPtr(approval.ActivatedAt),
		ExpiresAt:              copyStringPtr(approval.ExpiresAt),
		CreatedAt:              approval.CreatedAt,
	}
}

func sortAdminHumanApprovalEvents(approvals []adminHumanApprovalEvent) {
	sort.SliceStable(approvals, func(i, j int) bool {
		if approvals[i].ApprovalResult != approvals[j].ApprovalResult {
			return approvals[i].ApprovalResult < approvals[j].ApprovalResult
		}
		return approvals[i].ID < approvals[j].ID
	})
}

// Attribution belongs to the request, not the approval's subject or approver.
func adminHumanApprovalMutationAuditLog(r *http.Request, eventType string, approval adminHumanApprovalEvent, evaluator decision.Evaluator, now time.Time, partial bool) model.AuditLog {
	audit := adminHumanApprovalEventAuditLog(eventType, approval, evaluator, now)
	audit.ActorUserID = auditActorPrincipal(r)
	audit.Metadata["applied"] = true
	if partial {
		audit.Result = stringPtr("partial")
		audit.Reason = stringPtr("Approval revoked on this server; persistence is unconfirmed. Retry revocation before restarting.")
		audit.Metadata["persistence"] = "unconfirmed"
	}
	if identity, ok := adminIdentityFromRequest(r); ok && strings.TrimSpace(identity.TenantID) != "" && identity.TenantID != approval.TenantID {
		stampOperatorActor(audit.Metadata, identity)
	}
	return audit
}

func adminHumanApprovalEventAuditLog(eventType string, approval adminHumanApprovalEvent, evaluator decision.Evaluator, now time.Time) model.AuditLog {
	action := strings.TrimPrefix(eventType, "admin_human_approval_event_")
	result := approval.ApprovalResult
	reason := "Human approval event admin metadata updated."
	targetType := "admin_human_approval_event"
	return model.AuditLog{
		ID:             randomEdgeID("audit_", now),
		TenantID:       approval.TenantID,
		EventType:      eventType,
		TargetType:     &targetType,
		TargetID:       &approval.ID,
		Action:         &action,
		Result:         &result,
		Reason:         &reason,
		PolicyBundleID: &evaluator.PolicyBundle.ID,
		EdgeRegionID:   &evaluator.EdgeRegionID,
		EdgeClusterID:  &evaluator.EdgeClusterID,
		Timestamp:      now.UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"approval_source":                        approval.ApprovalSource,
			"approval_result":                        approval.ApprovalResult,
			"approver_user_id_present":               approval.ApproverUserID != nil && *approval.ApproverUserID != "",
			"subject_user_id_present":                approval.SubjectUserID != nil && *approval.SubjectUserID != "",
			"actor_nhi_id_present":                   approval.ActorNHIID != nil && *approval.ActorNHIID != "",
			"delegated_access_grant_id_present":      approval.DelegatedAccessGrantID != nil && *approval.DelegatedAccessGrantID != "",
			"agent_task_session_id_present":          approval.AgentTaskSessionID != nil && *approval.AgentTaskSessionID != "",
			"application_id_present":                 approval.ApplicationID != nil && *approval.ApplicationID != "",
			"audience_present":                       approval.Audience != nil && *approval.Audience != "",
			"resource_present":                       approval.Resource != nil && *approval.Resource != "",
			"action_type_present":                    approval.ActionType != nil && *approval.ActionType != "",
			"task_id_present":                        approval.TaskID != nil && *approval.TaskID != "",
			"run_id_present":                         approval.RunID != nil && *approval.RunID != "",
			"requested_scope_count":                  len(approval.RequestedScopes),
			"reason_code_present":                    approval.ReasonCode != nil && *approval.ReasonCode != "",
			"activated_at_present":                   approval.ActivatedAt != nil && *approval.ActivatedAt != "",
			"expires_at_present":                     approval.ExpiresAt != nil && *approval.ExpiresAt != "",
			"created_at_present":                     approval.CreatedAt != "",
			"human_approval_metadata_recorded_scope": "none",
			"notification_sent":                      false,
			"runtime_hot_reload":                     false,
			"reason_codes":                           []string{"admin_human_approval_event_lifecycle"},
		},
	}
}
