package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	delegatedgrant "github.com/lantern-networks/dsse-core/delegatedgrant"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

type adminDelegatedAccessGrantListOptions struct {
	Status        string
	ActorNHIID    string
	SubjectUserID string
	Limit         int
}

type adminDelegatedAccessGrantListResponse struct {
	Grants []adminDelegatedAccessGrant `json:"grants"`
	Count  int                         `json:"count"`
	Limit  int                         `json:"limit"`
}

type adminDelegatedAccessGrant struct {
	ID                   string   `json:"id"`
	TenantID             string   `json:"tenant_id"`
	SubjectUserID        string   `json:"subject_user_id"`
	ActorNHIID           string   `json:"actor_nhi_id"`
	DeviceID             *string  `json:"device_id"`
	ApplicationID        *string  `json:"application_id"`
	Audience             *string  `json:"audience"`
	Resource             *string  `json:"resource"`
	Scopes               []string `json:"scopes"`
	Purpose              *string  `json:"purpose"`
	TaskID               *string  `json:"task_id"`
	RunID                *string  `json:"run_id"`
	ToolIDs              []string `json:"tool_ids"`
	ApprovalEventID      *string  `json:"approval_event_id"`
	TokenBindingRequired bool     `json:"token_binding_required"`
	MaxSessionDuration   *int     `json:"max_session_duration"`
	ExpiresAt            string   `json:"expires_at"`
	CreatedAt            *string  `json:"created_at"`
	RevokedAt            *string  `json:"revoked_at"`
	RevocationReasonCode *string  `json:"revocation_reason_code"`
	Status               string   `json:"status"`
}

type adminDelegatedAccessGrantRevokeRequest struct {
	RevocationReasonCode string `json:"revocation_reason_code"`
}

func adminListDelegatedAccessGrant(s *delegatedgrant.Store, ctx context.Context, tenantID string, options adminDelegatedAccessGrantListOptions) (adminDelegatedAccessGrantListResponse, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return adminDelegatedAccessGrantListResponse{}, fmt.Errorf("tenant_id is required")
	}
	status := strings.TrimSpace(options.Status)
	if status != "" && !validDelegatedGrantStatus(status) {
		return adminDelegatedAccessGrantListResponse{}, fmt.Errorf("delegated access grant status %s is invalid", status)
	}
	actorNHIID := strings.TrimSpace(options.ActorNHIID)
	if actorNHIID != "" && !safeAdminDelegatedGrantRef(actorNHIID) {
		return adminDelegatedAccessGrantListResponse{}, fmt.Errorf("actor_nhi_id is invalid")
	}
	subjectUserID := strings.TrimSpace(options.SubjectUserID)
	if subjectUserID != "" && !safeAdminDelegatedGrantRef(subjectUserID) {
		return adminDelegatedAccessGrantListResponse{}, fmt.Errorf("subject_user_id is invalid")
	}
	limit := options.Limit
	if limit <= 0 {
		limit = 100
	}

	if err := s.RefreshShared(); err != nil {
		return adminDelegatedAccessGrantListResponse{}, err
	}
	rows := []adminDelegatedAccessGrant{}
	for _, grant := range s.Snapshot() {
		if grant.TenantID != tenantID {
			continue
		}
		if status != "" && grant.Status != status {
			continue
		}
		if actorNHIID != "" && grant.ActorNHIID != actorNHIID {
			continue
		}
		if subjectUserID != "" && grant.SubjectUserID != subjectUserID {
			continue
		}
		rows = append(rows, adminDelegatedAccessGrantFromModel(grant))
	}
	sortAdminDelegatedAccessGrants(rows)
	count := len(rows)
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return adminDelegatedAccessGrantListResponse{
		Grants: rows,
		Count:  count,
		Limit:  limit,
	}, nil
}

func adminGetDelegatedAccessGrant(s *delegatedgrant.Store, ctx context.Context, tenantID, grantID string) (adminDelegatedAccessGrant, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	grantID = strings.TrimSpace(grantID)
	if tenantID == "" {
		return adminDelegatedAccessGrant{}, false, fmt.Errorf("tenant_id is required")
	}
	if grantID == "" {
		return adminDelegatedAccessGrant{}, false, fmt.Errorf("grant_id is required")
	}
	if strings.Contains(grantID, "/") {
		return adminDelegatedAccessGrant{}, false, fmt.Errorf("grant_id cannot contain slash")
	}

	grant, ok, err := s.GetForTenantContext(ctx, tenantID, grantID)
	if err != nil {
		return adminDelegatedAccessGrant{}, false, err
	}
	if !ok || grant.TenantID != tenantID {
		return adminDelegatedAccessGrant{}, false, nil
	}
	return adminDelegatedAccessGrantFromModel(grant), true, nil
}

func adminUpsertDelegatedAccessGrant(s *delegatedgrant.Store, ctx context.Context, grant adminDelegatedAccessGrant, tenantID string, now time.Time) (adminDelegatedAccessGrant, error) {
	modelGrant, err := normalizeAdminDelegatedAccessGrant(grant, tenantID, now)
	if err != nil {
		return adminDelegatedAccessGrant{}, err
	}
	stored, err := s.UpsertContext(ctx, modelGrant)
	if err != nil {
		return adminDelegatedAccessGrant{}, err
	}
	return adminDelegatedAccessGrantFromModel(stored), nil
}

func adminRevokeDelegatedAccessGrant(s *delegatedgrant.Store, ctx context.Context, tenantID, grantID string, request adminDelegatedAccessGrantRevokeRequest, now time.Time) (adminDelegatedAccessGrant, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	grantID = strings.TrimSpace(grantID)
	if tenantID == "" {
		return adminDelegatedAccessGrant{}, false, fmt.Errorf("tenant_id is required")
	}
	if grantID == "" {
		return adminDelegatedAccessGrant{}, false, fmt.Errorf("grant_id is required")
	}
	if strings.Contains(grantID, "/") {
		return adminDelegatedAccessGrant{}, false, fmt.Errorf("grant_id cannot contain slash")
	}
	reasonCode := strings.TrimSpace(request.RevocationReasonCode)
	if reasonCode != "" && !safeAdminDelegatedGrantRef(reasonCode) {
		return adminDelegatedAccessGrant{}, false, fmt.Errorf("revocation_reason_code is invalid")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	grant, err := s.RevokeForTenantContext(ctx, tenantID, grantID, reasonCode, now)
	if errors.Is(err, delegatedgrant.ErrAbsent) {
		return adminDelegatedAccessGrant{}, false, nil
	}
	if err != nil {
		if errors.Is(err, delegatedgrant.ErrPersistence) && grant.TenantID == tenantID && grant.ID == grantID && grant.Status == "revoked" {
			return adminDelegatedAccessGrantFromModel(grant), true, err
		}
		return adminDelegatedAccessGrant{}, false, err
	}

	return adminDelegatedAccessGrantFromModel(grant), true, nil
}

func normalizeAdminDelegatedAccessGrant(grant adminDelegatedAccessGrant, tenantID string, now time.Time) (model.DelegatedAccessGrant, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return model.DelegatedAccessGrant{}, fmt.Errorf("tenant_id is required")
	}
	grant.ID = strings.TrimSpace(grant.ID)
	if grant.ID == "" {
		return model.DelegatedAccessGrant{}, fmt.Errorf("id is required")
	}
	if strings.Contains(grant.ID, "/") {
		return model.DelegatedAccessGrant{}, fmt.Errorf("id cannot contain slash")
	}
	grant.TenantID = strings.TrimSpace(grant.TenantID)
	if grant.TenantID == "" {
		grant.TenantID = tenantID
	}
	if grant.TenantID != tenantID {
		return model.DelegatedAccessGrant{}, fmt.Errorf("delegated access grant tenant_id %s does not match authenticated tenant_id %s", grant.TenantID, tenantID)
	}
	grant.SubjectUserID = strings.TrimSpace(grant.SubjectUserID)
	if grant.SubjectUserID == "" {
		return model.DelegatedAccessGrant{}, fmt.Errorf("subject_user_id is required")
	}
	if !safeAdminDelegatedGrantRef(grant.SubjectUserID) {
		return model.DelegatedAccessGrant{}, fmt.Errorf("subject_user_id is invalid")
	}
	grant.ActorNHIID = strings.TrimSpace(grant.ActorNHIID)
	if grant.ActorNHIID == "" {
		return model.DelegatedAccessGrant{}, fmt.Errorf("actor_nhi_id is required")
	}
	if !safeAdminDelegatedGrantRef(grant.ActorNHIID) {
		return model.DelegatedAccessGrant{}, fmt.Errorf("actor_nhi_id is invalid")
	}
	if err := normalizeAdminDelegatedGrantStringPtr(&grant.DeviceID, "device_id"); err != nil {
		return model.DelegatedAccessGrant{}, err
	}
	if err := normalizeAdminDelegatedGrantStringPtr(&grant.ApplicationID, "application_id"); err != nil {
		return model.DelegatedAccessGrant{}, err
	}
	if err := normalizeAdminDelegatedGrantStringPtr(&grant.Audience, "audience"); err != nil {
		return model.DelegatedAccessGrant{}, err
	}
	if err := normalizeAdminDelegatedGrantStringPtr(&grant.Resource, "resource"); err != nil {
		return model.DelegatedAccessGrant{}, err
	}
	if err := normalizeAdminDelegatedGrantStringPtr(&grant.Purpose, "purpose"); err != nil {
		return model.DelegatedAccessGrant{}, err
	}
	if err := normalizeAdminDelegatedGrantStringPtr(&grant.TaskID, "task_id"); err != nil {
		return model.DelegatedAccessGrant{}, err
	}
	if err := normalizeAdminDelegatedGrantStringPtr(&grant.RunID, "run_id"); err != nil {
		return model.DelegatedAccessGrant{}, err
	}
	if err := normalizeAdminDelegatedGrantStringPtr(&grant.ApprovalEventID, "approval_event_id"); err != nil {
		return model.DelegatedAccessGrant{}, err
	}
	grant.Scopes = normalizedStringList(grant.Scopes)
	for _, scope := range grant.Scopes {
		if !safeAdminDelegatedGrantRef(scope) {
			return model.DelegatedAccessGrant{}, fmt.Errorf("scopes contains invalid identifier")
		}
	}
	grant.ToolIDs = normalizedStringList(grant.ToolIDs)
	for _, toolID := range grant.ToolIDs {
		if !safeAdminDelegatedGrantRef(toolID) {
			return model.DelegatedAccessGrant{}, fmt.Errorf("tool_ids contains invalid identifier")
		}
	}
	if grant.MaxSessionDuration != nil && *grant.MaxSessionDuration <= 0 {
		return model.DelegatedAccessGrant{}, fmt.Errorf("max_session_duration must be positive")
	}
	grant.ExpiresAt = strings.TrimSpace(grant.ExpiresAt)
	if grant.ExpiresAt != "" {
		if _, err := time.Parse(time.RFC3339, grant.ExpiresAt); err != nil {
			return model.DelegatedAccessGrant{}, fmt.Errorf("expires_at must be RFC3339")
		}
	}
	if grant.CreatedAt != nil {
		createdAt := strings.TrimSpace(*grant.CreatedAt)
		if createdAt == "" {
			grant.CreatedAt = nil
		} else {
			if _, err := time.Parse(time.RFC3339, createdAt); err != nil {
				return model.DelegatedAccessGrant{}, fmt.Errorf("created_at must be RFC3339")
			}
			grant.CreatedAt = &createdAt
		}
	}
	grant.Status = strings.TrimSpace(grant.Status)
	if grant.Status == "" {
		grant.Status = "active"
	}
	if !validDelegatedGrantStatus(grant.Status) {
		return model.DelegatedAccessGrant{}, fmt.Errorf("delegated access grant status %s is invalid", grant.Status)
	}

	modelGrant := model.DelegatedAccessGrant{
		ID:                   grant.ID,
		TenantID:             grant.TenantID,
		SubjectUserID:        grant.SubjectUserID,
		ActorNHIID:           grant.ActorNHIID,
		DeviceID:             grant.DeviceID,
		ApplicationID:        grant.ApplicationID,
		Audience:             grant.Audience,
		Resource:             grant.Resource,
		Scopes:               grant.Scopes,
		Purpose:              grant.Purpose,
		TaskID:               grant.TaskID,
		RunID:                grant.RunID,
		ToolIDs:              grant.ToolIDs,
		ApprovalEventID:      grant.ApprovalEventID,
		TokenBindingRequired: grant.TokenBindingRequired,
		MaxSessionDuration:   grant.MaxSessionDuration,
		ExpiresAt:            grant.ExpiresAt,
		CreatedAt:            grant.CreatedAt,
		Status:               grant.Status,
		Metadata:             map[string]any{},
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := normalizeDelegatedAccessGrant(&modelGrant, tenantID, now); err != nil {
		return model.DelegatedAccessGrant{}, err
	}
	return modelGrant, nil
}

func adminDelegatedAccessGrantFromModel(grant model.DelegatedAccessGrant) adminDelegatedAccessGrant {
	return adminDelegatedAccessGrant{
		ID:                   grant.ID,
		TenantID:             grant.TenantID,
		SubjectUserID:        grant.SubjectUserID,
		ActorNHIID:           grant.ActorNHIID,
		DeviceID:             copyStringPtr(grant.DeviceID),
		ApplicationID:        copyStringPtr(grant.ApplicationID),
		Audience:             copyStringPtr(grant.Audience),
		Resource:             copyStringPtr(grant.Resource),
		Scopes:               append([]string(nil), grant.Scopes...),
		Purpose:              copyStringPtr(grant.Purpose),
		TaskID:               copyStringPtr(grant.TaskID),
		RunID:                copyStringPtr(grant.RunID),
		ToolIDs:              append([]string(nil), grant.ToolIDs...),
		ApprovalEventID:      copyStringPtr(grant.ApprovalEventID),
		TokenBindingRequired: grant.TokenBindingRequired,
		MaxSessionDuration:   copyIntPtr(grant.MaxSessionDuration),
		ExpiresAt:            grant.ExpiresAt,
		CreatedAt:            copyStringPtr(grant.CreatedAt),
		RevokedAt:            copyStringPtr(grant.RevokedAt),
		RevocationReasonCode: copyStringPtr(grant.RevocationReason),
		Status:               grant.Status,
	}
}

func normalizeAdminDelegatedGrantStringPtr(value **string, field string) error {
	if value == nil || *value == nil {
		return nil
	}
	trimmed := strings.TrimSpace(**value)
	if trimmed == "" {
		*value = nil
		return nil
	}
	if !safeAdminDelegatedGrantRef(trimmed) {
		return fmt.Errorf("%s is invalid", field)
	}
	*value = &trimmed
	return nil
}

func safeAdminDelegatedGrantRef(value string) bool {
	if value == "" {
		return false
	}
	for _, ch := range value {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.' || ch == ':' || ch == '@' {
			continue
		}
		return false
	}
	return true
}

func copyStringPtr(value *string) *string {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}

func copyIntPtr(value *int) *int {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}

func sortAdminDelegatedAccessGrants(grants []adminDelegatedAccessGrant) {
	sort.SliceStable(grants, func(i, j int) bool {
		if grants[i].Status != grants[j].Status {
			return grants[i].Status < grants[j].Status
		}
		return grants[i].ID < grants[j].ID
	})
}

func adminDelegatedAccessGrantAuditLog(eventType string, grant adminDelegatedAccessGrant, evaluator decision.Evaluator, now time.Time) model.AuditLog {
	action := strings.TrimPrefix(eventType, "admin_delegated_access_grant_")
	result := grant.Status
	reason := "Delegated access grant admin metadata updated."
	targetType := "admin_delegated_access_grant"
	return model.AuditLog{
		ID:             randomEdgeID("audit_", now),
		TenantID:       grant.TenantID,
		EventType:      eventType,
		TargetType:     &targetType,
		TargetID:       &grant.ID,
		Action:         &action,
		Result:         &result,
		Reason:         &reason,
		PolicyBundleID: &evaluator.PolicyBundle.ID,
		EdgeRegionID:   &evaluator.EdgeRegionID,
		EdgeClusterID:  &evaluator.EdgeClusterID,
		Timestamp:      now.UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"status":                                  grant.Status,
			"subject_user_id_present":                 grant.SubjectUserID != "",
			"actor_nhi_id_present":                    grant.ActorNHIID != "",
			"device_id_present":                       grant.DeviceID != nil && *grant.DeviceID != "",
			"application_id_present":                  grant.ApplicationID != nil && *grant.ApplicationID != "",
			"audience_present":                        grant.Audience != nil && *grant.Audience != "",
			"resource_present":                        grant.Resource != nil && *grant.Resource != "",
			"scope_count":                             len(grant.Scopes),
			"tool_id_count":                           len(grant.ToolIDs),
			"approval_event_id_present":               grant.ApprovalEventID != nil && *grant.ApprovalEventID != "",
			"token_binding_required":                  grant.TokenBindingRequired,
			"max_session_duration_present":            grant.MaxSessionDuration != nil,
			"expires_at_present":                      grant.ExpiresAt != "",
			"revoked_at_present":                      grant.RevokedAt != nil && *grant.RevokedAt != "",
			"revocation_reason_code_present":          grant.RevocationReasonCode != nil && *grant.RevocationReasonCode != "",
			"delegated_grant_metadata_recorded_scope": "none",
			"delegated_token_issued":                  false,
			"runtime_hot_reload":                      false,
			"reason_codes":                            []string{"admin_delegated_access_grant_lifecycle"},
		},
	}
}
