package agenttool

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

type RuntimeStore interface {
	List(context.Context, string, ListOptions) (ListResponse, error)
	Get(context.Context, string, string) (Tool, bool, error)
	Upsert(context.Context, Tool, string, time.Time) (Tool, error)
}

type ListOptions struct {
	Status     string
	ActionType string
	Limit      int
}

type ListResponse struct {
	Tools []Tool `json:"tools"`
	Count int    `json:"count"`
	Limit int    `json:"limit"`
}

type Tool struct {
	ToolID                     string   `json:"tool_id"`
	TenantID                   string   `json:"tenant_id"`
	Name                       string   `json:"name"`
	Description                string   `json:"description"`
	Publisher                  string   `json:"publisher"`
	Version                    string   `json:"version"`
	SignatureState             string   `json:"signature_state"`
	PermissionProfile          string   `json:"permission_profile"`
	ActionType                 string   `json:"action_type"`
	MCPServerID                string   `json:"mcp_server_id"`
	AllowedApplicationIDs      []string `json:"allowed_application_ids"`
	AllowedDataClassifications []string `json:"allowed_data_classifications"`
	HumanApprovalRequired      bool     `json:"human_approval_required"`
	RuntimeEnvironmentID       string   `json:"runtime_environment_id"`
	LastUsedAt                 *string  `json:"last_used_at"`
	MetadataKeyCount           int      `json:"metadata_key_count"`
	Status                     string   `json:"status"`
	UpdatedAt                  *string  `json:"updated_at"`
}

type Store struct {
	mu    sync.RWMutex
	tools map[string]map[string]Tool
}

func NewStore(tenantID string, policies []model.Policy) *Store {
	store := &Store{tools: map[string]map[string]Tool{}}
	now := time.Now().UTC()
	for _, policy := range policies {
		toolIDs := normalizedStringList(policy.AllowedToolIDs)
		actionTypes := normalizedStringList(policy.AllowedToolActions)
		for _, toolID := range toolIDs {
			actionType := "unspecified"
			if len(actionTypes) > 0 {
				actionType = actionTypes[0]
			}
			tool := Tool{
				ToolID:         toolID,
				TenantID:       firstNonEmptyString(policy.TenantID, tenantID),
				Name:           toolID,
				SignatureState: "unknown",
				ActionType:     actionType,
				Status:         "active",
			}
			normalized, err := normalize(tool, firstNonEmptyString(policy.TenantID, tenantID), now)
			if err != nil {
				continue
			}
			store.putLocked(normalized)
		}
	}
	return store
}

func (store *Store) List(_ context.Context, tenantID string, options ListOptions) (ListResponse, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return ListResponse{}, fmt.Errorf("tenant_id is required")
	}
	status := strings.TrimSpace(options.Status)
	if status != "" && !validStatus(status) {
		return ListResponse{}, fmt.Errorf("agent tool status %s is invalid", status)
	}
	actionType := strings.TrimSpace(options.ActionType)
	if actionType != "" && !safeToolToken(actionType) {
		return ListResponse{}, fmt.Errorf("action_type is invalid")
	}
	limit := options.Limit
	if limit <= 0 {
		limit = 100
	}

	store.mu.RLock()
	defer store.mu.RUnlock()

	rows := []Tool{}
	for _, tool := range store.tools[tenantID] {
		if status != "" && tool.Status != status {
			continue
		}
		if actionType != "" && tool.ActionType != actionType {
			continue
		}
		rows = append(rows, copyTool(tool))
	}
	sortTools(rows)
	count := len(rows)
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return ListResponse{
		Tools: rows,
		Count: count,
		Limit: limit,
	}, nil
}

func (store *Store) Get(_ context.Context, tenantID, toolID string) (Tool, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	toolID = strings.TrimSpace(toolID)
	if tenantID == "" {
		return Tool{}, false, fmt.Errorf("tenant_id is required")
	}
	if toolID == "" {
		return Tool{}, false, fmt.Errorf("tool_id is required")
	}

	store.mu.RLock()
	defer store.mu.RUnlock()

	tool, ok := store.tools[tenantID][toolID]
	if !ok {
		return Tool{}, false, nil
	}
	return copyTool(tool), true, nil
}

func (store *Store) Upsert(_ context.Context, tool Tool, tenantID string, now time.Time) (Tool, error) {
	normalized, err := normalize(tool, tenantID, now)
	if err != nil {
		return Tool{}, err
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	store.putLocked(normalized)
	return copyTool(normalized), nil
}

func (store *Store) putLocked(tool Tool) {
	if store.tools[tool.TenantID] == nil {
		store.tools[tool.TenantID] = map[string]Tool{}
	}
	store.tools[tool.TenantID][tool.ToolID] = copyTool(tool)
}

func normalize(tool Tool, tenantID string, now time.Time) (Tool, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return Tool{}, fmt.Errorf("tenant_id is required")
	}
	tool.ToolID = strings.TrimSpace(tool.ToolID)
	if tool.ToolID == "" {
		return Tool{}, fmt.Errorf("tool_id is required")
	}
	if strings.Contains(tool.ToolID, "/") {
		return Tool{}, fmt.Errorf("tool_id cannot contain slash")
	}
	tool.TenantID = strings.TrimSpace(tool.TenantID)
	if tool.TenantID == "" {
		tool.TenantID = tenantID
	}
	if tool.TenantID != tenantID {
		return Tool{}, fmt.Errorf("agent tool tenant_id %s does not match authenticated tenant_id %s", tool.TenantID, tenantID)
	}
	tool.Name = strings.TrimSpace(tool.Name)
	if tool.Name == "" {
		tool.Name = tool.ToolID
	}
	tool.Description = strings.TrimSpace(tool.Description)
	tool.Publisher = strings.TrimSpace(tool.Publisher)
	if tool.Publisher != "" && !safeToolToken(tool.Publisher) {
		return Tool{}, fmt.Errorf("publisher is invalid")
	}
	tool.Version = strings.TrimSpace(tool.Version)
	if tool.Version != "" && !safeToolToken(tool.Version) {
		return Tool{}, fmt.Errorf("version is invalid")
	}
	tool.SignatureState = strings.TrimSpace(tool.SignatureState)
	if tool.SignatureState == "" {
		tool.SignatureState = "unknown"
	}
	if !validSignatureState(tool.SignatureState) {
		return Tool{}, fmt.Errorf("signature_state %s is invalid", tool.SignatureState)
	}
	tool.PermissionProfile = strings.TrimSpace(tool.PermissionProfile)
	if tool.PermissionProfile != "" && !safeToolToken(tool.PermissionProfile) {
		return Tool{}, fmt.Errorf("permission_profile is invalid")
	}
	tool.ActionType = strings.TrimSpace(tool.ActionType)
	if tool.ActionType == "" {
		tool.ActionType = "unspecified"
	}
	if !safeToolToken(tool.ActionType) {
		return Tool{}, fmt.Errorf("action_type is invalid")
	}
	tool.MCPServerID = strings.TrimSpace(tool.MCPServerID)
	if tool.MCPServerID != "" && !safeToolToken(tool.MCPServerID) {
		return Tool{}, fmt.Errorf("mcp_server_id is invalid")
	}
	tool.AllowedApplicationIDs = normalizedStringList(tool.AllowedApplicationIDs)
	for _, applicationID := range tool.AllowedApplicationIDs {
		if !safeAdminCatalogRef(applicationID) {
			return Tool{}, fmt.Errorf("allowed_application_ids contains invalid identifier")
		}
	}
	tool.AllowedDataClassifications = normalizedStringList(tool.AllowedDataClassifications)
	for _, classification := range tool.AllowedDataClassifications {
		if !safeToolToken(classification) {
			return Tool{}, fmt.Errorf("allowed_data_classifications contains invalid identifier")
		}
	}
	tool.RuntimeEnvironmentID = strings.TrimSpace(tool.RuntimeEnvironmentID)
	if tool.RuntimeEnvironmentID != "" && !safeToolToken(tool.RuntimeEnvironmentID) {
		return Tool{}, fmt.Errorf("runtime_environment_id is invalid")
	}
	if tool.LastUsedAt != nil {
		lastUsedAt := strings.TrimSpace(*tool.LastUsedAt)
		if lastUsedAt == "" {
			tool.LastUsedAt = nil
		} else {
			if _, err := time.Parse(time.RFC3339, lastUsedAt); err != nil {
				return Tool{}, fmt.Errorf("last_used_at must be RFC3339")
			}
			tool.LastUsedAt = &lastUsedAt
		}
	}
	if tool.MetadataKeyCount < 0 {
		return Tool{}, fmt.Errorf("metadata_key_count must be non-negative")
	}
	tool.Status = strings.TrimSpace(tool.Status)
	if tool.Status == "" {
		tool.Status = "draft"
	}
	if !validStatus(tool.Status) {
		return Tool{}, fmt.Errorf("agent tool status %s is invalid", tool.Status)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	updatedAt := now.UTC().Format(time.RFC3339)
	tool.UpdatedAt = &updatedAt
	return tool, nil
}

func validSignatureState(signatureState string) bool {
	switch signatureState {
	case "unknown", "unsigned", "signed", "verified", "revoked":
		return true
	default:
		return false
	}
}

func validStatus(status string) bool {
	switch status {
	case "active", "draft", "disabled", "revoked":
		return true
	default:
		return false
	}
}

func safeToolToken(value string) bool {
	if value == "" {
		return false
	}
	for _, ch := range value {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.' || ch == ':' {
			continue
		}
		return false
	}
	return true
}

func copyTool(tool Tool) Tool {
	tool.AllowedApplicationIDs = append([]string(nil), tool.AllowedApplicationIDs...)
	tool.AllowedDataClassifications = append([]string(nil), tool.AllowedDataClassifications...)
	return tool
}

func sortTools(tools []Tool) {
	sort.SliceStable(tools, func(i, j int) bool {
		if tools[i].Status != tools[j].Status {
			return tools[i].Status < tools[j].Status
		}
		return tools[i].ToolID < tools[j].ToolID
	})
}

// normalizedStringList trims, de-dups, and drops empties (order-preserving) — package-local copy of the
// shared admin helper so the package stays self-contained.
func normalizedStringList(values []string) []string {
	result := []string{}
	seen := map[string]bool{}
	for _, value := range values {
		normalized := strings.TrimSpace(value)
		if normalized == "" || seen[normalized] {
			continue
		}
		seen[normalized] = true
		result = append(result, normalized)
	}
	return result
}

// firstNonEmptyString returns the first non-blank value (after trimming), else "".
func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

// safeAdminCatalogRef reports whether ref is a safe catalog identifier (alphanumerics + _-), used to
// validate allowed_application_ids — package-local copy of the shared admin validator.
func safeAdminCatalogRef(ref string) bool {
	if ref == "" {
		return false
	}
	for _, ch := range ref {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' {
			continue
		}
		return false
	}
	return true
}
