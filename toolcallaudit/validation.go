package toolcallaudit

import (
	"fmt"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

func Normalize(event *model.ToolCallEvent, expectedTenantID string, now time.Time) error {
	if event.ID == "" {
		return fmt.Errorf("tool call event id is required")
	}
	if event.TenantID == "" {
		return fmt.Errorf("tool call event tenant_id is required")
	}
	if expectedTenantID != "" && event.TenantID != expectedTenantID {
		return fmt.Errorf("tool call event tenant_id %s does not match edge tenant_id %s", event.TenantID, expectedTenantID)
	}
	if event.ActorNHIID == "" {
		return fmt.Errorf("tool call event actor_nhi_id is required")
	}
	if event.ToolID == "" {
		return fmt.Errorf("tool call event tool_id is required")
	}
	if event.ActionType == "" {
		return fmt.Errorf("tool call event action_type is required")
	}
	if event.Timestamp == "" {
		event.Timestamp = now.UTC().Format(time.RFC3339)
	}
	if event.ResultSummaryScope == "" {
		event.ResultSummaryScope = "metadata_only"
	}
	if !toolCallEventResultSummaryScopeAllowed(event.ResultSummaryScope) {
		return fmt.Errorf("tool call event result_summary_scope %q is not accepted", event.ResultSummaryScope)
	}
	if event.Metadata == nil {
		event.Metadata = map[string]any{}
	}
	if forbiddenKey, ok := toolCallEventMetadataContainsForbiddenKey(event.Metadata); ok {
		return fmt.Errorf("tool call event metadata key %s is not accepted for non-secret audit logging", forbiddenKey)
	}
	return nil
}

func toolCallEventResultSummaryScopeAllowed(scope string) bool {
	switch scope {
	case "metadata_only", "masked_summary", "payload_reference":
		return true
	default:
		return false
	}
}

func toolCallEventMetadataContainsForbiddenKey(metadata map[string]any) (string, bool) {
	for key, value := range metadata {
		path := key
		if toolCallEventMetadataKeyForbidden(key) {
			return path, true
		}
		if nested, ok := toolCallEventValueContainsForbiddenKey(value, path); ok {
			return nested, true
		}
	}
	return "", false
}

func toolCallEventValueContainsForbiddenKey(value any, path string) (string, bool) {
	switch typed := value.(type) {
	case map[string]any:
		for key, nestedValue := range typed {
			nestedPath := path + "." + key
			if toolCallEventMetadataKeyForbidden(key) {
				return nestedPath, true
			}
			if nested, ok := toolCallEventValueContainsForbiddenKey(nestedValue, nestedPath); ok {
				return nested, true
			}
		}
	case []any:
		for index, nestedValue := range typed {
			if nested, ok := toolCallEventValueContainsForbiddenKey(nestedValue, fmt.Sprintf("%s[%d]", path, index)); ok {
				return nested, true
			}
		}
	}
	return "", false
}

func toolCallEventMetadataKeyForbidden(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(key), "-", "_"), " ", "_"))
	for _, fragment := range []string{
		"payload",
		"raw_output",
		"raw_prompt",
		"token",
		"secret",
		"credential",
		"password",
		"cookie",
		"session_id",
		"client_secret",
	} {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}
	return false
}
