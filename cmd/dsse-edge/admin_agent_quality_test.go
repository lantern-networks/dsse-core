package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	devicestore "github.com/lantern-networks/dsse-core/device"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

func TestAdminAgentQualityEndpoint(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	now := time.Now().UTC()
	devices := devicestore.NewStore()
	if _, err := devices.Register(model.Device{
		ID:                  "dev_quality_healthy",
		TenantID:            "tenant_lab_001",
		UserID:              "user_quality_001",
		Hostname:            "macbook-quality",
		OS:                  "macos",
		AgentVersion:        "0.1.2",
		DeviceTrustLevel:    "managed",
		Status:              "healthy",
		RegisteredAt:        now.Add(-time.Hour).Format(time.RFC3339),
		LastSeenAt:          now.Add(-time.Minute).Format(time.RFC3339),
		PolicyBundleID:      "pb_lab_20260522_001",
		PolicyBundleVersion: "2026.05.22.001",
	}, testEvaluator().PolicyBundle, now); err != nil {
		t.Fatalf("register healthy device: %v", err)
	}
	if _, err := devices.Register(model.Device{
		ID:                  "dev_quality_stale",
		TenantID:            "tenant_lab_001",
		UserID:              "user_quality_002",
		Hostname:            "macbook-stale",
		OS:                  "macos",
		AgentVersion:        "0.1.0",
		DeviceTrustLevel:    "managed",
		Status:              "degraded",
		RegisteredAt:        now.Add(-2 * time.Hour).Format(time.RFC3339),
		LastSeenAt:          now.Add(-agentQualityStaleAfter - time.Minute).Format(time.RFC3339),
		PolicyBundleID:      "pb_lab_20260522_001",
		PolicyBundleVersion: "2026.05.22.001",
	}, testEvaluator().PolicyBundle, now); err != nil {
		t.Fatalf("register stale device: %v", err)
	}
	if _, err := devices.Register(model.Device{
		ID:                  "dev_quality_other_tenant",
		TenantID:            "tenant_other_001",
		UserID:              "user_other_001",
		Hostname:            "other",
		OS:                  "macos",
		AgentVersion:        "9.9.9",
		DeviceTrustLevel:    "managed",
		Status:              "healthy",
		RegisteredAt:        now.Format(time.RFC3339),
		LastSeenAt:          now.Format(time.RFC3339),
		PolicyBundleID:      "pb_other",
		PolicyBundleVersion: "other",
	}, model.PolicyBundle{TenantID: "tenant_other_001"}, now); err != nil {
		t.Fatalf("register other tenant device: %v", err)
	}
	for _, event := range []model.AgentUpdateEvent{
		{ID: "aue_quality_installed", TenantID: "tenant_lab_001", DeviceID: "dev_quality_healthy", UserID: "user_quality_001", CurrentAgentVersion: "0.1.1", TargetAgentVersion: "0.1.2", ReleaseChannel: "lab", UpdateStatus: "installed", UpdateSource: "control_plane", Timestamp: now.Format(time.RFC3339)},
		{ID: "aue_quality_failed", TenantID: "tenant_lab_001", DeviceID: "dev_quality_stale", UserID: "user_quality_002", CurrentAgentVersion: "0.1.0", TargetAgentVersion: "0.1.2", ReleaseChannel: "lab", UpdateStatus: "failed", UpdateSource: "mdm", Timestamp: now.Format(time.RFC3339)},
		{ID: "aue_quality_other", TenantID: "tenant_other_001", DeviceID: "dev_quality_other_tenant", UserID: "user_other_001", CurrentAgentVersion: "9.9.8", TargetAgentVersion: "9.9.9", ReleaseChannel: "lab", UpdateStatus: "installed", UpdateSource: "manual", Timestamp: now.Format(time.RFC3339)},
	} {
		if err := writer.Append("audit.log.jsonl", agentUpdateAuditLog(event, testEvaluator(), "127.0.0.1")); err != nil {
			t.Fatalf("append agent update audit: %v", err)
		}
	}
	for _, status := range []model.AgentStatus{
		{DeviceID: "dev_quality_healthy", TenantID: "tenant_lab_001", PolicyBundleID: "pb_lab_001", PolicyBundleVersion: "2026.05.25.001", BundleSource: "remote", DeviceTrustLevel: "managed", Status: "healthy", Timestamp: now.Format(time.RFC3339), Metadata: map[string]any{"crash_count": 0, "steering_attempted": 4, "steering_succeeded": 3, "steering_failed": 1, "connect_unsupported": 2}},
		{DeviceID: "dev_quality_stale", TenantID: "tenant_lab_001", PolicyBundleID: "pb_lab_001", PolicyBundleVersion: "2026.05.25.001", BundleSource: "remote", DeviceTrustLevel: "managed", Status: "degraded", Timestamp: now.Format(time.RFC3339), Metadata: map[string]any{"crash_count": 1, "steering_attempted": 1, "steering_succeeded": 1, "steering_failed": 0, "connect_unsupported": 1}},
		{DeviceID: "dev_quality_other_tenant", TenantID: "tenant_other_001", PolicyBundleID: "pb_other", PolicyBundleVersion: "other", BundleSource: "remote", DeviceTrustLevel: "managed", Status: "healthy", Timestamp: now.Format(time.RFC3339), Metadata: map[string]any{"crash_count": 0, "steering_attempted": 10, "steering_succeeded": 10, "connect_unsupported": 10}},
	} {
		if err := writer.Append("audit.log.jsonl", agentStatusAuditLog(status, testEvaluator(), "127.0.0.1")); err != nil {
			t.Fatalf("append agent status audit: %v", err)
		}
	}
	for _, dec := range []model.AccessDecision{
		{ID: "dec_quality_allow", TenantID: "tenant_lab_001", ApplicationID: "app_dummy_https", Decision: "allow", ServiceFamily: stringPtr("https"), ConnectorID: stringPtr("conn_lab_001"), Timestamp: now.Format(time.RFC3339), Metadata: map[string]any{}},
		{ID: "dec_quality_deny", TenantID: "tenant_lab_001", ApplicationID: "app_dummy_ssh", Decision: "deny", ServiceFamily: stringPtr("ssh"), Timestamp: now.Format(time.RFC3339), Metadata: map[string]any{}},
		{ID: "dec_quality_other", TenantID: "tenant_other_001", ApplicationID: "app_dummy_https", Decision: "allow", ServiceFamily: stringPtr("https"), ConnectorID: stringPtr("conn_other_001"), Timestamp: now.Format(time.RFC3339), Metadata: map[string]any{}},
	} {
		if err := writer.Append("access.log.jsonl", decision.AccessLogFromDecision(dec)); err != nil {
			t.Fatalf("append access log: %v", err)
		}
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:          testEvaluator(),
		Writer:             writer,
		DeviceStore:        devices,
		AgentTargetVersion: "0.1.2",
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/agent/quality", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var summary map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&summary); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if summary["quality_status"] != "warn" {
		t.Fatalf("quality status = %#v", summary["quality_status"])
	}
	reasons := summary["quality_reasons"].([]any)
	if !containsAnyString(reasons, "stale_devices") || !containsAnyString(reasons, "agent_crash_events") || !containsAnyString(reasons, "steering_failures") || !containsAnyString(reasons, "agent_update_failures") {
		t.Fatalf("quality reasons = %#v", reasons)
	}
	devicesSummary := summary["devices"].(map[string]any)
	if devicesSummary["total"] != float64(2) || devicesSummary["stale"] != float64(1) || devicesSummary["on_target_version"] != float64(1) {
		t.Fatalf("devices summary = %#v", devicesSummary)
	}
	statusCounts := devicesSummary["status_counts"].(map[string]any)
	if statusCounts["healthy"] != float64(1) || statusCounts["degraded"] != float64(1) {
		t.Fatalf("status counts = %#v", statusCounts)
	}
	updateSummary := summary["agent_update_events"].(map[string]any)
	if updateSummary["total"] != float64(2) || updateSummary["terminal_events"] != float64(2) || updateSummary["installed_events"] != float64(1) {
		t.Fatalf("update summary = %#v", updateSummary)
	}
	if updateSummary["update_success_rate"] != float64(0.5) {
		t.Fatalf("success rate = %#v", updateSummary["update_success_rate"])
	}
	statusSummary := summary["agent_status_events"].(map[string]any)
	if statusSummary["total"] != float64(2) || statusSummary["crash_events"] != float64(1) || statusSummary["steering_attempted"] != float64(5) || statusSummary["steering_succeeded"] != float64(4) || statusSummary["steering_failed"] != float64(1) || statusSummary["connect_unsupported"] != float64(3) {
		t.Fatalf("agent status summary = %#v", statusSummary)
	}
	if statusSummary["crash_free_rate"] != float64(0.5) || statusSummary["steering_success_rate"] != float64(0.8) {
		t.Fatalf("agent status rates = %#v", statusSummary)
	}
	accessSummary := summary["access_decisions"].(map[string]any)
	if accessSummary["total"] != float64(2) || accessSummary["allowed_events"] != float64(1) || accessSummary["with_connector"] != float64(1) {
		t.Fatalf("access summary = %#v", accessSummary)
	}
	if accessSummary["allow_rate"] != float64(0.5) {
		t.Fatalf("allow rate = %#v", accessSummary["allow_rate"])
	}
	decisionCounts := accessSummary["decision_counts"].(map[string]any)
	if decisionCounts["allow"] != float64(1) || decisionCounts["deny"] != float64(1) {
		t.Fatalf("decision counts = %#v", decisionCounts)
	}
}
