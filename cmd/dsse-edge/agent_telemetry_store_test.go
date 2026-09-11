package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	agenttelemetry "github.com/lantern-networks/dsse-core/agenttelemetry"

	devicestore "github.com/lantern-networks/dsse-core/device"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

func TestAgentQualityEndpointUsesTelemetryStore(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	evaluator := testEvaluator()
	devices := devicestore.NewStore()
	now := time.Now().UTC()
	if _, err := devices.Register(model.Device{
		ID:                  "dev_telemetry_001",
		TenantID:            evaluator.PolicyBundle.TenantID,
		UserID:              "user_lab_001",
		Hostname:            "telemetry-device",
		OS:                  "macos",
		AgentVersion:        "0.1.0",
		DeviceTrustLevel:    "managed",
		Status:              "healthy",
		RegisteredAt:        now.Format(time.RFC3339),
		LastSeenAt:          now.Format(time.RFC3339),
		PolicyBundleID:      evaluator.PolicyBundle.ID,
		PolicyBundleVersion: evaluator.PolicyBundle.Version,
	}, evaluator.PolicyBundle, now); err != nil {
		t.Fatalf("Register device returned error: %v", err)
	}
	telemetry := agenttelemetry.NewStore()
	if err := telemetry.RecordUpdate(context.Background(), model.AgentUpdateEvent{ID: "aue_telemetry_001", TenantID: evaluator.PolicyBundle.TenantID, DeviceID: "dev_telemetry_001", UpdateStatus: "installed", Timestamp: now.Format(time.RFC3339)}); err != nil {
		t.Fatalf("RecordUpdate returned error: %v", err)
	}
	if err := telemetry.RecordStatus(context.Background(), model.AgentStatus{TenantID: evaluator.PolicyBundle.TenantID, DeviceID: "dev_telemetry_001", Status: "healthy", Timestamp: now.Format(time.RFC3339), Metadata: map[string]any{"crash_count": 0, "steering_attempted": 1, "steering_succeeded": 1, "connect_unsupported": 1}}); err != nil {
		t.Fatalf("RecordStatus returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:          evaluator,
		Writer:             writer,
		DeviceStore:        devices,
		AgentTelemetry:     telemetry,
		AgentTargetVersion: "0.1.0",
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/agent/quality", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var summary map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&summary); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	if summary["quality_status"] != "ok" {
		t.Fatalf("quality status = %#v, want ok", summary["quality_status"])
	}
	updateSummary := summary["agent_update_events"].(map[string]any)
	if updateSummary["total"] != float64(1) || updateSummary["installed_events"] != float64(1) {
		t.Fatalf("update summary = %#v", updateSummary)
	}
	statusSummary := summary["agent_status_events"].(map[string]any)
	if statusSummary["total"] != float64(1) || statusSummary["steering_succeeded"] != float64(1) || statusSummary["connect_unsupported"] != float64(1) {
		t.Fatalf("status summary = %#v", statusSummary)
	}
}
