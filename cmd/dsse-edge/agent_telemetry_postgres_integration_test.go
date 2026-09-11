package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"

	_ "github.com/lib/pq"
)

func TestSetupEdgeAgentTelemetryStorePostgresE2E(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open returned error: %v", err)
	}
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("PingContext returned error: %v", err)
	}
	resetPostgresExportTaskQueueTables(t, ctx, db)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		resetPostgresExportTaskQueueTables(t, cleanupCtx, db)
		_ = db.Close()
	})

	store, closeFn, err := setupEdgeAgentTelemetryStore(ctx, edgeAgentTelemetryStoreConfig{
		Mode:          "postgres",
		DSN:           dsn,
		MigrationDir:  filepath.Join("..", "..", "migrations"),
		RunMigrations: true,
	})
	if err != nil {
		t.Fatalf("setupEdgeAgentTelemetryStore returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := closeFn(); err != nil {
			t.Fatalf("close agent telemetry store: %v", err)
		}
	})

	now := time.Date(2026, 5, 25, 1, 2, 3, 0, time.UTC)
	for _, event := range []model.AgentUpdateEvent{
		{
			ID:                  "aue_pg_installed",
			TenantID:            "tenant_lab_001",
			DeviceID:            "dev_pg_001",
			UserID:              "user_lab_001",
			CurrentAgentVersion: "0.1.0",
			TargetAgentVersion:  "0.1.1",
			ReleaseChannel:      "lab",
			UpdateStatus:        "installed",
			UpdateSource:        "control_plane",
			Timestamp:           now.Format(time.RFC3339),
			Metadata:            map[string]any{"source": "postgres-e2e"},
		},
		{
			ID:                  "aue_pg_failed",
			TenantID:            "tenant_lab_001",
			DeviceID:            "dev_pg_002",
			UserID:              "user_lab_002",
			CurrentAgentVersion: "0.1.0",
			TargetAgentVersion:  "0.1.1",
			ReleaseChannel:      "lab",
			UpdateStatus:        "failed",
			UpdateSource:        "mdm",
			Timestamp:           now.Add(time.Second).Format(time.RFC3339),
			Metadata:            map[string]any{"source": "postgres-e2e"},
		},
		{
			ID:                  "aue_pg_other",
			TenantID:            "tenant_other",
			DeviceID:            "dev_other",
			CurrentAgentVersion: "0.1.0",
			TargetAgentVersion:  "0.1.1",
			ReleaseChannel:      "lab",
			UpdateStatus:        "installed",
			UpdateSource:        "control_plane",
			Timestamp:           now.Format(time.RFC3339),
			Metadata:            map[string]any{},
		},
	} {
		if err := store.RecordUpdate(ctx, event); err != nil {
			t.Fatalf("RecordUpdate(%s) returned error: %v", event.ID, err)
		}
	}
	for _, status := range []model.AgentStatus{
		{
			TenantID:            "tenant_lab_001",
			DeviceID:            "dev_pg_001",
			PolicyBundleID:      "pb_lab_001",
			PolicyBundleVersion: "2026.05.25.001",
			BundleSource:        "remote",
			DeviceTrustLevel:    "managed",
			Status:              "healthy",
			Timestamp:           now.Format(time.RFC3339),
			Metadata:            map[string]any{"crash_count": 0, "steering_attempted": 4, "steering_succeeded": 4, "connect_unsupported": 2},
		},
		{
			TenantID:            "tenant_lab_001",
			DeviceID:            "dev_pg_002",
			PolicyBundleID:      "pb_lab_001",
			PolicyBundleVersion: "2026.05.25.001",
			BundleSource:        "cache_fallback",
			DeviceTrustLevel:    "managed",
			Status:              "degraded",
			Timestamp:           now.Add(time.Second).Format(time.RFC3339),
			Metadata:            map[string]any{"crash_count": 1, "steering_attempted": 2, "steering_succeeded": 1, "steering_failed": 1, "connect_unsupported": 1},
		},
		{
			TenantID:            "tenant_other",
			DeviceID:            "dev_other",
			PolicyBundleID:      "pb_other",
			PolicyBundleVersion: "2026.05.25.001",
			BundleSource:        "remote",
			DeviceTrustLevel:    "managed",
			Status:              "healthy",
			Timestamp:           now.Format(time.RFC3339),
			Metadata:            map[string]any{"crash_count": 0, "steering_attempted": 10, "steering_succeeded": 10, "connect_unsupported": 10},
		},
	} {
		if err := store.RecordStatus(ctx, status); err != nil {
			t.Fatalf("RecordStatus(%s) returned error: %v", status.DeviceID, err)
		}
	}

	updateSummary, err := store.UpdateSummary(ctx, "tenant_lab_001")
	if err != nil {
		t.Fatalf("UpdateSummary returned error: %v", err)
	}
	if updateSummary["total"] != 2 || updateSummary["terminal_events"] != 2 || updateSummary["installed_events"] != 1 || updateSummary["update_success_rate"] != float64(0.5) {
		t.Fatalf("update summary = %#v", updateSummary)
	}
	statusSummary, err := store.StatusSummary(ctx, "tenant_lab_001")
	if err != nil {
		t.Fatalf("StatusSummary returned error: %v", err)
	}
	if statusSummary["total"] != 2 || statusSummary["crash_events"] != 1 || statusSummary["steering_attempted"] != 6 || statusSummary["steering_succeeded"] != 5 || statusSummary["steering_failed"] != 1 || statusSummary["connect_unsupported"] != 3 {
		t.Fatalf("status summary = %#v", statusSummary)
	}
	otherUpdates, err := store.UpdateSummary(ctx, "tenant_other")
	if err != nil {
		t.Fatalf("UpdateSummary other returned error: %v", err)
	}
	if otherUpdates["total"] != 1 {
		t.Fatalf("other update summary = %#v, want one event", otherUpdates)
	}
}

func TestAgentRuntimeReportsPersistToPostgresTelemetryE2E(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open returned error: %v", err)
	}
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("PingContext returned error: %v", err)
	}
	resetPostgresExportTaskQueueTables(t, ctx, db)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		resetPostgresExportTaskQueueTables(t, cleanupCtx, db)
		_ = db.Close()
	})

	migrationDir := filepath.Join("..", "..", "migrations")
	deviceStore, closeDeviceStore, err := setupEdgeDeviceStore(ctx, edgeDeviceStoreConfig{
		Mode:          "postgres",
		DSN:           dsn,
		MigrationDir:  migrationDir,
		RunMigrations: true,
	})
	if err != nil {
		t.Fatalf("setupEdgeDeviceStore returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := closeDeviceStore(); err != nil {
			t.Fatalf("close device store: %v", err)
		}
	})
	telemetryStore, closeTelemetryStore, err := setupEdgeAgentTelemetryStore(ctx, edgeAgentTelemetryStoreConfig{
		Mode:          "postgres",
		DSN:           dsn,
		MigrationDir:  migrationDir,
		RunMigrations: true,
	})
	if err != nil {
		t.Fatalf("setupEdgeAgentTelemetryStore returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := closeTelemetryStore(); err != nil {
			t.Fatalf("close agent telemetry store: %v", err)
		}
	})
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	evaluator := testEvaluator()
	now := time.Date(2026, 5, 25, 1, 2, 3, 0, time.UTC)
	if _, err := deviceStore.Register(model.Device{
		ID:                  "dev_pg_agent_runtime",
		TenantID:            evaluator.PolicyBundle.TenantID,
		UserID:              "user_lab_001",
		Hostname:            "pg-agent-runtime",
		OS:                  "macos",
		AgentVersion:        "0.1.0",
		DeviceTrustLevel:    "managed",
		Status:              "registered",
		RegisteredAt:        now.Format(time.RFC3339),
		LastSeenAt:          now.Format(time.RFC3339),
		PolicyBundleID:      evaluator.PolicyBundle.ID,
		PolicyBundleVersion: evaluator.PolicyBundle.Version,
	}, evaluator.PolicyBundle, now); err != nil {
		t.Fatalf("Register returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:           evaluator,
		Writer:              writer,
		DeviceStore:         deviceStore,
		AgentTelemetry:      telemetryStore,
		AgentTargetVersion:  "0.1.1",
		AgentReleaseChannel: "pilot",
	})

	updateReq := httptest.NewRequest(http.MethodPost, "/devices/dev_pg_agent_runtime/agent-updates", strings.NewReader(`{}`))
	updateRec := httptest.NewRecorder()
	handler.ServeHTTP(updateRec, updateReq)
	if updateRec.Code != http.StatusAccepted {
		t.Fatalf("agent update status = %d, want %d, body=%s", updateRec.Code, http.StatusAccepted, updateRec.Body.String())
	}
	var update model.AgentUpdateEvent
	if err := json.NewDecoder(updateRec.Body).Decode(&update); err != nil {
		t.Fatalf("decode update response: %v", err)
	}
	if update.UpdateStatus != "available" || update.ReleaseChannel != "pilot" || update.TargetAgentVersion != "0.1.1" {
		t.Fatalf("update response = %#v, want normalized defaults", update)
	}
	statusReq := httptest.NewRequest(http.MethodPost, "/devices/dev_pg_agent_runtime/agent-status", strings.NewReader(`{}`))
	statusRec := httptest.NewRecorder()
	handler.ServeHTTP(statusRec, statusReq)
	if statusRec.Code != http.StatusAccepted {
		t.Fatalf("agent status status = %d, want %d, body=%s", statusRec.Code, http.StatusAccepted, statusRec.Body.String())
	}

	updateSummary, err := telemetryStore.UpdateSummary(ctx, evaluator.PolicyBundle.TenantID)
	if err != nil {
		t.Fatalf("UpdateSummary returned error: %v", err)
	}
	if updateSummary["total"] != 1 || updateSummary["status_counts"].(map[string]int)["available"] != 1 {
		t.Fatalf("update summary = %#v", updateSummary)
	}
	statusSummary, err := telemetryStore.StatusSummary(ctx, evaluator.PolicyBundle.TenantID)
	if err != nil {
		t.Fatalf("StatusSummary returned error: %v", err)
	}
	if statusSummary["total"] != 1 || statusSummary["status_counts"].(map[string]int)["healthy"] != 1 {
		t.Fatalf("status summary = %#v", statusSummary)
	}
}
