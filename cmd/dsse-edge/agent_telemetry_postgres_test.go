package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	agenttelemetry "github.com/lantern-networks/dsse-core/agenttelemetry"

	"github.com/lantern-networks/dsse-core/model"
)

func TestPostgresAgentTelemetryMigrationMatchesSchemaSQL(t *testing.T) {
	migrationSQL, err := os.ReadFile(filepath.Join("..", "..", "migrations", "019_agent_telemetry.sql"))
	if err != nil {
		t.Fatalf("read agent telemetry migration: %v", err)
	}
	got := normalizePostgresExportTaskSQLContract(string(migrationSQL))
	want := normalizePostgresExportTaskSQLContract(strings.Join(postgresAgentTelemetrySchemaSQL(), "\n"))
	if got != want {
		t.Fatalf("agent telemetry migration drift\n got: %s\nwant: %s", got, want)
	}
}

// ★ THIS TEST IS WHY THE MISSING MIGRATION SURVIVED (2026-08-12, ninth review). It asserted the list was
// exactly ["019"], so 033 — written, committed, and selected by nothing — passed every gate while the INSERT
// that needs it named the composite conflict target. Against a real PostgreSQL every update outcome failed
// with "no unique constraint matching", answered 500, and the whole reporting lane was dead in exactly the
// deployment it was built for.
//
// It now asserts what the store REQUIRES rather than a snapshot of what it had: every migration file that
// touches these tables must be selected. A new one is a test failure until it is listed.
func TestPostgresAgentTelemetryMigrationVersions(t *testing.T) {
	got := postgresAgentTelemetryMigrationVersions()
	if want := []string{"019", "033", "034"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("agent telemetry versions = %#v, want %#v", got, want)
	}
	// And every one of them must exist on disk: a version listed here with no file would fail at startup on a
	// deployment nobody runs locally.
	for _, version := range got {
		matches, err := filepath.Glob(filepath.Join("..", "..", "migrations", version+"_*.sql"))
		if err != nil || len(matches) == 0 {
			t.Fatalf("migration %s is selected and no file matches it (%v)", version, err)
		}
	}
	// The conflict target the INSERT names must be backed by one of them. This is the pairing that broke: the
	// statement was updated and the migration that creates the constraint was never selected.
	stmt, berr := buildPostgresAgentUpdateInsertStatement(model.AgentUpdateEvent{
		ID: "aue_x", TenantID: "t", DeviceID: "d", CurrentAgentVersion: "0.2.7", TargetAgentVersion: "0.2.8",
		ReleaseChannel: "lab", UpdateStatus: "installed", UpdateSource: "control_plane",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}, time.Now())
	if berr != nil {
		t.Fatalf("build the insert: %v", berr)
	}
	target := "(tenant_id, device_id, event_id)"
	if !strings.Contains(stmt.SQL, "ON CONFLICT "+target) {
		t.Fatalf("the insert's conflict target changed: %s", stmt.SQL)
	}
	sqlBytes, rerr := os.ReadFile(filepath.Join("..", "..", "migrations", "033_agent_update_event_scope.sql"))
	if rerr != nil {
		t.Fatalf("read 033: %v", rerr)
	}
	if !strings.Contains(string(sqlBytes), target) {
		t.Fatalf("no selected migration creates the constraint the insert names %s", target)
	}
}

func TestSetupEdgeAgentTelemetryStoreModes(t *testing.T) {
	store, closeFn, err := setupEdgeAgentTelemetryStore(context.Background(), edgeAgentTelemetryStoreConfig{Mode: "memory"})
	if err != nil {
		t.Fatalf("setupEdgeAgentTelemetryStore memory returned error: %v", err)
	}
	if _, ok := store.(*agenttelemetry.Store); !ok {
		t.Fatalf("memory store = %T, want *agenttelemetry.Store", store)
	}
	if closeFn == nil {
		t.Fatal("memory close function is nil")
	}
	if err := closeFn(); err != nil {
		t.Fatalf("memory close returned error: %v", err)
	}

	if _, _, err := setupEdgeAgentTelemetryStore(context.Background(), edgeAgentTelemetryStoreConfig{Mode: "postgres"}); err == nil || !strings.Contains(err.Error(), "agent-telemetry-postgres-dsn") {
		t.Fatalf("postgres without DSN error = %v, want DSN error", err)
	}
	if _, _, err := setupEdgeAgentTelemetryStore(context.Background(), edgeAgentTelemetryStoreConfig{Mode: "bogus"}); err == nil || !strings.Contains(err.Error(), "unsupported agent telemetry store mode") {
		t.Fatalf("unsupported mode error = %v", err)
	}
}

func TestBuildPostgresAgentTelemetryInsertStatementsSerializePayloads(t *testing.T) {
	now := time.Date(2026, 5, 25, 1, 2, 3, 0, time.UTC)
	updateStatement, err := buildPostgresAgentUpdateInsertStatement(model.AgentUpdateEvent{
		ID:                  "aue_sql_001",
		TenantID:            "tenant_lab_001",
		DeviceID:            "dev_sql_001",
		UserID:              "user_lab_001",
		CurrentAgentVersion: "0.1.0",
		TargetAgentVersion:  "0.1.1",
		ReleaseChannel:      "lab",
		UpdateStatus:        "installed",
		UpdateSource:        "control_plane",
		Timestamp:           now.Format(time.RFC3339),
		Metadata:            map[string]any{"steering": "ok"},
	}, now)
	if err != nil {
		t.Fatalf("buildPostgresAgentUpdateInsertStatement returned error: %v", err)
	}
	// ★ DO NOTHING, not DO UPDATE (2026-08-12, seventh review). A retry re-sends the SAME event, so there is
	// nothing to update — and rewriting on conflict is what let a client-chosen event id overwrite an existing
	// row's tenant, device and payload.
	if !strings.Contains(updateStatement.SQL, "INSERT INTO agent_update_events") || !strings.Contains(updateStatement.SQL, "ON CONFLICT (tenant_id, device_id, event_id) DO NOTHING") {
		t.Fatalf("update SQL = %s", updateStatement.SQL)
	}
	if strings.Contains(updateStatement.SQL, "DO UPDATE") {
		t.Fatalf("a conflicting event id can still overwrite the stored row: %s", updateStatement.SQL)
	}
	if got, want := len(updateStatement.Args), 13; got != want {
		t.Fatalf("update args = %#v, want %d", updateStatement.Args, want)
	}
	if !strings.Contains(updateStatement.Args[11].(string), `"id":"aue_sql_001"`) || !strings.Contains(updateStatement.Args[11].(string), `"steering":"ok"`) {
		t.Fatalf("update payload = %s", updateStatement.Args[11])
	}

	statusStatement, err := buildPostgresAgentStatusInsertStatement(model.AgentStatus{
		TenantID:            "tenant_lab_001",
		DeviceID:            "dev_sql_001",
		PolicyBundleID:      "pb_lab_001",
		PolicyBundleVersion: "2026.05.25.001",
		BundleSource:        "remote",
		DeviceTrustLevel:    "managed",
		Status:              "healthy",
		Timestamp:           now.Format(time.RFC3339),
		Metadata:            map[string]any{"crash_count": 0},
	}, now)
	if err != nil {
		t.Fatalf("buildPostgresAgentStatusInsertStatement returned error: %v", err)
	}
	if !strings.Contains(statusStatement.SQL, "INSERT INTO agent_status_events") {
		t.Fatalf("status SQL = %s", statusStatement.SQL)
	}
	if got, want := len(statusStatement.Args), 12; got != want {
		t.Fatalf("status args = %#v, want %d", statusStatement.Args, want)
	}
	if statusID, ok := statusStatement.Args[0].(string); !ok || !strings.HasPrefix(statusID, "ags_") {
		t.Fatalf("status id arg = %#v, want ags_ prefix", statusStatement.Args[0])
	}
	if !strings.Contains(statusStatement.Args[10].(string), `"device_id":"dev_sql_001"`) || !strings.Contains(statusStatement.Args[10].(string), `"crash_count":0`) {
		t.Fatalf("status payload = %s", statusStatement.Args[10])
	}
}

func TestBuildPostgresAgentTelemetryListStatementsScopeTenant(t *testing.T) {
	updateStatement, err := buildPostgresAgentUpdateListByTenantStatement("tenant_lab_001")
	if err != nil {
		t.Fatalf("buildPostgresAgentUpdateListByTenantStatement returned error: %v", err)
	}
	if !strings.Contains(updateStatement.SQL, "WHERE tenant_id = $1") || !strings.Contains(updateStatement.SQL, "ORDER BY occurred_at ASC, event_id ASC") {
		t.Fatalf("update list SQL = %s", updateStatement.SQL)
	}
	if got, want := updateStatement.Args, []any{"tenant_lab_001"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("update list args = %#v, want %#v", got, want)
	}

	statusStatement, err := buildPostgresAgentStatusListByTenantStatement("tenant_lab_001")
	if err != nil {
		t.Fatalf("buildPostgresAgentStatusListByTenantStatement returned error: %v", err)
	}
	if !strings.Contains(statusStatement.SQL, "WHERE tenant_id = $1") || !strings.Contains(statusStatement.SQL, "ORDER BY occurred_at ASC, agent_status_id ASC") {
		t.Fatalf("status list SQL = %s", statusStatement.SQL)
	}
	if got, want := statusStatement.Args, []any{"tenant_lab_001"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("status list args = %#v, want %#v", got, want)
	}
}

func TestBuildPostgresAgentTelemetryStatementsValidateInputs(t *testing.T) {
	now := time.Date(2026, 5, 25, 1, 2, 3, 0, time.UTC)
	update := model.AgentUpdateEvent{
		ID:                  "aue_sql_001",
		TenantID:            "tenant_lab_001",
		DeviceID:            "dev_sql_001",
		CurrentAgentVersion: "0.1.0",
		TargetAgentVersion:  "0.1.1",
		ReleaseChannel:      "lab",
		UpdateStatus:        "installed",
		UpdateSource:        "control_plane",
		Timestamp:           now.Format(time.RFC3339),
	}
	update.TenantID = ""
	if _, err := buildPostgresAgentUpdateInsertStatement(update, now); err == nil {
		t.Fatal("update insert accepted blank tenant")
	}
	status := model.AgentStatus{
		TenantID:            "tenant_lab_001",
		DeviceID:            "dev_sql_001",
		PolicyBundleID:      "pb_lab_001",
		PolicyBundleVersion: "2026.05.25.001",
		BundleSource:        "remote",
		DeviceTrustLevel:    "managed",
		Status:              "healthy",
		Timestamp:           now.Format(time.RFC3339),
	}
	status.TenantID = ""
	if _, err := buildPostgresAgentStatusInsertStatement(status, now); err == nil {
		t.Fatal("status insert accepted blank tenant")
	}
	if _, err := buildPostgresAgentUpdateListByTenantStatement(""); err == nil {
		t.Fatal("update list accepted blank tenant")
	}
	if _, err := buildPostgresAgentStatusListByTenantStatement(""); err == nil {
		t.Fatal("status list accepted blank tenant")
	}
}
