package main

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	usagemeter "github.com/lantern-networks/dsse-core/usagemeter"
)

func TestPostgresUsageMeterMigrationMatchesSchemaSQL(t *testing.T) {
	migrationSQL, err := os.ReadFile(filepath.Join("..", "..", "migrations", "008_usage_meter_records.sql"))
	if err != nil {
		t.Fatalf("read usage meter migration: %v", err)
	}
	got := normalizePostgresExportTaskSQLContract(string(migrationSQL))
	want := normalizePostgresExportTaskSQLContract(strings.Join(postgresUsageMeterSchemaSQL(), "\n"))
	if got != want {
		t.Fatalf("usage meter migration drift\n got: %s\nwant: %s", got, want)
	}
}

func TestPostgresUsageMeterMigrationVersions(t *testing.T) {
	if got, want := postgresUsageMeterMigrationVersions(), []string{"008"}; len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("usage meter versions = %#v, want %#v", got, want)
	}
}

func TestSetupEdgeUsageMeterStoreModes(t *testing.T) {
	store, closeFn, err := setupEdgeUsageMeterStore(context.Background(), edgeUsageMeterStoreConfig{Mode: "memory"})
	if err != nil {
		t.Fatalf("setupEdgeUsageMeterStore memory returned error: %v", err)
	}
	if _, ok := store.(*usagemeter.UsageMeterStore); !ok {
		t.Fatalf("memory store = %T, want *usagemeter.UsageMeterStore", store)
	}
	if closeFn == nil {
		t.Fatal("memory close function is nil")
	}
	if err := closeFn(); err != nil {
		t.Fatalf("memory close returned error: %v", err)
	}

	if _, _, err := setupEdgeUsageMeterStore(context.Background(), edgeUsageMeterStoreConfig{Mode: "postgres"}); err == nil || !strings.Contains(err.Error(), "usage-meter-postgres-dsn") {
		t.Fatalf("postgres without DSN error = %v, want DSN error", err)
	}
	if _, _, err := setupEdgeUsageMeterStore(context.Background(), edgeUsageMeterStoreConfig{Mode: "bogus"}); err == nil || !strings.Contains(err.Error(), "unsupported usage meter store mode") {
		t.Fatalf("unsupported mode error = %v", err)
	}
}

func TestBuildPostgresUsageMeterInsertStatementSerializesPayload(t *testing.T) {
	now := time.Date(2026, 5, 24, 1, 2, 3, 0, time.UTC)
	record := readUsageMeterSampleForTest(t, "usage_meter_nhi_decision_lab.json")
	statement, err := buildPostgresUsageMeterInsertStatement(record, now)
	if err != nil {
		t.Fatalf("buildPostgresUsageMeterInsertStatement returned error: %v", err)
	}
	if !strings.Contains(statement.SQL, "INSERT INTO usage_meter_records") || !strings.Contains(statement.SQL, "ON CONFLICT (tenant_id, usage_meter_id) DO UPDATE") {
		t.Fatalf("statement SQL = %s", statement.SQL)
	}
	if got, want := len(statement.Args), 16; got != want {
		t.Fatalf("args = %#v, want %d args", statement.Args, want)
	}
	if got, want := statement.Args[0], "tenant_lab_001"; got != want {
		t.Fatalf("tenant arg = %v, want %s", got, want)
	}
	if !strings.Contains(statement.Args[14].(string), "\"meter_type\":\"decision\"") || !strings.Contains(statement.Args[14].(string), "\"schema_version\":\"usage_meter.v1\"") {
		t.Fatalf("payload arg = %s", statement.Args[14])
	}
}

func TestBuildPostgresUsageMeterListStatementScopesTenantAndPeriod(t *testing.T) {
	periodStart := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	periodEnd := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	statement, err := buildPostgresUsageMeterListStatement("tenant_lab_001", periodStart, periodEnd)
	if err != nil {
		t.Fatalf("buildPostgresUsageMeterListStatement returned error: %v", err)
	}
	for _, want := range []string{"tenant_id = $1", "period_end > $2", "period_start < $3", "ORDER BY period_start ASC, usage_meter_id ASC"} {
		if !strings.Contains(statement.SQL, want) {
			t.Fatalf("statement SQL = %s, missing %s", statement.SQL, want)
		}
	}
	if got, want := len(statement.Args), 3; got != want {
		t.Fatalf("args = %#v, want %d args", statement.Args, want)
	}
}

func TestBuildPostgresUsageMeterStatementsValidateInputs(t *testing.T) {
	record := readUsageMeterSampleForTest(t, "usage_meter_nhi_decision_lab.json")
	record.TenantID = ""
	if _, err := buildPostgresUsageMeterInsertStatement(record, time.Now()); err == nil {
		t.Fatal("buildPostgresUsageMeterInsertStatement accepted blank tenant")
	}
	if _, err := buildPostgresUsageMeterListStatement("", time.Now(), time.Now().Add(time.Hour)); err == nil {
		t.Fatal("buildPostgresUsageMeterListStatement accepted blank tenant")
	}
	if _, err := buildPostgresUsageMeterListStatement("tenant_lab_001", time.Now(), time.Now().Add(-time.Hour)); err == nil {
		t.Fatal("buildPostgresUsageMeterListStatement accepted unordered period")
	}
}

func TestPostgresUsageMeterRecordBuffersWhenDBUnavailable(t *testing.T) {
	store := &postgresUsageMeterStore{MaxPending: 10}
	record := readUsageMeterSampleForTest(t, "usage_meter_nhi_decision_lab.json")

	store.Record(record)
	summary := store.Summary("tenant_lab_001", time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))

	if got := len(store.pendingSnapshot()); got != 1 {
		t.Fatalf("pending records = %d, want 1", got)
	}
	assertUsageMeterSummary(t, summary.Meters["decision"], "decision", "decision", "sum", 125000, 1)
}

// Review #33: when Postgres is down AND no spool dir is configured, records overflow the bounded memory
// buffer and are dropped — irreversible billing data loss. The drop must be COUNTED (surfaced via
// DroppedRecordCount) so a health check can alarm on the degraded mode, not silently swallowed.
func TestPostgresUsageMeterDropsAreCountedWhenNoSpool(t *testing.T) {
	store := &postgresUsageMeterStore{MaxPending: 3} // no SpoolDir → memory buffer only
	record := readUsageMeterSampleForTest(t, "usage_meter_nhi_decision_lab.json")

	// Buffer more distinct records than the cap; the oldest overflow must be dropped and counted.
	for i := 0; i < 10; i++ {
		r := record
		r.ID = "rec-" + strconv.Itoa(i) // distinct so the dedup path doesn't collapse them
		store.bufferPending(r)
	}
	if got := len(store.pendingSnapshot()); got != 3 {
		t.Fatalf("pending buffer should be capped at 3, got %d", got)
	}
	if dropped := store.DroppedRecordCount(); dropped != 7 {
		t.Fatalf("DroppedRecordCount = %d, want 7 (10 buffered - 3 kept)", dropped)
	}
}

func TestPostgresUsageMeterRecordSpoolsWhenConfigured(t *testing.T) {
	spoolDir := t.TempDir()
	store := &postgresUsageMeterStore{SpoolDir: spoolDir, MaxPending: 10}
	record := readUsageMeterSampleForTest(t, "usage_meter_nhi_decision_lab.json")

	store.Record(record)
	if got := len(store.pending); got != 0 {
		t.Fatalf("memory pending records = %d, want 0 when spool is configured", got)
	}
	if _, err := os.Stat(filepath.Join(spoolDir, postgresUsageMeterSpoolFile)); err != nil {
		t.Fatalf("usage meter spool file is absent: %v", err)
	}
	summary := store.Summary("tenant_lab_001", time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	assertUsageMeterSummary(t, summary.Meters["decision"], "decision", "decision", "sum", 125000, 1)
}

func TestPostgresUsageMeterReplayPendingKeepsSpoolOnFailure(t *testing.T) {
	spoolDir := t.TempDir()
	store := &postgresUsageMeterStore{SpoolDir: spoolDir}
	record := readUsageMeterSampleForTest(t, "usage_meter_nhi_decision_lab.json")

	if err := store.appendSpool(record); err != nil {
		t.Fatalf("appendSpool returned error: %v", err)
	}
	if err := store.ReplayPending(context.Background()); err == nil {
		t.Fatal("ReplayPending succeeded with nil DB")
	}
	if _, err := os.Stat(filepath.Join(spoolDir, postgresUsageMeterSpoolFile)); err != nil {
		t.Fatalf("spool file missing after failed replay: %v", err)
	}
	if got := len(store.pendingSnapshot()); got != 1 {
		t.Fatalf("pending snapshot = %d, want 1", got)
	}
}
