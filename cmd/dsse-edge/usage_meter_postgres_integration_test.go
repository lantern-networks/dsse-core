package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"

	_ "github.com/lib/pq"
)

func TestSetupEdgeUsageMeterStorePostgresE2E(t *testing.T) {
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

	store, closeFn, err := setupEdgeUsageMeterStore(ctx, edgeUsageMeterStoreConfig{
		Mode:          "postgres",
		DSN:           dsn,
		MigrationDir:  filepath.Join("..", "..", "migrations"),
		RunMigrations: true,
	})
	if err != nil {
		t.Fatalf("setupEdgeUsageMeterStore returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := closeFn(); err != nil {
			t.Fatalf("close usage meter store: %v", err)
		}
	})

	record := readUsageMeterSampleForTest(t, "usage_meter_nhi_decision_lab.json")
	store.Record(record)

	periodStart := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	periodEnd := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	summary := store.Summary("tenant_lab_001", periodStart, periodEnd)
	assertUsageMeterSummary(t, summary.Meters["decision"], "decision", "decision", "sum", 125000, 1)

	var count int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM usage_meter_records WHERE tenant_id = $1 AND usage_meter_id = $2", record.TenantID, record.ID).Scan(&count); err != nil {
		t.Fatalf("query usage_meter_records count: %v", err)
	}
	if count != 1 {
		t.Fatalf("usage_meter_records count = %d, want 1", count)
	}
}

func TestDecisionEvaluateRecordsUsageMeterPostgresE2E(t *testing.T) {
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

	store, closeFn, err := setupEdgeUsageMeterStore(ctx, edgeUsageMeterStoreConfig{
		Mode:          "postgres",
		DSN:           dsn,
		MigrationDir:  filepath.Join("..", "..", "migrations"),
		RunMigrations: true,
	})
	if err != nil {
		t.Fatalf("setupEdgeUsageMeterStore returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := closeFn(); err != nil {
			t.Fatalf("close usage meter store: %v", err)
		}
	})
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	tenantCAs, connectorTLS := postgresTestConnectorIdentity(t, "tenant_lab_001", "conn_usage")
	handler := newServerWithConfig(serverConfig{
		TenantCARegistry: tenantCAs,
		Evaluator:        testEvaluator(),
		Writer:           writer,
		UsageMeters:      store,
		ConnectorSecret:  defaultConnectorSecret,
		LabMode:          boolPtr(false),
	})
	body := []byte(`{
		"tenant_id":"tenant_lab_001",
		"user_id":"user_lab_001",
		"subject_user_id":"user_lab_001",
		"actor_type":"human",
		"application_id":"app_dummy_https",
		"application_sensitivity":"medium",
		"source_ip":"127.0.0.1",
		"source_port":50100,
		"destination":"dummy-private-app.local",
		"destination_ip":"127.0.0.1",
		"destination_port":8443,
		"protocol":"tcp",
		"fqdn":"dummy-private-app.local",
		"sni":"dummy-private-app.local",
		"service_family":"https",
		"connection_initiator":"client",
		"source_role":"managed_endpoint",
		"destination_role":"private_app"
	}`)
	req := httptest.NewRequest(http.MethodPost, "/decisions/evaluate", bytes.NewReader(body))
	req.TLS = connectorTLS
	req.Header.Set(connectorIDHeader, "conn_usage")
	req.Header.Set("content-type", "application/json")
	req.Header.Set(connectorSecretHeader, defaultConnectorSecret)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var dec model.AccessDecision
	if err := json.NewDecoder(rec.Body).Decode(&dec); err != nil {
		t.Fatalf("decode decision response: %v", err)
	}
	if dec.Decision != "allow" {
		t.Fatalf("decision = %q, want allow", dec.Decision)
	}
	var count int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM usage_meter_records WHERE tenant_id = $1 AND meter_type = 'decision'", dec.TenantID).Scan(&count); err != nil {
		t.Fatalf("query usage_meter_records decision count: %v", err)
	}
	if count != 1 {
		t.Fatalf("usage decision meter rows = %d, want 1", count)
	}
}

func TestPostgresUsageMeterSpoolReplayE2E(t *testing.T) {
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
	applyPostgresExportTaskQueueMigration(t, ctx, db)

	spoolDir := t.TempDir()
	spooled := readUsageMeterSampleForTest(t, "usage_meter_nhi_decision_lab.json")
	spooled.ID = "usage_spooled_replay_001"
	unavailableStore := &postgresUsageMeterStore{SpoolDir: spoolDir}
	unavailableStore.Record(spooled)
	if _, err := os.Stat(filepath.Join(spoolDir, postgresUsageMeterSpoolFile)); err != nil {
		t.Fatalf("spool file is absent after failed record: %v", err)
	}

	replayStore := &postgresUsageMeterStore{DB: db, SpoolDir: spoolDir}
	current := spooled
	current.ID = "usage_current_after_replay_001"
	current.Quantity = 1
	replayStore.Record(current)

	var count int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM usage_meter_records WHERE tenant_id = $1 AND usage_meter_id IN ($2, $3)", spooled.TenantID, spooled.ID, current.ID).Scan(&count); err != nil {
		t.Fatalf("query replayed usage_meter_records count: %v", err)
	}
	if count != 2 {
		t.Fatalf("replayed usage records = %d, want 2", count)
	}
	if _, err := os.Stat(filepath.Join(spoolDir, postgresUsageMeterSpoolFile)); !os.IsNotExist(err) {
		t.Fatalf("spool file still exists after replay: %v", err)
	}
}

func TestPostgresUsageMeterSpoolReplayOnSummaryE2E(t *testing.T) {
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
	applyPostgresExportTaskQueueMigration(t, ctx, db)

	spoolDir := t.TempDir()
	spooled := readUsageMeterSampleForTest(t, "usage_meter_nhi_decision_lab.json")
	spooled.ID = "usage_spooled_summary_replay_001"
	unavailableStore := &postgresUsageMeterStore{SpoolDir: spoolDir}
	unavailableStore.Record(spooled)
	if _, err := os.Stat(filepath.Join(spoolDir, postgresUsageMeterSpoolFile)); err != nil {
		t.Fatalf("spool file is absent after failed record: %v", err)
	}

	replayStore := &postgresUsageMeterStore{DB: db, SpoolDir: spoolDir}
	summary := replayStore.Summary(spooled.TenantID, spooled.PeriodStart, spooled.PeriodEnd)
	assertUsageMeterSummary(t, summary.Meters["decision"], "decision", "decision", "sum", spooled.Quantity, 1)

	var count int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM usage_meter_records WHERE tenant_id = $1 AND usage_meter_id = $2", spooled.TenantID, spooled.ID).Scan(&count); err != nil {
		t.Fatalf("query replayed usage meter summary count: %v", err)
	}
	if count != 1 {
		t.Fatalf("summary replayed records = %d, want 1", count)
	}
	if _, err := os.Stat(filepath.Join(spoolDir, postgresUsageMeterSpoolFile)); !os.IsNotExist(err) {
		t.Fatalf("spool file still exists after summary replay: %v", err)
	}
}

func TestSetupEdgeUsageMeterStoreReplaysSpoolOnStartupE2E(t *testing.T) {
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
	applyPostgresExportTaskQueueMigration(t, ctx, db)

	spoolDir := t.TempDir()
	spooled := readUsageMeterSampleForTest(t, "usage_meter_nhi_decision_lab.json")
	spooled.ID = "usage_spooled_startup_replay_001"
	unavailableStore := &postgresUsageMeterStore{SpoolDir: spoolDir}
	unavailableStore.Record(spooled)
	if _, err := os.Stat(filepath.Join(spoolDir, postgresUsageMeterSpoolFile)); err != nil {
		t.Fatalf("spool file is absent after failed record: %v", err)
	}

	store, closeFn, err := setupEdgeUsageMeterStore(ctx, edgeUsageMeterStoreConfig{
		Mode:     "postgres",
		DSN:      dsn,
		SpoolDir: spoolDir,
	})
	if err != nil {
		t.Fatalf("setupEdgeUsageMeterStore returned error: %v", err)
	}
	t.Cleanup(func() { _ = closeFn() })
	summary := store.Summary(spooled.TenantID, spooled.PeriodStart, spooled.PeriodEnd)
	assertUsageMeterSummary(t, summary.Meters["decision"], "decision", "decision", "sum", spooled.Quantity, 1)

	var count int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM usage_meter_records WHERE tenant_id = $1 AND usage_meter_id = $2", spooled.TenantID, spooled.ID).Scan(&count); err != nil {
		t.Fatalf("query startup replayed usage meter count: %v", err)
	}
	if count != 1 {
		t.Fatalf("startup replayed records = %d, want 1", count)
	}
	if _, err := os.Stat(filepath.Join(spoolDir, postgresUsageMeterSpoolFile)); !os.IsNotExist(err) {
		t.Fatalf("spool file still exists after startup replay: %v", err)
	}
}
