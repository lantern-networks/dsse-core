package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/hotstore"
	"github.com/lantern-networks/dsse-core/logs"
	migrationstore "github.com/lantern-networks/dsse-core/migrations"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/objectstore"

	_ "github.com/lib/pq"
)

func TestPostgresExportTaskQueueWorkerE2E(t *testing.T) {
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

	adapter, document, _ := newPostgresExportTaskQueueAdapterFixture(t)
	adapter.DB = postgresExportTaskSQLDB{DB: db}
	postgresJobStore := attachPostgresAdminExportJobStoreToAdapter(t, ctx, db, &adapter, document)
	worker := postgresQueuedAdminExportWorker{Queue: adapter, Timeout: 5 * time.Second}
	if err := adapter.Enqueue(ctx, adminExportQueuedTask{Document: document}); err != nil {
		t.Fatalf("Enqueue returned error: %v", err)
	}

	processed, err := worker.runOne(ctx, time.Date(2026, 5, 23, 1, 20, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("runOne returned error: %v", err)
	}
	if !processed {
		t.Fatalf("runOne processed = false")
	}
	job, ok := postgresJobStore.Get(document.ExportJobID)
	if !ok || job.Status != "completed" {
		t.Fatalf("job = %#v, ok=%v, want completed", job, ok)
	}
	if count := countPostgresExportTaskRows(t, ctx, db, postgresExportTaskRowsActiveTable); count != 0 {
		t.Fatalf("active queue rows = %d, want 0", count)
	}
	if count := countPostgresExportTaskRows(t, ctx, db, postgresExportTaskRowsDeadLetterTable); count != 0 {
		t.Fatalf("dead letter rows = %d, want 0", count)
	}
}

func TestPostgresExportTaskQueueWorkerExtendsLeaseE2E(t *testing.T) {
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

	adapter, document, _ := newPostgresExportTaskQueueAdapterFixture(t)
	recordingDB := &recordingPostgresExportTaskSQLDB{DB: db}
	adapter.DB = recordingDB
	adapter.LeaseDuration = 40 * time.Millisecond
	attachPostgresAdminExportJobStoreToAdapter(t, ctx, db, &adapter, document)
	adapter.Resolver.HotStore = delayedPostgresQueueHotStore{delay: 80 * time.Millisecond}
	worker := postgresQueuedAdminExportWorker{
		Queue:                  adapter,
		Timeout:                5 * time.Second,
		LeaseExtensionInterval: 5 * time.Millisecond,
	}
	if err := adapter.Enqueue(ctx, adminExportQueuedTask{Document: document}); err != nil {
		t.Fatalf("Enqueue returned error: %v", err)
	}

	processed, err := worker.runOne(ctx, time.Date(2026, 5, 23, 1, 25, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("runOne returned error: %v", err)
	}
	if !processed {
		t.Fatalf("runOne processed = false")
	}
	if count := recordingDB.countQueriesContaining("lease_owner = $3"); count == 0 {
		t.Fatalf("ExtendLease query count = %d, want at least one", count)
	}
	if count := countPostgresExportTaskRows(t, ctx, db, postgresExportTaskRowsActiveTable); count != 0 {
		t.Fatalf("active queue rows = %d, want 0", count)
	}
}

func TestPostgresExportTaskQueueWorkerWithPostgresHotStoreE2E(t *testing.T) {
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

	adapter, document, _ := newPostgresExportTaskQueueAdapterFixture(t)
	adapter.DB = postgresExportTaskSQLDB{DB: db}
	postgresJobStore := attachPostgresAdminExportJobStoreToAdapter(t, ctx, db, &adapter, document)
	adapter.Resolver.HotStore = hotstore.NewPostgresStore(db)
	insertPostgresHotEventForEdgeTest(t, ctx, db, "tenant_lab_001", "access", "evt_worker_hotstore_001", map[string]any{
		"tenant_id":          "tenant_lab_001",
		"stream":             "access",
		"event_id":           "evt_worker_hotstore_001",
		"access_decision_id": "dec_worker_hotstore_001",
		"decision":           "allow",
		"application_id":     "app_dummy_https",
	})
	worker := postgresQueuedAdminExportWorker{Queue: adapter, Timeout: 5 * time.Second}
	if err := adapter.Enqueue(ctx, adminExportQueuedTask{Document: document}); err != nil {
		t.Fatalf("Enqueue returned error: %v", err)
	}

	processed, err := worker.runOne(ctx, time.Date(2026, 5, 23, 1, 35, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("runOne returned error: %v", err)
	}
	if !processed {
		t.Fatalf("runOne processed = false")
	}
	job, ok := postgresJobStore.Get(document.ExportJobID)
	if !ok || job.Status != "completed" || job.RowCount != 1 {
		t.Fatalf("job = %#v, ok=%v, want completed row_count=1", job, ok)
	}
}

func TestEdgePostgresHotStoreIngestFromWriterE2E(t *testing.T) {
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

	// Upgrade an existing pre-region table through production component setup.
	migrations, err := migrationstore.LoadDir(filepath.Join("..", "..", "migrations"))
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := selectPostgresComponentMigrations(migrations, "legacy hot store", postgresMigrationHotEvents)
	if err != nil {
		t.Fatal(err)
	}
	if err := migrationstore.Apply(ctx, db, legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO hot_events(tenant_id,stream,event_id,occurred_at,payload) VALUES('tenant_legacy','access','old-event',now(),'{}')`); err != nil {
		t.Fatal(err)
	}

	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	store, closeStore, err := setupEdgeHotStore(ctx, edgeHotStoreConfig{
		Mode:          "postgres",
		DSN:           dsn,
		MigrationDir:  filepath.Join("..", "..", "migrations"),
		RunMigrations: true,
		Writer:        writer,
	})
	if err != nil {
		t.Fatalf("setupEdgeHotStore returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := closeStore(); err != nil {
			t.Fatalf("close edge hot store: %v", err)
		}
	})

	var legacyRegion string
	if err := db.QueryRowContext(ctx, `SELECT edge_region_id FROM hot_events WHERE tenant_id='tenant_legacy' AND event_id='old-event'`).Scan(&legacyRegion); err != nil || legacyRegion != "" {
		t.Fatalf("legacy row upgrade: region=%q err=%v", legacyRegion, err)
	}

	if err := writer.Append("access.log.jsonl", map[string]any{
		"id":                 "alog_edge_ingest_001",
		"edge_region_id":     "region-test",
		"tenant_id":          "tenant_lab_001",
		"timestamp":          "2026-05-23T04:00:00Z",
		"decision":           "allow",
		"application_id":     "app_dummy_https",
		"access_decision_id": "dec_edge_ingest_001",
	}); err != nil {
		t.Fatalf("Append returned error: %v", err)
	}
	if err := writer.Append("audit.log.jsonl", map[string]any{
		"id":        "audit_edge_ingest_other_tenant",
		"tenant_id": "tenant_other_001",
		"timestamp": "2026-05-23T04:00:00Z",
		"event":     "ignored_by_tenant_scope",
	}); err != nil {
		t.Fatalf("Append other tenant audit returned error: %v", err)
	}

	result, err := store.Search(ctx, hotstore.SearchQuery{
		TenantID: "tenant_lab_001",
		Stream:   "access",
		Filters:  map[string]string{"decision": "allow", "edge_region_id": "region-test"},
		Limit:    10,
	})
	if err != nil {
		t.Fatalf("Search returned error: %v", err)
	}
	if result.TotalMatches != 1 || len(result.Rows) != 1 || result.Rows[0]["id"] != "alog_edge_ingest_001" {
		t.Fatalf("search result = %#v", result)
	}
	related, err := store.RelatedByAccessDecisionID(ctx, hotstore.RelatedLogQuery{
		TenantID:         "tenant_lab_001",
		AccessDecisionID: "dec_edge_ingest_001",
	})
	if err != nil {
		t.Fatalf("RelatedByAccessDecisionID returned error: %v", err)
	}
	if related.TotalRows != 1 || len(related.RowsByStream["access"]) != 1 {
		t.Fatalf("related = %#v", related)
	}
	// Region coverage ignores only region/pagination, retaining all other scope.
	from, to := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	for _, row := range []struct {
		id, tenant, stream, region, decision, text string
		at                                         time.Time
	}{
		{"match", "tenant_coverage", "access", "", "deny", "needle", time.Now()},
		{"foreign", "foreign", "access", "", "deny", "needle", time.Now()},
		{"stream", "tenant_coverage", "audit", "", "deny", "needle", time.Now()},
		{"known", "tenant_coverage", "access", "region-test", "deny", "needle", time.Now()},
		{"allow", "tenant_coverage", "access", "", "allow", "needle", time.Now()},
		{"text", "tenant_coverage", "access", "", "deny", "other", time.Now()},
		{"old", "tenant_coverage", "access", "", "deny", "needle", from.Add(-time.Hour)},
	} {
		payload, _ := json.Marshal(map[string]string{"decision": row.decision, "message": row.text})
		if _, err := db.ExecContext(ctx, `INSERT INTO hot_events(tenant_id,stream,event_id,edge_region_id,occurred_at,payload) VALUES($1,$2,$3,$4,$5,$6)`, row.tenant, row.stream, row.id, row.region, row.at, payload); err != nil {
			t.Fatal(err)
		}
	}
	counter, ok := store.(hotstore.UnknownRegionCounter)
	if !ok {
		t.Fatal("PostgreSQL region counter absent")
	}
	query := hotstore.SearchQuery{TenantID: "tenant_coverage", Stream: "access", Filters: map[string]string{"edge_region_id": "region-test", "decision": "deny", "tenant_id": "foreign"}, Text: "needle", From: &from, To: &to, Limit: 1, Cursor: "ignored-by-count"}
	if n, err := counter.CountUnknownRegion(ctx, query); err != nil || n != 1 {
		t.Fatalf("unknown count=%d err=%v", n, err)
	}
	query.TenantID = "empty-tenant"
	if n, err := counter.CountUnknownRegion(ctx, query); err != nil || n != 0 {
		t.Fatalf("empty count=%d err=%v", n, err)
	}

}

func TestPostgresAdminExportJobStoreE2E(t *testing.T) {
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

	now := time.Date(2026, 5, 23, 2, 15, 0, 0, time.UTC)
	req := adminExportJobRequest{Stream: "access", Format: "ndjson", From: "2026-05-23T00:00:00Z", To: "2026-05-23T01:00:00Z", Limit: 10}
	job := newAdminExportJobStore().Create(req, "tenant_lab_001", "admin_lab_001", now)
	store := postgresAdminExportJobStore{DB: db}
	if err := store.Upsert(ctx, job, now); err != nil {
		t.Fatalf("Upsert returned error: %v", err)
	}
	got, ok, err := store.GetByTenant(ctx, job.TenantID, job.ID)
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if !ok || got.ID != job.ID || got.TenantID != job.TenantID || got.Status != "queued" {
		t.Fatalf("got = %#v, ok=%v", got, ok)
	}
	jobs, err := store.ListByTenant(ctx, job.TenantID, 20)
	if err != nil {
		t.Fatalf("List returned error: %v", err)
	}
	if len(jobs) != 1 || jobs[0].ID != job.ID {
		t.Fatalf("jobs = %#v", jobs)
	}
	running, err := store.MarkRunning(job.ID, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("MarkRunning returned error: %v", err)
	}
	if running.Status != "running" || running.StartedAt == nil {
		t.Fatalf("running = %#v", running)
	}
	if _, err := store.MarkProgress(job.ID, 7, "exporting", now.Add(2*time.Minute)); err != nil {
		t.Fatalf("MarkProgress returned error: %v", err)
	}
	completed, err := store.MarkCompleted(job.ID, 7, 10, true, "evidence://tenant/tenant_lab_001/exports/export.ndjson.gz", "sha256:test", now.Add(3*time.Minute))
	if err != nil {
		t.Fatalf("MarkCompleted returned error: %v", err)
	}
	if completed.Status != "completed" || completed.RowCount != 7 || completed.ObjectRef == nil || completed.PayloadChecksum == nil {
		t.Fatalf("completed = %#v", completed)
	}
	runtimeJob, ok := store.Get(job.ID)
	if !ok || runtimeJob.Status != "completed" || runtimeJob.RowCount != 7 {
		t.Fatalf("runtime job = %#v, ok=%v", runtimeJob, ok)
	}
}

func TestAdminExportJobAPIWithPostgresJobStoreE2E(t *testing.T) {
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

	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	if err := writer.Append("access.log.jsonl", map[string]any{
		"id":                 "alog_pg_job_api_001",
		"tenant_id":          "tenant_lab_001",
		"timestamp":          "2026-05-23T04:15:00Z",
		"decision":           "allow",
		"access_decision_id": "dec_pg_job_api_001",
	}); err != nil {
		t.Fatalf("Append returned error: %v", err)
	}
	objectStore, err := objectstore.NewLocalStore(writer.Dir())
	if err != nil {
		t.Fatalf("NewLocalStore returned error: %v", err)
	}
	postgresJobStore := postgresAdminExportJobStore{DB: db}
	handler := newServerWithConfig(serverConfig{
		Evaluator:         testEvaluator(),
		Writer:            writer,
		ExportObjectStore: objectStore,
		HotStore:          hotstore.NewJSONLStore(writer, adminLogStreamFilenameMap()),
		AdminExportJobs:   postgresJobStore,
	})

	body := bytes.NewBufferString(`{"stream":"access","format":"ndjson","from":"2026-05-23T00:00:00Z","to":"2026-05-23T05:00:00Z","limit":10}`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/export-jobs", body)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /admin/export-jobs status=%d body=%s", rec.Code, rec.Body.String())
	}
	var job adminExportJob
	if err := json.Unmarshal(rec.Body.Bytes(), &job); err != nil {
		t.Fatalf("decode export job response: %v", err)
	}
	if job.Status != "completed" || job.RowCount != 1 {
		t.Fatalf("job response = %#v, want completed row_count=1", job)
	}
	persisted, ok, err := postgresJobStore.GetByTenant(ctx, "tenant_lab_001", job.ID)
	if err != nil {
		t.Fatalf("GetByTenant returned error: %v", err)
	}
	if !ok || persisted.Status != "completed" || persisted.RowCount != 1 {
		t.Fatalf("persisted job = %#v ok=%v", persisted, ok)
	}

	listRec := httptest.NewRecorder()
	listReq := httptest.NewRequest(http.MethodGet, "/admin/export-jobs", nil)
	handler.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("GET /admin/export-jobs status=%d body=%s", listRec.Code, listRec.Body.String())
	}
	if !strings.Contains(listRec.Body.String(), job.ID) {
		t.Fatalf("list response %s does not include job %s", listRec.Body.String(), job.ID)
	}
}

func TestAdminExportJobAPIEnqueuesPostgresQueueTaskE2E(t *testing.T) {
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

	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	objectStore, err := objectstore.NewLocalStore(writer.Dir())
	if err != nil {
		t.Fatalf("NewLocalStore returned error: %v", err)
	}
	postgresJobStore := postgresAdminExportJobStore{DB: db}
	handler := newServerWithConfig(serverConfig{
		Evaluator:         testEvaluator(),
		Writer:            writer,
		ExportObjectStore: objectStore,
		HotStore:          hotstore.NewJSONLStore(writer, adminLogStreamFilenameMap()),
		AdminExportJobs:   postgresJobStore,
		AdminExportWorker: postgresQueueAdminExportWorker{
			Queue: postgresExportTaskQueueAdapter{DB: postgresExportTaskSQLDB{DB: db}},
			DB:    db,
		},
	})

	body := bytes.NewBufferString(`{"stream":"access","format":"ndjson","from":"2026-05-23T00:00:00Z","to":"2026-05-23T05:00:00Z","limit":10}`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/export-jobs", body)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /admin/export-jobs status=%d body=%s", rec.Code, rec.Body.String())
	}
	var job adminExportJob
	if err := json.Unmarshal(rec.Body.Bytes(), &job); err != nil {
		t.Fatalf("decode export job response: %v", err)
	}
	if job.Status != "queued" {
		t.Fatalf("job response = %#v, want queued", job)
	}
	persisted, ok, err := postgresJobStore.GetByTenant(ctx, "tenant_lab_001", job.ID)
	if err != nil {
		t.Fatalf("GetByTenant returned error: %v", err)
	}
	if !ok || persisted.Status != "queued" {
		t.Fatalf("persisted job = %#v ok=%v, want queued", persisted, ok)
	}
	if count := countPostgresExportTaskRows(t, ctx, db, postgresExportTaskRowsActiveTable); count != 1 {
		t.Fatalf("active queue rows = %d, want 1", count)
	}
	if count := countPostgresAdminAuditOutboxRows(t, ctx, db, "tenant_lab_001"); count != 2 {
		t.Fatalf("admin audit outbox rows = %d, want 2", count)
	}
	eventTypes := postgresAdminAuditOutboxEventTypes(t, ctx, db, "tenant_lab_001")
	if got, want := strings.Join(eventTypes, ","), "admin_export_requested,admin_export_task_enqueued"; got != want {
		t.Fatalf("admin audit outbox event types = %s, want %s", got, want)
	}
}

func TestAdminExportJobAPIEnqueuesPostgresQueueTaskWithoutDirectAuditJSONLE2E(t *testing.T) {
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

	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	objectStore, err := objectstore.NewLocalStore(writer.Dir())
	if err != nil {
		t.Fatalf("NewLocalStore returned error: %v", err)
	}
	postgresJobStore := postgresAdminExportJobStore{DB: db}
	handler := newServerWithConfig(serverConfig{
		Evaluator:         testEvaluator(),
		Writer:            writer,
		ExportObjectStore: objectStore,
		HotStore:          hotstore.NewJSONLStore(writer, adminLogStreamFilenameMap()),
		AdminExportJobs:   postgresJobStore,
		AdminExportWorker: postgresQueueAdminExportWorker{
			Queue:                   postgresExportTaskQueueAdapter{DB: postgresExportTaskSQLDB{DB: db}},
			DB:                      db,
			DisableDirectAuditJSONL: true,
		},
	})

	body := bytes.NewBufferString(`{"stream":"access","format":"ndjson","from":"2026-05-23T00:00:00Z","to":"2026-05-23T05:00:00Z","limit":10}`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/export-jobs", body)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /admin/export-jobs status=%d body=%s", rec.Code, rec.Body.String())
	}
	var job adminExportJob
	if err := json.Unmarshal(rec.Body.Bytes(), &job); err != nil {
		t.Fatalf("decode export job response: %v", err)
	}
	if job.Status != "queued" {
		t.Fatalf("job response = %#v, want queued", job)
	}
	if count := countPostgresExportTaskRows(t, ctx, db, postgresExportTaskRowsActiveTable); count != 1 {
		t.Fatalf("active queue rows = %d, want 1", count)
	}
	if count := countPostgresAdminAuditOutboxRows(t, ctx, db, "tenant_lab_001"); count != 2 {
		t.Fatalf("admin audit outbox rows = %d, want 2", count)
	}
	auditRows, err := writer.ReadJSONL("audit.log.jsonl")
	if err != nil {
		t.Fatalf("ReadJSONL returned error: %v", err)
	}
	// The worker suppresses its domain JSONL events; the shared HTTP audit remains mandatory.
	if len(auditRows) != 1 || auditRows[0]["event_type"] != "admin_config_change" || auditRows[0]["result"] != "success" {
		t.Fatalf("expected one shared HTTP audit, got %#v", auditRows)
	}
	metadata, ok := auditRows[0]["metadata"].(map[string]any)
	if !ok || metadata["path"] != "/admin/export-jobs" || metadata["status_code"] != float64(202) {
		t.Fatalf("HTTP audit metadata=%#v", metadata)
	}
}

func TestRunPostgresExportWorkerModeE2E(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	setupCtx, setupCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer setupCancel()

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open returned error: %v", err)
	}
	if err := db.PingContext(setupCtx); err != nil {
		t.Fatalf("PingContext returned error: %v", err)
	}
	resetPostgresExportTaskQueueTables(t, setupCtx, db)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		resetPostgresExportTaskQueueTables(t, cleanupCtx, db)
		_ = db.Close()
	})

	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	objectStore, err := objectstore.NewLocalStore(logDir)
	if err != nil {
		t.Fatalf("NewLocalStore returned error: %v", err)
	}
	runCtx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(500 * time.Millisecond)
		cancel()
	}()
	err = runPostgresExportWorker(runCtx, postgresExportWorkerConfig{
		DSN:           dsn,
		MigrationDir:  filepath.Join("..", "..", "migrations"),
		RunMigrations: true,
		SchemaDir:     filepath.Join("..", "..", "schemas"),
		TenantID:      "tenant_lab_001",
		WorkerID:      "worker_mode_e2e_001",
		PollInterval:  10 * time.Millisecond,
		Writer:        writer,
		ObjectStore:   objectStore,
		Evaluator:     testEvaluator(),
	})
	if err != nil {
		t.Fatalf("runPostgresExportWorker returned error: %v", err)
	}
}

func TestPostgresAdminAuditOutboxPublisherE2E(t *testing.T) {
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

	now := time.Date(2026, 5, 23, 2, 20, 0, 0, time.UTC)
	audit := model.AuditLog{
		ID:        "audit_outbox_e2e_001",
		TenantID:  "tenant_lab_001",
		EventType: "admin_export_requested",
		Timestamp: now.Format(time.RFC3339),
		Metadata:  map[string]any{"export_job_id": "exp_outbox_e2e_001"},
	}
	statement, err := buildPostgresAdminAuditOutboxInsertStatement(audit, now)
	if err != nil {
		t.Fatalf("build outbox insert statement returned error: %v", err)
	}
	if _, err := db.ExecContext(ctx, statement.SQL, statement.Args...); err != nil {
		t.Fatalf("insert outbox row returned error: %v", err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	publisher := postgresAdminAuditOutboxPublisher{
		DB:          db,
		TenantID:    "tenant_lab_001",
		PublisherID: "publisher_e2e_001",
		Writer:      writer,
		BatchSize:   10,
	}
	published, err := publisher.PublishOnce(ctx, now.Add(time.Second))
	if err != nil {
		t.Fatalf("PublishOnce returned error: %v", err)
	}
	if published != 1 {
		t.Fatalf("published = %d, want 1", published)
	}
	rows, err := writer.ReadJSONL("audit.log.jsonl")
	if err != nil {
		t.Fatalf("ReadJSONL returned error: %v", err)
	}
	if len(rows) != 1 || rows[0]["event_type"] != "admin_export_requested" {
		t.Fatalf("audit rows = %#v", rows)
	}
	var status string
	var publishAttempt int
	if err := db.QueryRowContext(ctx, "SELECT status, publish_attempt FROM admin_audit_outbox WHERE tenant_id = $1 AND outbox_id = $2", "tenant_lab_001", "audit_outbox_e2e_001").Scan(&status, &publishAttempt); err != nil {
		t.Fatalf("query outbox row returned error: %v", err)
	}
	if status != "published" || publishAttempt != 1 {
		t.Fatalf("outbox status=%s publish_attempt=%d, want published/1", status, publishAttempt)
	}
}

func TestRunPostgresAuditOutboxPublisherModeE2E(t *testing.T) {
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

	now := time.Date(2026, 5, 23, 2, 30, 0, 0, time.UTC)
	audit := model.AuditLog{
		ID:        "audit_outbox_mode_e2e_001",
		TenantID:  "tenant_lab_001",
		EventType: "admin_export_task_enqueued",
		Timestamp: now.Format(time.RFC3339),
		Metadata:  map[string]any{"export_job_id": "exp_outbox_mode_e2e_001"},
	}
	statement, err := buildPostgresAdminAuditOutboxInsertStatement(audit, now)
	if err != nil {
		t.Fatalf("build outbox insert statement returned error: %v", err)
	}
	if _, err := db.ExecContext(ctx, statement.SQL, statement.Args...); err != nil {
		t.Fatalf("insert outbox row returned error: %v", err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	runCtx, stop := context.WithCancel(context.Background())
	go func() {
		time.Sleep(500 * time.Millisecond)
		stop()
	}()
	err = runPostgresAuditOutboxPublisher(runCtx, postgresAuditOutboxPublisherConfig{
		DSN:           dsn,
		MigrationDir:  filepath.Join("..", "..", "migrations"),
		RunMigrations: true,
		TenantID:      "tenant_lab_001",
		PublisherID:   "publisher_mode_e2e_001",
		PollInterval:  10 * time.Millisecond,
		Writer:        writer,
	})
	if err != nil {
		t.Fatalf("runPostgresAuditOutboxPublisher returned error: %v", err)
	}
	rows, err := writer.ReadJSONL("audit.log.jsonl")
	if err != nil {
		t.Fatalf("ReadJSONL returned error: %v", err)
	}
	if len(rows) != 1 || rows[0]["event_type"] != "admin_export_task_enqueued" {
		t.Fatalf("audit rows = %#v", rows)
	}
	var status string
	if err := db.QueryRowContext(ctx, "SELECT status FROM admin_audit_outbox WHERE tenant_id = $1 AND outbox_id = $2", "tenant_lab_001", "audit_outbox_mode_e2e_001").Scan(&status); err != nil {
		t.Fatalf("query outbox status returned error: %v", err)
	}
	if status != "published" {
		t.Fatalf("outbox status = %s, want published", status)
	}
}

func TestRunPostgresAuditOutboxPublisherWebhookModeE2E(t *testing.T) {
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

	now := time.Date(2026, 5, 23, 2, 35, 0, 0, time.UTC)
	audit := model.AuditLog{
		ID:        "audit_outbox_webhook_mode_e2e_001",
		TenantID:  "tenant_lab_001",
		EventType: "admin_export_completed",
		Timestamp: now.Format(time.RFC3339),
		Metadata:  map[string]any{"export_job_id": "exp_outbox_webhook_mode_e2e_001"},
	}
	statement, err := buildPostgresAdminAuditOutboxInsertStatement(audit, now)
	if err != nil {
		t.Fatalf("build outbox insert statement returned error: %v", err)
	}
	if _, err := db.ExecContext(ctx, statement.SQL, statement.Args...); err != nil {
		t.Fatalf("insert outbox row returned error: %v", err)
	}

	type webhookCapture struct {
		auth      string
		keyID     string
		timestamp string
		nonce     string
		signature string
		payload   []byte
		audit     model.AuditLog
	}
	received := make(chan webhookCapture, 1)
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		payload, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body", http.StatusInternalServerError)
			return
		}
		var gotAudit model.AuditLog
		if err := json.Unmarshal(payload, &gotAudit); err != nil {
			http.Error(w, "decode body", http.StatusBadRequest)
			return
		}
		received <- webhookCapture{
			auth:      r.Header.Get("authorization"),
			keyID:     r.Header.Get("x-admin-audit-signature-key-id"),
			timestamp: r.Header.Get("x-admin-audit-timestamp"),
			nonce:     r.Header.Get("x-admin-audit-nonce"),
			signature: r.Header.Get("x-admin-audit-signature"),
			payload:   payload,
			audit:     gotAudit,
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer webhook.Close()

	runCtx, stop := context.WithCancel(context.Background())
	go func() {
		time.Sleep(500 * time.Millisecond)
		stop()
	}()
	err = runPostgresAuditOutboxPublisher(runCtx, postgresAuditOutboxPublisherConfig{
		DSN:            dsn,
		MigrationDir:   filepath.Join("..", "..", "migrations"),
		RunMigrations:  true,
		TenantID:       "tenant_lab_001",
		PublisherID:    "publisher_webhook_mode_e2e_001",
		PollInterval:   10 * time.Millisecond,
		DeliveryMode:   "webhook",
		WebhookURL:     webhook.URL,
		WebhookToken:   "audit-webhook-token",
		WebhookSecret:  "audit-webhook-secret",
		WebhookKeyID:   "kid-audit-webhook-e2e",
		WebhookTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("runPostgresAuditOutboxPublisher webhook returned error: %v", err)
	}

	var got webhookCapture
	select {
	case got = <-received:
	default:
		t.Fatalf("webhook did not receive an admin audit")
	}
	if got.auth != "Bearer audit-webhook-token" || got.keyID != "kid-audit-webhook-e2e" || got.audit.ID != audit.ID {
		t.Fatalf("webhook capture = %#v", got)
	}
	if want := adminAuditWebhookSignature("audit-webhook-secret", got.timestamp, got.nonce, got.payload); got.signature != want {
		t.Fatalf("webhook signature = %q, want %q", got.signature, want)
	}
	if err := verifyAdminAuditWebhookSignature("audit-webhook-secret", got.timestamp, got.nonce, got.signature, got.payload, time.Now().UTC(), 5*time.Minute); err != nil {
		t.Fatalf("verifyAdminAuditWebhookSignature returned error: %v", err)
	}
	var status string
	if err := db.QueryRowContext(ctx, "SELECT status FROM admin_audit_outbox WHERE tenant_id = $1 AND outbox_id = $2", "tenant_lab_001", audit.ID).Scan(&status); err != nil {
		t.Fatalf("query webhook outbox status returned error: %v", err)
	}
	if status != "published" {
		t.Fatalf("outbox status = %s, want published", status)
	}
}

func TestPostgresAdminAuditOutboxPublisherDetectsStolenLockE2E(t *testing.T) {
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

	now := time.Date(2026, 5, 23, 2, 40, 0, 0, time.UTC)
	audit := model.AuditLog{
		ID:        "audit_outbox_stolen_lock_e2e_001",
		TenantID:  "tenant_lab_001",
		EventType: "admin_export_requested",
		Timestamp: now.Format(time.RFC3339),
	}
	insert, err := buildPostgresAdminAuditOutboxInsertStatement(audit, now)
	if err != nil {
		t.Fatalf("build outbox insert statement returned error: %v", err)
	}
	if _, err := db.ExecContext(ctx, insert.SQL, insert.Args...); err != nil {
		t.Fatalf("insert outbox row returned error: %v", err)
	}

	publisherA := postgresAdminAuditOutboxPublisher{
		DB:           db,
		TenantID:     "tenant_lab_001",
		PublisherID:  "publisher_stolen_a",
		LockDuration: 10 * time.Millisecond,
	}
	claimedA, err := publisherA.claim(ctx, now)
	if err != nil {
		t.Fatalf("publisher A claim returned error: %v", err)
	}
	if len(claimedA) != 1 {
		t.Fatalf("publisher A claimed %d rows, want 1", len(claimedA))
	}
	publisherB := postgresAdminAuditOutboxPublisher{
		DB:          db,
		TenantID:    "tenant_lab_001",
		PublisherID: "publisher_stolen_b",
	}
	claimedB, err := publisherB.claim(ctx, now.Add(20*time.Millisecond))
	if err != nil {
		t.Fatalf("publisher B claim returned error: %v", err)
	}
	if len(claimedB) != 1 {
		t.Fatalf("publisher B claimed %d rows, want 1", len(claimedB))
	}
	err = publisherA.markPublished(ctx, claimedA[0], now.Add(30*time.Millisecond))
	if err == nil || !strings.Contains(err.Error(), "lock was stolen") {
		t.Fatalf("publisher A markPublished error = %v, want stolen lock", err)
	}
}

func TestPostgresAdminAuditOutboxPublisherDetectsStolenReleaseLockE2E(t *testing.T) {
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

	now := time.Date(2026, 5, 23, 2, 45, 0, 0, time.UTC)
	audit := model.AuditLog{
		ID:        "audit_outbox_stolen_release_e2e_001",
		TenantID:  "tenant_lab_001",
		EventType: "admin_export_requested",
		Timestamp: now.Format(time.RFC3339),
	}
	insert, err := buildPostgresAdminAuditOutboxInsertStatement(audit, now)
	if err != nil {
		t.Fatalf("build outbox insert statement returned error: %v", err)
	}
	if _, err := db.ExecContext(ctx, insert.SQL, insert.Args...); err != nil {
		t.Fatalf("insert outbox row returned error: %v", err)
	}

	publisherA := postgresAdminAuditOutboxPublisher{
		DB:           db,
		TenantID:     "tenant_lab_001",
		PublisherID:  "publisher_release_stolen_a",
		LockDuration: 10 * time.Millisecond,
	}
	claimedA, err := publisherA.claim(ctx, now)
	if err != nil {
		t.Fatalf("publisher A claim returned error: %v", err)
	}
	if len(claimedA) != 1 {
		t.Fatalf("publisher A claimed %d rows, want 1", len(claimedA))
	}
	publisherB := postgresAdminAuditOutboxPublisher{
		DB:          db,
		TenantID:    "tenant_lab_001",
		PublisherID: "publisher_release_stolen_b",
	}
	claimedB, err := publisherB.claim(ctx, now.Add(20*time.Millisecond))
	if err != nil {
		t.Fatalf("publisher B claim returned error: %v", err)
	}
	if len(claimedB) != 1 {
		t.Fatalf("publisher B claimed %d rows, want 1", len(claimedB))
	}
	err = publisherA.release(ctx, claimedA[0], "audit_delivery_failed", now.Add(30*time.Millisecond))
	if err == nil || !strings.Contains(err.Error(), "lock was stolen") {
		t.Fatalf("publisher A release error = %v, want stolen lock", err)
	}
}

func TestPostgresAdminAuditOutboxPublisherDeadLettersAfterMaxAttemptsE2E(t *testing.T) {
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

	now := time.Date(2026, 5, 23, 2, 50, 0, 0, time.UTC)
	audit := model.AuditLog{
		ID:        "audit_outbox_dead_e2e_001",
		TenantID:  "tenant_lab_001",
		EventType: "admin_export_task_enqueued",
		Timestamp: now.Format(time.RFC3339),
	}
	insert, err := buildPostgresAdminAuditOutboxInsertStatement(audit, now)
	if err != nil {
		t.Fatalf("build outbox insert statement returned error: %v", err)
	}
	if _, err := db.ExecContext(ctx, insert.SQL, insert.Args...); err != nil {
		t.Fatalf("insert outbox row returned error: %v", err)
	}

	publisher := postgresAdminAuditOutboxPublisher{
		DB:          db,
		TenantID:    "tenant_lab_001",
		PublisherID: "publisher_dead_e2e",
		MaxAttempts: 1,
	}
	claimed, err := publisher.claim(ctx, now.Add(time.Second))
	if err != nil {
		t.Fatalf("claim returned error: %v", err)
	}
	if len(claimed) != 1 || claimed[0].PublishAttempt != 1 {
		t.Fatalf("claimed = %#v, want one row with publish_attempt=1", claimed)
	}
	if err := publisher.release(ctx, claimed[0], "jsonl_publish_failed", now.Add(2*time.Second)); err != nil {
		t.Fatalf("release returned error: %v", err)
	}

	var status, lastError string
	var publishAttempt int
	var deadAtPresent bool
	var nextAttemptPresent bool
	if err := db.QueryRowContext(ctx, "SELECT status, publish_attempt, last_error, dead_at IS NOT NULL, next_attempt_at IS NOT NULL FROM admin_audit_outbox WHERE tenant_id = $1 AND outbox_id = $2", "tenant_lab_001", "audit_outbox_dead_e2e_001").Scan(&status, &publishAttempt, &lastError, &deadAtPresent, &nextAttemptPresent); err != nil {
		t.Fatalf("query outbox row returned error: %v", err)
	}
	if status != "dead" || publishAttempt != 1 || lastError != "jsonl_publish_failed" || !deadAtPresent || nextAttemptPresent {
		t.Fatalf("status=%s publish_attempt=%d last_error=%s dead_at=%v next_attempt=%v, want dead/1/jsonl_publish_failed/dead_at/no-next", status, publishAttempt, lastError, deadAtPresent, nextAttemptPresent)
	}
	deadRows, err := listPostgresAdminAuditOutboxDeadRows(ctx, db, "tenant_lab_001", 10)
	if err != nil {
		t.Fatalf("listPostgresAdminAuditOutboxDeadRows returned error: %v", err)
	}
	if len(deadRows) != 1 || deadRows[0].OutboxID != "audit_outbox_dead_e2e_001" || deadRows[0].LastError != "jsonl_publish_failed" || deadRows[0].Audit.ID != "audit_outbox_dead_e2e_001" {
		t.Fatalf("deadRows = %#v", deadRows)
	}
	deadRow, found, err := getPostgresAdminAuditOutboxDeadRow(ctx, db, "tenant_lab_001", "audit_outbox_dead_e2e_001")
	if err != nil {
		t.Fatalf("getPostgresAdminAuditOutboxDeadRow returned error: %v", err)
	}
	if !found || deadRow.OutboxID != "audit_outbox_dead_e2e_001" || deadRow.LastError != "jsonl_publish_failed" {
		t.Fatalf("deadRow = %#v found=%v, want audit_outbox_dead_e2e_001/jsonl_publish_failed", deadRow, found)
	}
	stats, err := postgresAdminAuditOutboxStatsForTenant(ctx, db, "tenant_lab_001")
	if err != nil {
		t.Fatalf("postgresAdminAuditOutboxStatsForTenant returned error: %v", err)
	}
	if stats.Dead != 1 || stats.Total != 1 || stats.OldestDeadAt == nil || !stats.OldestDeadAt.Equal(now.Add(2*time.Second)) {
		t.Fatalf("stats after dead = %#v, want one dead row", stats)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		AdminAuditOutbox: postgresAdminAuditOutboxReader{DB: db},
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/audit-outbox/dead?limit=10", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("dead outbox endpoint status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var result struct {
		Returned int                               `json:"returned"`
		Rows     []postgresAdminAuditOutboxDeadRow `json:"rows"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode dead outbox endpoint response: %v", err)
	}
	if result.Returned != 1 || len(result.Rows) != 1 || result.Rows[0].OutboxID != "audit_outbox_dead_e2e_001" {
		t.Fatalf("dead outbox endpoint result = %#v", result)
	}
	claimedAgain, err := publisher.claim(ctx, now.Add(3*time.Second))
	if err != nil {
		t.Fatalf("second claim returned error: %v", err)
	}
	if len(claimedAgain) != 0 {
		t.Fatalf("claimed dead rows = %#v, want none", claimedAgain)
	}
	replayed, found, err := replayPostgresAdminAuditOutboxDeadRow(ctx, db, "tenant_lab_001", "audit_outbox_dead_e2e_001", now.Add(4*time.Second))
	if err != nil {
		t.Fatalf("replayPostgresAdminAuditOutboxDeadRow returned error: %v", err)
	}
	if !found || replayed.Status != "pending" || replayed.PublishAttempt != 0 {
		t.Fatalf("replayed = %#v found=%v, want pending attempt 0", replayed, found)
	}
	if replayed.PreviousPublishAttempt != 1 || replayed.PreviousLastError != "jsonl_publish_failed" || replayed.PreviousDeadAt == nil {
		t.Fatalf("replayed previous failure = %#v, want attempt 1/jsonl_publish_failed/dead_at", replayed)
	}
	stats, err = postgresAdminAuditOutboxStatsForTenant(ctx, db, "tenant_lab_001")
	if err != nil {
		t.Fatalf("stats after replay returned error: %v", err)
	}
	if stats.Pending != 1 || stats.Dead != 0 || stats.Total != 1 || stats.OldestPendingAt == nil || !stats.OldestPendingAt.Equal(now) {
		t.Fatalf("stats after replay = %#v, want one pending row", stats)
	}
	claimedAfterReplay, err := publisher.claim(ctx, now.Add(5*time.Second))
	if err != nil {
		t.Fatalf("claim after replay returned error: %v", err)
	}
	if len(claimedAfterReplay) != 1 || claimedAfterReplay[0].OutboxID != "audit_outbox_dead_e2e_001" || claimedAfterReplay[0].PublishAttempt != 1 {
		t.Fatalf("claimed after replay = %#v", claimedAfterReplay)
	}
}

func TestPostgresAdminAuditOutboxPublisherDeliveryFailureDeadLettersE2E(t *testing.T) {
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

	now := time.Date(2026, 5, 23, 3, 0, 0, 0, time.UTC)
	audit := model.AuditLog{
		ID:        "audit_outbox_delivery_dead_e2e_001",
		TenantID:  "tenant_lab_001",
		EventType: "admin_export_requested",
		Timestamp: now.Format(time.RFC3339),
	}
	insert, err := buildPostgresAdminAuditOutboxInsertStatement(audit, now)
	if err != nil {
		t.Fatalf("build outbox insert statement returned error: %v", err)
	}
	if _, err := db.ExecContext(ctx, insert.SQL, insert.Args...); err != nil {
		t.Fatalf("insert outbox row returned error: %v", err)
	}

	publisher := postgresAdminAuditOutboxPublisher{
		DB:          db,
		TenantID:    "tenant_lab_001",
		PublisherID: "publisher_delivery_dead_e2e",
		Delivery:    failingAdminAuditOutboxDelivery{},
		MaxAttempts: 1,
	}
	published, err := publisher.PublishOnce(ctx, now.Add(time.Second))
	if err == nil || !strings.Contains(err.Error(), "delivery unavailable") {
		t.Fatalf("PublishOnce error = %v, want delivery unavailable", err)
	}
	if published != 0 {
		t.Fatalf("published = %d, want 0", published)
	}

	var status, lastError string
	var deadAtPresent bool
	if err := db.QueryRowContext(ctx, "SELECT status, last_error, dead_at IS NOT NULL FROM admin_audit_outbox WHERE tenant_id = $1 AND outbox_id = $2", "tenant_lab_001", "audit_outbox_delivery_dead_e2e_001").Scan(&status, &lastError, &deadAtPresent); err != nil {
		t.Fatalf("query outbox row returned error: %v", err)
	}
	if status != "dead" || lastError != "audit_delivery_failed" || !deadAtPresent {
		t.Fatalf("status=%s last_error=%s dead_at=%v, want dead/audit_delivery_failed/dead_at", status, lastError, deadAtPresent)
	}
}

func TestPostgresAdminAuditOutboxPublisherRecordsClassifiedDeliveryFailureE2E(t *testing.T) {
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

	now := time.Date(2026, 5, 23, 3, 5, 0, 0, time.UTC)
	audit := model.AuditLog{
		ID:        "audit_outbox_delivery_classified_e2e_001",
		TenantID:  "tenant_lab_001",
		EventType: "admin_export_requested",
		Timestamp: now.Format(time.RFC3339),
	}
	insert, err := buildPostgresAdminAuditOutboxInsertStatement(audit, now)
	if err != nil {
		t.Fatalf("build outbox insert statement returned error: %v", err)
	}
	if _, err := db.ExecContext(ctx, insert.SQL, insert.Args...); err != nil {
		t.Fatalf("insert outbox row returned error: %v", err)
	}

	publisher := postgresAdminAuditOutboxPublisher{
		DB:          db,
		TenantID:    "tenant_lab_001",
		PublisherID: "publisher_delivery_classified_e2e",
		Delivery: typedFailingAdminAuditOutboxDelivery{
			err: adminAuditOutboxDeliveryFailure{Code: "audit_delivery_http_5xx", Err: fmt.Errorf("status 503")},
		},
		MaxAttempts: 1,
	}
	published, err := publisher.PublishOnce(ctx, now.Add(time.Second))
	if err == nil || !strings.Contains(err.Error(), "audit_delivery_http_5xx") {
		t.Fatalf("PublishOnce error = %v, want classified delivery failure", err)
	}
	if published != 0 {
		t.Fatalf("published = %d, want 0", published)
	}

	var status, lastError string
	if err := db.QueryRowContext(ctx, "SELECT status, last_error FROM admin_audit_outbox WHERE tenant_id = $1 AND outbox_id = $2", "tenant_lab_001", "audit_outbox_delivery_classified_e2e_001").Scan(&status, &lastError); err != nil {
		t.Fatalf("query outbox row returned error: %v", err)
	}
	if status != "dead" || lastError != "audit_delivery_http_5xx" {
		t.Fatalf("status=%s last_error=%s, want dead/audit_delivery_http_5xx", status, lastError)
	}
}

func resetPostgresExportTaskQueueTables(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	for _, statement := range []string{
		"DROP TABLE IF EXISTS agent_status_events",
		"DROP TABLE IF EXISTS agent_update_events",
		"DROP TABLE IF EXISTS device_inventory",
		"DROP TABLE IF EXISTS admin_api_tokens",
		"DROP TABLE IF EXISTS admin_sessions",
		"DROP TABLE IF EXISTS admin_principals",
		"DROP TABLE IF EXISTS connector_registrations",
		"DROP TABLE IF EXISTS human_identity_source_policies",
		"DROP TABLE IF EXISTS human_identity_source_states",
		"DROP TABLE IF EXISTS human_identities",
		"DROP TABLE IF EXISTS workload_attestation_nonces",
		"DROP TABLE IF EXISTS non_human_identities",
		"DROP TABLE IF EXISTS usage_meter_records",
		"DROP TABLE IF EXISTS domain_event_outbox",
		"DROP TABLE IF EXISTS admin_audit_outbox",
		"DROP TABLE IF EXISTS hot_events",
		"DROP TABLE IF EXISTS export_worker_task_dead_letters",
		"DROP TABLE IF EXISTS export_worker_tasks",
		"DROP TABLE IF EXISTS admin_export_jobs",
		// Migration 047 attaches a non-idempotent trigger to this table.
		// Its table must be removed together with the migration ledger.
		"DROP TABLE IF EXISTS cp_state_blobs CASCADE",
		"DROP TABLE IF EXISTS schema_migrations",
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			t.Fatalf("reset postgres export task queue table with %q: %v", statement, err)
		}
	}
}

func applyPostgresExportTaskQueueMigration(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	migrations, err := migrationstore.LoadDir(filepath.Join("..", "..", "migrations"))
	if err != nil {
		t.Fatalf("load postgres export task migrations: %v", err)
	}
	if err := migrationstore.Apply(ctx, db, migrations); err != nil {
		t.Fatalf("apply postgres export task migrations: %v", err)
	}
}

func attachPostgresAdminExportJobStoreToAdapter(t *testing.T, ctx context.Context, db *sql.DB, adapter *postgresExportTaskQueueAdapter, document adminExportWorkerTaskDocument) postgresAdminExportJobStore {
	t.Helper()
	sourceJob, ok := adapter.Resolver.Store.Get(document.ExportJobID)
	if !ok {
		t.Fatalf("fixture job %s is absent", document.ExportJobID)
	}
	store := postgresAdminExportJobStore{DB: db}
	if err := store.Upsert(ctx, sourceJob, time.Date(2026, 5, 23, 1, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("Upsert postgres admin export job returned error: %v", err)
	}
	adapter.Resolver.Store = store
	return store
}

func insertPostgresHotEventForEdgeTest(t *testing.T, ctx context.Context, db *sql.DB, tenantID, stream, eventID string, payload map[string]any) {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal hot event payload: %v", err)
	}
	decisionID := strings.TrimSpace(fmt.Sprint(payload["access_decision_id"]))
	occurredAt := time.Date(2026, 5, 23, 0, 30, 0, 0, time.UTC)
	_, err = db.ExecContext(ctx, "INSERT INTO hot_events (tenant_id, stream, event_id, access_decision_id, occurred_at, received_at, payload) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)", tenantID, stream, eventID, decisionID, occurredAt, occurredAt.Add(time.Second), string(data))
	if err != nil {
		t.Fatalf("insert hot event: %v", err)
	}
}

type postgresExportTaskRowsTable string

const (
	postgresExportTaskRowsActiveTable     postgresExportTaskRowsTable = "export_worker_tasks"
	postgresExportTaskRowsDeadLetterTable postgresExportTaskRowsTable = "export_worker_task_dead_letters"
)

func (table postgresExportTaskRowsTable) sqlName(t *testing.T) string {
	t.Helper()
	switch table {
	case postgresExportTaskRowsActiveTable, postgresExportTaskRowsDeadLetterTable:
		return string(table)
	default:
		t.Fatalf("unsupported postgres export task table %q", table)
		return ""
	}
}

func countPostgresExportTaskRows(t *testing.T, ctx context.Context, db *sql.DB, table postgresExportTaskRowsTable) int {
	t.Helper()
	var count int
	tableName := table.sqlName(t)
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM "+tableName).Scan(&count); err != nil {
		t.Fatalf("count %s rows: %v", table, err)
	}
	return count
}

func countPostgresAdminAuditOutboxRows(t *testing.T, ctx context.Context, db *sql.DB, tenantID string) int {
	t.Helper()
	var count int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM admin_audit_outbox WHERE tenant_id = $1", tenantID).Scan(&count); err != nil {
		t.Fatalf("count admin audit outbox rows: %v", err)
	}
	return count
}

func postgresAdminAuditOutboxEventTypes(t *testing.T, ctx context.Context, db *sql.DB, tenantID string) []string {
	t.Helper()
	rows, err := db.QueryContext(ctx, "SELECT event_type FROM admin_audit_outbox WHERE tenant_id = $1 ORDER BY event_type", tenantID)
	if err != nil {
		t.Fatalf("query admin audit outbox event types: %v", err)
	}
	defer rows.Close()
	var eventTypes []string
	for rows.Next() {
		var eventType string
		if err := rows.Scan(&eventType); err != nil {
			t.Fatalf("scan admin audit outbox event type: %v", err)
		}
		eventTypes = append(eventTypes, eventType)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate admin audit outbox event types: %v", err)
	}
	return eventTypes
}

type failingAdminAuditOutboxDelivery struct{}

func (delivery failingAdminAuditOutboxDelivery) DeliverAdminAudit(context.Context, model.AuditLog) error {
	return fmt.Errorf("delivery unavailable")
}

type typedFailingAdminAuditOutboxDelivery struct {
	err error
}

func (delivery typedFailingAdminAuditOutboxDelivery) DeliverAdminAudit(context.Context, model.AuditLog) error {
	return delivery.err
}

type recordingPostgresExportTaskSQLDB struct {
	DB      *sql.DB
	queries []string
}

func (db *recordingPostgresExportTaskSQLDB) ExecContext(ctx context.Context, statement string, args ...any) (sql.Result, error) {
	return db.DB.ExecContext(ctx, statement, args...)
}

func (db *recordingPostgresExportTaskSQLDB) QueryRowContext(ctx context.Context, statement string, args ...any) postgresExportTaskRow {
	db.queries = append(db.queries, statement)
	return db.DB.QueryRowContext(ctx, statement, args...)
}

func (db *recordingPostgresExportTaskSQLDB) countQueriesContaining(needle string) int {
	count := 0
	for _, query := range db.queries {
		if strings.Contains(query, needle) {
			count++
		}
	}
	return count
}
