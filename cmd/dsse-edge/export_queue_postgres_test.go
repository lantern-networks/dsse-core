package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/hotstore"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/objectstore"
)

func TestBuildPostgresExportTaskEnqueueStatementSerializesDocument(t *testing.T) {
	now := time.Date(2026, 5, 23, 1, 0, 0, 0, time.UTC)
	req := adminExportJobRequest{Stream: "access", Format: "ndjson", From: "2026-05-23T00:00:00Z", To: "2026-05-23T01:00:00Z"}
	job := newAdminExportJobStore().Create(req, "tenant_lab_001", "admin_lab_001", now)
	document, err := adminExportWorkerTaskDocumentFromJob(job, req, "127.0.0.1")
	if err != nil {
		t.Fatalf("adminExportWorkerTaskDocumentFromJob returned error: %v", err)
	}

	statement, err := buildPostgresExportTaskEnqueueStatement(adminExportQueuedTask{Document: document})
	if err != nil {
		t.Fatalf("buildPostgresExportTaskEnqueueStatement returned error: %v", err)
	}
	for _, want := range []string{
		"INSERT INTO export_worker_tasks",
		"tenant_id, task_id, export_job_id",
		"ON CONFLICT (tenant_id, task_id) DO NOTHING",
		"$6::jsonb",
	} {
		if !strings.Contains(statement.SQL, want) {
			t.Fatalf("SQL = %s, want %s", statement.SQL, want)
		}
	}
	if len(statement.Args) != 6 || statement.Args[0] != "tenant_lab_001" || statement.Args[1] != document.ID || statement.Args[2] != job.ID {
		t.Fatalf("args = %#v", statement.Args)
	}
	var payload adminExportWorkerTaskDocument
	if err := json.Unmarshal([]byte(statement.Args[5].(string)), &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if payload.ID != document.ID || payload.ExportJobID != job.ID || payload.TenantID != "tenant_lab_001" {
		t.Fatalf("payload = %#v", payload)
	}
}

func TestBuildPostgresExportTaskLeaseStatementUsesSkipLockedAndTenantScope(t *testing.T) {
	now := time.Date(2026, 5, 23, 1, 0, 0, 0, time.UTC)

	statement, err := buildPostgresExportTaskLeaseStatement("tenant_lab_001", "worker_tokyo_001", now, 45*time.Second)
	if err != nil {
		t.Fatalf("buildPostgresExportTaskLeaseStatement returned error: %v", err)
	}
	for _, want := range []string{
		"UPDATE export_worker_tasks",
		"tenant_id = $1",
		"status = 'queued'",
		"retry_not_before IS NULL OR retry_not_before <= $4",
		"FOR UPDATE SKIP LOCKED LIMIT 1",
		"RETURNING payload",
	} {
		if !strings.Contains(statement.SQL, want) {
			t.Fatalf("SQL = %s, want %s", statement.SQL, want)
		}
	}
	if statement.Args[0] != "tenant_lab_001" || statement.Args[1] != "worker_tokyo_001" || !statement.Args[2].(time.Time).Equal(now.Add(45*time.Second)) || !statement.Args[3].(time.Time).Equal(now) {
		t.Fatalf("args = %#v", statement.Args)
	}
}

func TestBuildPostgresExportTaskLifecycleStatementsScopeTenant(t *testing.T) {
	now := time.Date(2026, 5, 23, 1, 0, 0, 0, time.UTC)
	must := func(statement postgresExportTaskQueueStatement, err error) postgresExportTaskQueueStatement {
		t.Helper()
		if err != nil {
			t.Fatalf("statement builder returned error: %v", err)
		}
		return statement
	}
	cases := map[string]struct {
		statement postgresExportTaskQueueStatement
		wants     []string
	}{
		"complete": {
			statement: must(buildPostgresExportTaskCompleteStatement("tenant_lab_001", "task_001")),
			wants:     []string{"DELETE FROM export_worker_tasks", "tenant_id = $1", "task_id = $2"},
		},
		"release": {
			statement: must(buildPostgresExportTaskReleaseStatement("tenant_lab_001", "task_001", now)),
			wants:     []string{"status = 'queued'", "lease_owner = NULL", "status = 'running'", "RETURNING payload"},
		},
		"extend": {
			statement: must(buildPostgresExportTaskExtendLeaseStatement("tenant_lab_001", "task_001", "worker_tokyo_001", now, time.Minute)),
			wants:     []string{"lease_expires_at = $4", "lease_owner = $3", "status = 'running'", "RETURNING payload"},
		},
		"retry": {
			statement: must(buildPostgresExportTaskRetryStatement("tenant_lab_001", "task_001", now, 30)),
			wants:     []string{"attempt = attempt + 1", "retry_not_before = $3", "{lease_expires_at}", "{metadata,retry_not_before}", "{metadata,retry_scheduled_at}", "{metadata,retry_backoff_seconds}", "attempt + 1 < max_attempts", "RETURNING payload"},
		},
		"dead letter": {
			statement: must(buildPostgresExportTaskDeadLetterStatement("tenant_lab_001", "task_001", now, "")),
			wants:     []string{"WITH moved AS", "DELETE FROM export_worker_tasks", "export_worker_task_dead_letters", "attempt + 1 >= max_attempts", "RETURNING payload"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			for _, want := range append([]string{"tenant_id = $1", "task_id = $2"}, tc.wants...) {
				if !strings.Contains(tc.statement.SQL, want) {
					t.Fatalf("SQL = %s, want %s", tc.statement.SQL, want)
				}
			}
			if len(tc.statement.Args) < 2 || tc.statement.Args[0] != "tenant_lab_001" || tc.statement.Args[1] != "task_001" {
				t.Fatalf("args = %#v", tc.statement.Args)
			}
		})
	}
}

func TestBuildPostgresExportTaskStatementsRejectInvalidInputs(t *testing.T) {
	now := time.Date(2026, 5, 23, 1, 0, 0, 0, time.UTC)
	if _, err := buildPostgresExportTaskEnqueueStatement(adminExportQueuedTask{}); err == nil {
		t.Fatalf("enqueue accepted empty document")
	}
	if _, err := buildPostgresExportTaskLeaseStatement("", "worker_tokyo_001", now, time.Minute); err == nil {
		t.Fatalf("lease accepted empty tenant")
	}
	if _, err := buildPostgresExportTaskLeaseStatement("tenant_lab_001", "", now, time.Minute); err == nil {
		t.Fatalf("lease accepted empty worker")
	}
	if _, err := buildPostgresExportTaskLeaseStatement("tenant_lab_001", "worker_tokyo_001", now, 0); err == nil {
		t.Fatalf("lease accepted zero duration")
	}
	if _, err := buildPostgresExportTaskCompleteStatement("tenant_lab_001", ""); err == nil {
		t.Fatalf("complete accepted empty task id")
	}
	if _, err := buildPostgresExportTaskRetryStatement("tenant_lab_001", "task_001", now, -1); err == nil {
		t.Fatalf("retry accepted negative backoff")
	}
}

func TestBuildPostgresExportTaskRetryStatementRecordsLocalRetryMetadataShape(t *testing.T) {
	now := time.Date(2026, 5, 23, 1, 0, 0, 0, time.UTC)

	statement, err := buildPostgresExportTaskRetryStatement("tenant_lab_001", "task_001", now, 120)
	if err != nil {
		t.Fatalf("buildPostgresExportTaskRetryStatement returned error: %v", err)
	}
	if !strings.Contains(statement.SQL, "'{lease_expires_at}', 'null'::jsonb") {
		t.Fatalf("SQL = %s, want payload lease_expires_at clear", statement.SQL)
	}
	for _, want := range []string{
		"'{metadata,retry_not_before}'",
		"'{metadata,retry_scheduled_at}'",
		"'{metadata,retry_backoff_seconds}'",
	} {
		if !strings.Contains(statement.SQL, want) {
			t.Fatalf("SQL = %s, want %s", statement.SQL, want)
		}
	}
	if len(statement.Args) != 5 || statement.Args[4] != 120 {
		t.Fatalf("args = %#v, want backoff seconds as fifth arg", statement.Args)
	}
}

func TestPostgresExportTaskQueueSchemaSQLMatchesStatementAssumptions(t *testing.T) {
	statements := postgresExportTaskQueueSchemaSQL()
	joined := strings.Join(statements, "\n")
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS export_worker_tasks",
		"PRIMARY KEY (tenant_id, task_id)",
		"status text NOT NULL CHECK (status IN ('queued', 'running'))",
		"retry_not_before timestamptz",
		"lease_owner text",
		"lease_expires_at timestamptz",
		"payload jsonb NOT NULL",
		"export_worker_tasks_lease_idx",
		"export_worker_task_dead_letters",
		"dead_letter_reason text NOT NULL",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("schema SQL = %s, want %s", joined, want)
		}
	}
	if strings.Contains(joined, "$1") {
		t.Fatalf("schema SQL should not contain runtime placeholders: %s", joined)
	}
}

func TestPostgresExportTaskQueueMigrationMatchesSchemaSQL(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "migrations", "001_export_worker_queue.sql"))
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	want := normalizePostgresExportTaskSQLContract(strings.Join(postgresExportTaskQueueSchemaSQL(), "\n"))
	got := normalizePostgresExportTaskSQLContract(string(data))
	if got != want {
		t.Fatalf("migration SQL does not match schema helper\nmigration: %s\nhelper:    %s", got, want)
	}
}

func TestPostgresExportTaskQueueAdapterExecutesEnqueueAndComplete(t *testing.T) {
	adapter, document, _ := newPostgresExportTaskQueueAdapterFixture(t)
	db := &recordingPostgresExportTaskDB{}
	adapter.DB = db

	if err := adapter.Enqueue(context.Background(), adminExportQueuedTask{Document: document}); err != nil {
		t.Fatalf("Enqueue returned error: %v", err)
	}
	if len(db.execs) != 1 || !strings.Contains(db.execs[0].SQL, "INSERT INTO export_worker_tasks") {
		t.Fatalf("execs = %#v, want enqueue insert", db.execs)
	}
	if err := adapter.Complete(context.Background(), document.ID); err != nil {
		t.Fatalf("Complete returned error: %v", err)
	}
	if len(db.execs) != 2 || !strings.Contains(db.execs[1].SQL, "DELETE FROM export_worker_tasks") {
		t.Fatalf("execs = %#v, want complete delete", db.execs)
	}
}

func TestPostgresExportTaskQueueAdapterLeaseHydratesReturnedPayload(t *testing.T) {
	adapter, document, payload := newPostgresExportTaskQueueAdapterFixture(t)
	db := &recordingPostgresExportTaskDB{rows: []postgresExportTaskRow{fakePostgresExportTaskRow{payload: payload}}}
	adapter.DB = db
	now := time.Date(2026, 5, 23, 1, 5, 0, 0, time.UTC)

	item, ok, err := adapter.Lease(context.Background(), now)
	if err != nil {
		t.Fatalf("Lease returned error: %v", err)
	}
	if !ok {
		t.Fatalf("Lease returned ok=false")
	}
	if len(db.queries) != 1 || !strings.Contains(db.queries[0].SQL, "FOR UPDATE SKIP LOCKED LIMIT 1") {
		t.Fatalf("queries = %#v, want SKIP LOCKED lease", db.queries)
	}
	if item.Document.ID != document.ID || item.Job.ID != document.ExportJobID || item.Task.Store == nil || item.Task.HotStore == nil {
		t.Fatalf("hydrated item = %#v", item)
	}
}

func TestPostgresExportTaskQueueAdapterRetryFallsThroughToDeadLetter(t *testing.T) {
	adapter, document, payload := newPostgresExportTaskQueueAdapterFixture(t)
	db := &recordingPostgresExportTaskDB{
		rows: []postgresExportTaskRow{
			fakePostgresExportTaskRow{err: sql.ErrNoRows},
			fakePostgresExportTaskRow{payload: payload},
		},
	}
	adapter.DB = db
	now := time.Date(2026, 5, 23, 1, 10, 0, 0, time.UTC)

	item, queued, err := adapter.Retry(context.Background(), adminExportQueuedTask{Document: document}, now)
	if err != nil {
		t.Fatalf("Retry returned error: %v", err)
	}
	if queued {
		t.Fatalf("Retry returned queued=true, want dead letter path")
	}
	if item.Document.ID != document.ID {
		t.Fatalf("dead letter item = %#v", item)
	}
	if len(db.queries) != 2 || !strings.Contains(db.queries[0].SQL, "attempt + 1 < max_attempts") || !strings.Contains(db.queries[1].SQL, "export_worker_task_dead_letters") {
		t.Fatalf("queries = %#v, want retry then dead letter", db.queries)
	}
}

func TestPostgresQueuedAdminExportWorkerRunOneCompletesLeasedTask(t *testing.T) {
	adapter, document, payload := newPostgresExportTaskQueueAdapterFixture(t)
	db := &recordingPostgresExportTaskDB{rows: []postgresExportTaskRow{fakePostgresExportTaskRow{payload: payload}}}
	adapter.DB = db
	worker := postgresQueuedAdminExportWorker{Queue: adapter, Timeout: time.Second}
	now := time.Date(2026, 5, 23, 1, 15, 0, 0, time.UTC)

	processed, err := worker.runOne(context.Background(), now)
	if err != nil {
		t.Fatalf("runOne returned error: %v", err)
	}
	if !processed {
		t.Fatalf("runOne processed = false")
	}
	if len(db.queries) != 1 || !strings.Contains(db.queries[0].SQL, "FOR UPDATE SKIP LOCKED LIMIT 1") {
		t.Fatalf("queries = %#v, want lease query", db.queries)
	}
	if len(db.execs) != 1 || !strings.Contains(db.execs[0].SQL, "DELETE FROM export_worker_tasks") || db.execs[0].Args[1] != document.ID {
		t.Fatalf("execs = %#v, want complete delete for leased task", db.execs)
	}
	job, ok := adapter.Resolver.Store.Get(document.ExportJobID)
	if !ok || job.Status != "completed" {
		t.Fatalf("job = %#v, ok=%v, want completed", job, ok)
	}
}

func TestPostgresQueuedAdminExportWorkerExtendsLeaseWhileExportRuns(t *testing.T) {
	adapter, _, payload := newPostgresExportTaskQueueAdapterFixture(t)
	adapter.Resolver.HotStore = delayedPostgresQueueHotStore{delay: 50 * time.Millisecond}
	db := &recordingPostgresExportTaskDB{
		rows:           []postgresExportTaskRow{fakePostgresExportTaskRow{payload: payload}},
		defaultPayload: payload,
	}
	adapter.DB = db
	worker := postgresQueuedAdminExportWorker{
		Queue:                  adapter,
		Timeout:                time.Second,
		LeaseExtensionInterval: 5 * time.Millisecond,
	}
	now := time.Date(2026, 5, 23, 1, 15, 0, 0, time.UTC)

	processed, err := worker.runOne(context.Background(), now)
	if err != nil {
		t.Fatalf("runOne returned error: %v", err)
	}
	if !processed {
		t.Fatalf("runOne processed = false")
	}
	if count := db.countQueriesContaining("lease_owner = $3"); count == 0 {
		t.Fatalf("ExtendLease query count = %d, want at least one", count)
	}
}

func TestPostgresQueuedAdminExportWorkerCompletesInFlightTaskAfterRunCancel(t *testing.T) {
	adapter, document, payload := newPostgresExportTaskQueueAdapterFixture(t)
	started := make(chan struct{})
	adapter.Resolver.HotStore = signalingDelayedPostgresQueueHotStore{
		started: started,
		delay:   20 * time.Millisecond,
	}
	db := &recordingPostgresExportTaskDB{rows: []postgresExportTaskRow{fakePostgresExportTaskRow{payload: payload}}}
	adapter.DB = db
	worker := postgresQueuedAdminExportWorker{
		Queue:        adapter,
		Timeout:      time.Second,
		PollInterval: time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- worker.Run(ctx)
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatalf("export did not start")
	}
	cancel()
	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned error %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatalf("Run did not stop after in-flight task completed")
	}
	job, ok := adapter.Resolver.Store.Get(document.ExportJobID)
	if !ok || job.Status != "completed" {
		t.Fatalf("job = %#v, ok=%v, want completed", job, ok)
	}
	if len(db.execs) != 1 || !strings.Contains(db.execs[0].SQL, "DELETE FROM export_worker_tasks") {
		t.Fatalf("execs = %#v, want complete delete despite canceled Run context", db.execs)
	}
}

func newPostgresExportTaskQueueAdapterFixture(t *testing.T) (postgresExportTaskQueueAdapter, adminExportWorkerTaskDocument, []byte) {
	t.Helper()
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	objectStore, err := objectstore.NewLocalStore(logDir)
	if err != nil {
		t.Fatalf("NewLocalStore returned error: %v", err)
	}
	now := time.Date(2026, 5, 23, 1, 0, 0, 0, time.UTC)
	req := adminExportJobRequest{
		Stream:  "access",
		Format:  "ndjson",
		Filters: map[string]string{"decision": "allow"},
		From:    "2026-05-23T00:00:00Z",
		To:      "2026-05-23T01:00:00Z",
		Limit:   50,
	}
	store := newAdminExportJobStore()
	job := store.Create(req, "tenant_lab_001", "admin_lab_001", now)
	document, err := adminExportWorkerTaskDocumentFromJob(job, req, "127.0.0.1")
	if err != nil {
		t.Fatalf("adminExportWorkerTaskDocumentFromJob returned error: %v", err)
	}
	payload, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("marshal document: %v", err)
	}
	adapter := postgresExportTaskQueueAdapter{
		TenantID:      "tenant_lab_001",
		WorkerID:      "worker_tokyo_001",
		LeaseDuration: 30 * time.Second,
		SchemaData:    readExportWorkerTaskSchemaForTest(t),
		Resolver: adminExportRuntimeResolver{
			Writer:      writer,
			ObjectStore: objectStore,
			HotStore:    hotstore.NewJSONLStore(writer, adminLogStreamFilenameMap()),
			Store:       store,
			Evaluator:   testEvaluator(),
		},
	}
	return adapter, document, payload
}

type recordingPostgresExportTaskDB struct {
	mu             sync.Mutex
	execs          []postgresExportTaskQueueStatement
	queries        []postgresExportTaskQueueStatement
	rows           []postgresExportTaskRow
	defaultPayload []byte
	execErr        error
}

func (db *recordingPostgresExportTaskDB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	db.execs = append(db.execs, postgresExportTaskQueueStatement{SQL: query, Args: append([]any(nil), args...)})
	return nil, db.execErr
}

func (db *recordingPostgresExportTaskDB) QueryRowContext(ctx context.Context, query string, args ...any) postgresExportTaskRow {
	db.mu.Lock()
	defer db.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return fakePostgresExportTaskRow{err: err}
	}
	db.queries = append(db.queries, postgresExportTaskQueueStatement{SQL: query, Args: append([]any(nil), args...)})
	if len(db.rows) == 0 {
		if db.defaultPayload != nil {
			return fakePostgresExportTaskRow{payload: db.defaultPayload}
		}
		return fakePostgresExportTaskRow{err: sql.ErrNoRows}
	}
	row := db.rows[0]
	db.rows = db.rows[1:]
	return row
}

func (db *recordingPostgresExportTaskDB) countQueriesContaining(needle string) int {
	db.mu.Lock()
	defer db.mu.Unlock()
	count := 0
	for _, query := range db.queries {
		if strings.Contains(query.SQL, needle) {
			count++
		}
	}
	return count
}

type fakePostgresExportTaskRow struct {
	payload []byte
	err     error
}

func (row fakePostgresExportTaskRow) Scan(dest ...any) error {
	if row.err != nil {
		return row.err
	}
	if len(dest) != 1 {
		return fmt.Errorf("scan destination count = %d, want 1", len(dest))
	}
	target, ok := dest[0].(*[]byte)
	if !ok {
		return fmt.Errorf("scan destination %T, want *[]byte", dest[0])
	}
	*target = append((*target)[:0], row.payload...)
	return nil
}

func normalizePostgresExportTaskSQLContract(value string) string {
	value = strings.ReplaceAll(value, ";", "")
	return strings.Join(strings.Fields(value), " ")
}

type delayedPostgresQueueHotStore struct {
	delay time.Duration
}

func (store delayedPostgresQueueHotStore) Search(_ context.Context, query hotstore.SearchQuery) (hotstore.SearchResult, error) {
	return hotstore.SearchResult{Stream: query.Stream, Limit: query.Limit}, nil
}

func (store delayedPostgresQueueHotStore) ExportRows(ctx context.Context, query hotstore.SearchQuery, yield hotstore.RowHandler) (hotstore.ExportResult, error) {
	timer := time.NewTimer(store.delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return hotstore.ExportResult{}, ctx.Err()
	case <-timer.C:
	}
	if err := yield(map[string]any{"id": "delayed_export_row_001", "tenant_id": query.TenantID, "stream": query.Stream}); err != nil {
		return hotstore.ExportResult{}, err
	}
	return hotstore.ExportResult{
		Stream:       query.Stream,
		Limit:        query.Limit,
		Filters:      map[string]string{"tenant_id": query.TenantID},
		TotalScanned: 1,
		TotalMatches: 1,
		RowsExported: 1,
	}, nil
}

func (store delayedPostgresQueueHotStore) RelatedByAccessDecisionID(_ context.Context, query hotstore.RelatedLogQuery) (hotstore.RelatedLogResult, error) {
	return hotstore.RelatedLogResult{AccessDecisionID: query.AccessDecisionID, RowsByStream: map[string][]map[string]any{}}, nil
}

type signalingDelayedPostgresQueueHotStore struct {
	started chan<- struct{}
	delay   time.Duration
}

func (store signalingDelayedPostgresQueueHotStore) Search(_ context.Context, query hotstore.SearchQuery) (hotstore.SearchResult, error) {
	return hotstore.SearchResult{Stream: query.Stream, Limit: query.Limit}, nil
}

func (store signalingDelayedPostgresQueueHotStore) ExportRows(ctx context.Context, query hotstore.SearchQuery, yield hotstore.RowHandler) (hotstore.ExportResult, error) {
	if store.started != nil {
		close(store.started)
	}
	timer := time.NewTimer(store.delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return hotstore.ExportResult{}, ctx.Err()
	case <-timer.C:
	}
	if err := yield(map[string]any{"id": "shutdown_export_row_001", "tenant_id": query.TenantID, "stream": query.Stream}); err != nil {
		return hotstore.ExportResult{}, err
	}
	return hotstore.ExportResult{
		Stream:       query.Stream,
		Limit:        query.Limit,
		Filters:      map[string]string{"tenant_id": query.TenantID},
		TotalScanned: 1,
		TotalMatches: 1,
		RowsExported: 1,
	}, nil
}

func (store signalingDelayedPostgresQueueHotStore) RelatedByAccessDecisionID(_ context.Context, query hotstore.RelatedLogQuery) (hotstore.RelatedLogResult, error) {
	return hotstore.RelatedLogResult{AccessDecisionID: query.AccessDecisionID, RowsByStream: map[string][]map[string]any{}}, nil
}
