package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/hotstore"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/objectstore"
	schemavalidator "github.com/lantern-networks/dsse-core/schema"
)

type recordingAdminExportWorker struct {
	task adminExportTask
}

func (worker *recordingAdminExportWorker) Enqueue(_ context.Context, task adminExportTask) (adminExportJob, error) {
	worker.task = task
	return adminExportJob{
		ID:                        "export_recorded_worker_001",
		TenantID:                  task.TenantID,
		CreatedByAdminPrincipalID: task.AdminPrincipalID,
		Stream:                    task.Request.Stream,
		Format:                    "ndjson",
		Filters:                   copyStringMap(task.Request.Filters),
		From:                      task.Request.From,
		To:                        task.Request.To,
		Status:                    "queued",
		CreatedAt:                 task.Now.UTC().Format(time.RFC3339),
		ExpiresAt:                 task.Now.UTC().Add(time.Hour).Format(time.RFC3339),
		Metadata:                  map[string]any{"worker": "recording"},
	}, nil
}

func TestAdminExportWorkerTaskDocumentMatchesSchema(t *testing.T) {
	now := time.Date(2026, 5, 23, 1, 0, 0, 0, time.UTC)
	req := adminExportJobRequest{
		Stream:  "access",
		Format:  "ndjson",
		Filters: map[string]string{"application_id": "app_dummy_ssh"},
		From:    "2026-05-23T00:00:00Z",
		To:      "2026-05-23T01:00:00Z",
	}
	job := newAdminExportJobStore().Create(req, "tenant_lab_001", "admin_lab_001", now)

	document, err := adminExportWorkerTaskDocumentFromJob(job, req, "127.0.0.1")
	if err != nil {
		t.Fatalf("adminExportWorkerTaskDocumentFromJob returned error: %v", err)
	}
	if document.ID != "export_task_"+job.ID || document.ExportJobID != job.ID || document.Limit != 1000000 || document.Status != "queued" {
		t.Fatalf("document = %#v", document)
	}
	if document.IdempotencyKey != adminExportWorkerTaskIdempotencyKey(job) {
		t.Fatalf("idempotency key = %q, want %q", document.IdempotencyKey, adminExportWorkerTaskIdempotencyKey(job))
	}
	if document.LeaseExpiresAt != nil {
		t.Fatalf("lease_expires_at = %#v, want nil before Alpha worker lease acquisition", document.LeaseExpiresAt)
	}
	if document.TimeoutSeconds != defaultAdminExportWorkerTimeoutSeconds || document.CancelCheckIntervalRows != defaultAdminExportWorkerCancelCheckIntervalRows || document.MaxAttempts != defaultAdminExportWorkerMaxAttempts {
		t.Fatalf("worker timing fields = timeout %d cancel interval %d max attempts %d", document.TimeoutSeconds, document.CancelCheckIntervalRows, document.MaxAttempts)
	}
	if len(document.RetryPolicy.RetryableErrorCodes) == 0 || len(document.RetryPolicy.NonRetryableErrorCodes) == 0 || len(document.RetryPolicy.BackoffSeconds) != document.MaxAttempts {
		t.Fatalf("retry policy = %#v", document.RetryPolicy)
	}
	if !strings.HasPrefix(document.OutputRefPrefix, "evidence://tenant/tenant_lab_001/exports/2026/05/23/") {
		t.Fatalf("output ref prefix = %q", document.OutputRefPrefix)
	}

	schemaData, err := os.ReadFile(filepath.Join("..", "..", "schemas", "export_worker_task.schema.json"))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	documentData, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("marshal document: %v", err)
	}
	if err := schemavalidator.ValidateRequired(schemaData, documentData); err != nil {
		t.Fatalf("document does not match export worker task schema: %v", err)
	}
}

func TestAdminExportWorkerTaskDocumentReconstructsRequest(t *testing.T) {
	now := time.Date(2026, 5, 23, 1, 0, 0, 0, time.UTC)
	req := adminExportJobRequest{
		Stream: "access",
		Format: "ndjson",
		Filters: map[string]string{
			"application_id": "app_dummy_ssh",
			"decision":       "allow",
		},
		From:  "2026-05-23T00:00:00Z",
		To:    "2026-05-23T01:00:00Z",
		Limit: 250,
	}
	job := newAdminExportJobStore().Create(req, "tenant_lab_001", "admin_lab_001", now)
	document, err := adminExportWorkerTaskDocumentFromJob(job, req, "127.0.0.1")
	if err != nil {
		t.Fatalf("adminExportWorkerTaskDocumentFromJob returned error: %v", err)
	}

	reconstructed := adminExportJobRequestFromWorkerTaskDocument(document)

	if reconstructed.Stream != req.Stream || reconstructed.Format != req.Format || reconstructed.From != req.From || reconstructed.To != req.To || reconstructed.Limit != req.Limit {
		t.Fatalf("reconstructed request = %#v, want %#v", reconstructed, req)
	}
	if !reflect.DeepEqual(reconstructed.Filters, req.Filters) {
		t.Fatalf("reconstructed filters = %#v, want %#v", reconstructed.Filters, req.Filters)
	}
	reconstructed.Filters["decision"] = "deny"
	if document.Filters["decision"] != "allow" {
		t.Fatalf("document filters mutated through reconstructed request: %#v", document.Filters)
	}
}

func TestAdminExportJobUsesConfiguredWorker(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	worker := &recordingAdminExportWorker{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:         testEvaluator(),
		Writer:            writer,
		Registry:          connector.NewRegistry(),
		AdminExportWorker: worker,
	})
	body := `{
		"stream":"access",
		"format":"ndjson",
		"filters":{"event_type":"access_allowed"},
		"from":"2026-05-23T01:00:00Z",
		"to":"2026-05-23T02:00:00Z"
	}`
	req := httptest.NewRequest(http.MethodPost, "/admin/export-jobs", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	if worker.task.TenantID != "tenant_lab_001" || worker.task.AdminPrincipalID != "admin_lab_bypass" || worker.task.Request.Stream != "access" {
		t.Fatalf("worker task = %#v", worker.task)
	}
	var job adminExportJob
	if err := json.NewDecoder(rec.Body).Decode(&job); err != nil {
		t.Fatalf("decode job: %v", err)
	}
	if job.ID != "export_recorded_worker_001" || job.Metadata["worker"] != "recording" {
		t.Fatalf("job = %#v, want worker-produced job", job)
	}
}

func TestLocalAsyncAdminExportWorkerReturnsQueuedThenCompletes(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	if err := writer.Append("access.log.jsonl", map[string]any{
		"id":         "alog_async_001",
		"tenant_id":  "tenant_lab_001",
		"event_type": "access_allowed",
		"timestamp":  "2026-05-23T01:10:00Z",
	}); err != nil {
		t.Fatalf("append access log: %v", err)
	}
	objectStore, err := objectstore.NewLocalStore(logDir)
	if err != nil {
		t.Fatalf("NewLocalStore returned error: %v", err)
	}
	exportJobs := newAdminExportJobStore()
	outbox := &recordingAdminAuditOutboxDeadReader{}
	worker := localAsyncAdminExportWorker{Timeout: 2 * time.Second}
	job, err := worker.Enqueue(context.Background(), adminExportTask{
		Writer:           writer,
		AdminAuditOutbox: outbox,
		ObjectStore:      objectStore,
		HotStore:         hotstore.NewJSONLStore(writer, adminLogStreamFilenameMap()),
		Store:            exportJobs,
		Evaluator:        testEvaluator(),
		Request: adminExportJobRequest{
			Stream: "access",
			Format: "ndjson",
			From:   "2026-05-23T01:00:00Z",
			To:     "2026-05-23T02:00:00Z",
		},
		TenantID:         "tenant_lab_001",
		AdminPrincipalID: "admin_lab_bypass",
		SourceIP:         "127.0.0.1",
		Now:              time.Date(2026, 5, 23, 1, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Enqueue returned error: %v", err)
	}
	if job.Status != "queued" {
		t.Fatalf("initial job status = %s, want queued", job.Status)
	}

	deadline := time.Now().Add(2 * time.Second)
	var completed adminExportJob
	for {
		current, ok := exportJobs.Get(job.ID)
		if !ok {
			t.Fatalf("queued job %s absent", job.ID)
		}
		if current.Status == "completed" {
			completed = current
			break
		}
		if current.Status == "failed" || current.Status == "cancelled" {
			t.Fatalf("async job terminal status = %#v, want completed", current)
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for async export completion; last job = %#v", current)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if completed.RowCount != 1 || completed.ObjectRef == nil || completed.PayloadChecksum == nil {
		t.Fatalf("completed = %#v, want one-row object export", completed)
	}
	auditRows, err := readAuditRowsExcludingWrapper(writer)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if len(auditRows) != 4 || auditRows[0]["event_type"] != "admin_export_requested" || auditRows[1]["event_type"] != "admin_export_task_enqueued" || auditRows[2]["event_type"] != "admin_export_started" || auditRows[3]["event_type"] != "admin_export_completed" {
		t.Fatalf("audit rows = %#v, want async export lifecycle", auditRows)
	}
	var gotOutboxEvents map[string]bool
	for {
		gotOutboxEvents = outbox.insertedAuditEventTypes()
		if gotOutboxEvents["admin_export_completed"] {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for async export outbox audit; events = %#v", gotOutboxEvents)
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, eventType := range []string{"admin_export_requested", "admin_export_task_enqueued", "admin_export_started", "admin_export_completed"} {
		if !gotOutboxEvents[eventType] {
			t.Fatalf("outbox inserted audits = %#v, want %s", outbox.insertedAudits, eventType)
		}
	}
}

func TestLocalAdminExportTaskQueueLeaseAndComplete(t *testing.T) {
	now := time.Date(2026, 5, 23, 1, 0, 0, 0, time.UTC)
	req := adminExportJobRequest{
		Stream: "access",
		Format: "ndjson",
		From:   "2026-05-23T00:00:00Z",
		To:     "2026-05-23T01:00:00Z",
	}
	job := newAdminExportJobStore().Create(req, "tenant_lab_001", "admin_lab_001", now)
	document, err := adminExportWorkerTaskDocumentFromJob(job, req, "127.0.0.1")
	if err != nil {
		t.Fatalf("adminExportWorkerTaskDocumentFromJob returned error: %v", err)
	}
	queue := newLocalAdminExportTaskQueue()
	if err := queue.Enqueue(adminExportQueuedTask{Document: document, Job: job}); err != nil {
		t.Fatalf("Enqueue returned error: %v", err)
	}
	queued, ok := queue.Get(document.ID)
	if !ok || queued.Document.Status != "queued" || queued.Document.LeaseExpiresAt != nil {
		t.Fatalf("queued task = %#v, want queued without lease", queued)
	}

	leased, ok := queue.Lease(now, 45*time.Second)
	if !ok {
		t.Fatalf("Lease returned no task")
	}
	if leased.Document.ID != document.ID || leased.Document.Status != "running" || leased.Document.LeaseExpiresAt == nil {
		t.Fatalf("leased task = %#v, want running with lease", leased)
	}
	if *leased.Document.LeaseExpiresAt != now.Add(45*time.Second).UTC().Format(time.RFC3339) {
		t.Fatalf("lease_expires_at = %q", *leased.Document.LeaseExpiresAt)
	}
	extended, err := queue.ExtendLease(document.ID, now.Add(10*time.Second), 2*time.Minute)
	if err != nil {
		t.Fatalf("ExtendLease returned error: %v", err)
	}
	if extended.Document.LeaseExpiresAt == nil || *extended.Document.LeaseExpiresAt != now.Add(130*time.Second).UTC().Format(time.RFC3339) {
		t.Fatalf("extended lease_expires_at = %#v", extended.Document.LeaseExpiresAt)
	}
	if extended.Document.Metadata["lease_extended_at"] != now.Add(10*time.Second).UTC().Format(time.RFC3339) {
		t.Fatalf("extended metadata = %#v", extended.Document.Metadata)
	}
	if _, ok := queue.Lease(now, 45*time.Second); ok {
		t.Fatalf("Lease returned a second task while first lease is running")
	}
	if err := queue.Complete(document.ID); err != nil {
		t.Fatalf("Complete returned error: %v", err)
	}
	if _, ok := queue.Get(document.ID); ok {
		t.Fatalf("completed task still present in queue")
	}
	if len(queue.order) != 0 {
		t.Fatalf("queue order = %#v, want cleaned after complete", queue.order)
	}
}

func TestLocalAdminExportTaskQueueImplementsBackendContract(t *testing.T) {
	now := time.Date(2026, 5, 23, 1, 0, 0, 0, time.UTC)
	req := adminExportJobRequest{
		Stream: "access",
		Format: "ndjson",
		From:   "2026-05-23T00:00:00Z",
		To:     "2026-05-23T01:00:00Z",
	}
	job := newAdminExportJobStore().Create(req, "tenant_lab_001", "admin_lab_001", now)
	document, err := adminExportWorkerTaskDocumentFromJob(job, req, "127.0.0.1")
	if err != nil {
		t.Fatalf("adminExportWorkerTaskDocumentFromJob returned error: %v", err)
	}
	var queue adminExportTaskQueue = newLocalAdminExportTaskQueue()
	if err := queue.Enqueue(adminExportQueuedTask{Document: document, Job: job}); err != nil {
		t.Fatalf("Enqueue returned error: %v", err)
	}
	leased, ok := queue.Lease(now, time.Minute)
	if !ok || leased.Document.Status != "running" || leased.Document.LeaseExpiresAt == nil {
		t.Fatalf("Lease = %#v, ok=%v, want running lease", leased, ok)
	}
	extended, err := queue.ExtendLease(document.ID, now.Add(10*time.Second), time.Minute)
	if err != nil || extended.Document.LeaseExpiresAt == nil {
		t.Fatalf("ExtendLease = %#v, err=%v", extended, err)
	}
	if err := queue.Release(document.ID); err != nil {
		t.Fatalf("Release returned error: %v", err)
	}
	leased, ok = queue.Lease(now.Add(time.Minute), time.Minute)
	if !ok || leased.Document.Status != "running" {
		t.Fatalf("Lease after release = %#v, ok=%v", leased, ok)
	}
	retried, queued, err := queue.Retry(document.ID, now.Add(2*time.Minute))
	if err != nil || !queued || retried.Document.Attempt != 1 {
		t.Fatalf("Retry = %#v, queued=%v, err=%v", retried, queued, err)
	}
	if err := queue.Complete(document.ID); err != nil {
		t.Fatalf("Complete returned error: %v", err)
	}
	if _, ok := queue.Lease(now.Add(3*time.Minute), time.Minute); ok {
		t.Fatalf("Lease returned task after Complete")
	}
}

func TestLocalAdminExportTaskQueueReleaseRetryAndDeadLetter(t *testing.T) {
	now := time.Date(2026, 5, 23, 1, 0, 0, 0, time.UTC)
	req := adminExportJobRequest{
		Stream: "access",
		Format: "ndjson",
		From:   "2026-05-23T00:00:00Z",
		To:     "2026-05-23T01:00:00Z",
	}
	job := newAdminExportJobStore().Create(req, "tenant_lab_001", "admin_lab_001", now)
	document, err := adminExportWorkerTaskDocumentFromJob(job, req, "127.0.0.1")
	if err != nil {
		t.Fatalf("adminExportWorkerTaskDocumentFromJob returned error: %v", err)
	}
	queue := newLocalAdminExportTaskQueue()
	if err := queue.Enqueue(adminExportQueuedTask{Document: document, Job: job}); err != nil {
		t.Fatalf("Enqueue returned error: %v", err)
	}
	leased, ok := queue.Lease(now, time.Minute)
	if !ok || leased.Document.Status != "running" {
		t.Fatalf("leased = %#v, ok=%v, want running", leased, ok)
	}
	if err := queue.Release(document.ID); err != nil {
		t.Fatalf("Release returned error: %v", err)
	}
	released, ok := queue.Get(document.ID)
	if !ok || released.Document.Status != "queued" || released.Document.LeaseExpiresAt != nil || released.Document.Attempt != 0 {
		t.Fatalf("released = %#v, want queued attempt 0 without lease", released)
	}

	leased, ok = queue.Lease(now.Add(time.Minute), time.Minute)
	if !ok || leased.Document.Attempt != 0 {
		t.Fatalf("leased after release = %#v, ok=%v", leased, ok)
	}
	retried, queued, err := queue.Retry(document.ID, now.Add(2*time.Minute))
	if err != nil || !queued || retried.Document.Attempt != 1 || retried.Document.Status != "queued" || retried.Document.LeaseExpiresAt != nil {
		t.Fatalf("retry attempt 1 = %#v queued=%v err=%v", retried, queued, err)
	}
	if retried.Document.Metadata["retry_backoff_seconds"] != 30 {
		t.Fatalf("retry metadata = %#v, want first backoff 30 seconds", retried.Document.Metadata)
	}
	if _, ok := queue.Lease(now.Add(2*time.Minute+29*time.Second), time.Minute); ok {
		t.Fatalf("Lease returned retry task before retry_not_before")
	}

	_, _ = queue.Lease(now.Add(3*time.Minute), time.Minute)
	retried, queued, err = queue.Retry(document.ID, now.Add(4*time.Minute))
	if err != nil || !queued || retried.Document.Attempt != 2 {
		t.Fatalf("retry attempt 2 = %#v queued=%v err=%v", retried, queued, err)
	}
	if retried.Document.Metadata["retry_backoff_seconds"] != 120 {
		t.Fatalf("retry metadata = %#v, want second backoff 120 seconds", retried.Document.Metadata)
	}

	if _, ok := queue.Lease(now.Add(5*time.Minute), time.Minute); ok {
		t.Fatalf("Lease returned second retry before retry_not_before")
	}
	_, _ = queue.Lease(now.Add(6*time.Minute), time.Minute)
	deadLettered, queued, err := queue.Retry(document.ID, now.Add(7*time.Minute))
	if err != nil || queued || deadLettered.Document.Status != "failed" || deadLettered.Document.Attempt != 2 {
		t.Fatalf("dead letter retry = %#v queued=%v err=%v", deadLettered, queued, err)
	}
	if _, ok := queue.Get(document.ID); ok {
		t.Fatalf("dead-lettered task still present in active queue")
	}
	deadLetter, ok := queue.GetDeadLetter(document.ID)
	if !ok || deadLetter.Document.Metadata["dead_letter_reason"] != "max_attempts_exhausted" {
		t.Fatalf("dead letter = %#v, ok=%v", deadLetter, ok)
	}
	if len(queue.order) != 0 {
		t.Fatalf("queue order = %#v, want cleaned after dead letter", queue.order)
	}
}

func TestLocalQueuedAdminExportWorkerMarksDeadLetteredJobFailed(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	now := time.Date(2026, 5, 23, 1, 0, 0, 0, time.UTC)
	req := adminExportJobRequest{
		Stream: "access",
		Format: "ndjson",
		From:   "2026-05-23T00:00:00Z",
		To:     "2026-05-23T01:00:00Z",
	}
	exportJobs := newAdminExportJobStore()
	job := exportJobs.Create(req, "tenant_lab_001", "admin_lab_bypass", now)
	document, err := adminExportWorkerTaskDocumentFromJob(job, req, "127.0.0.1")
	if err != nil {
		t.Fatalf("adminExportWorkerTaskDocumentFromJob returned error: %v", err)
	}
	document.MaxAttempts = 1
	queue := newLocalAdminExportTaskQueue()
	task := adminExportTask{
		Writer:    writer,
		Store:     exportJobs,
		Evaluator: testEvaluator(),
		Request:   req,
		TenantID:  "tenant_lab_001",
		SourceIP:  "127.0.0.1",
	}
	if err := queue.Enqueue(adminExportQueuedTask{Document: document, Task: task, Job: job}); err != nil {
		t.Fatalf("queue.Enqueue returned error: %v", err)
	}
	if _, ok := queue.Lease(now, time.Minute); !ok {
		t.Fatalf("Lease returned no task")
	}
	deadLettered, queued, err := queue.Retry(document.ID, now.Add(time.Minute))
	if err != nil || queued {
		t.Fatalf("Retry dead letter = %#v queued=%v err=%v", deadLettered, queued, err)
	}
	adminExportMarkDeadLettered(deadLettered, now.Add(2*time.Minute))

	failed, ok := exportJobs.Get(job.ID)
	if !ok {
		t.Fatalf("job %s absent", job.ID)
	}
	if failed.Status != "failed" || failed.ErrorCode == nil || *failed.ErrorCode != "max_attempts_exhausted" {
		t.Fatalf("failed job = %#v, want max_attempts_exhausted", failed)
	}
	if failed.Metadata["dead_letter_reason"] != "max_attempts_exhausted" || failed.Metadata["export_worker_task_id"] != document.ID {
		t.Fatalf("failed metadata = %#v", failed.Metadata)
	}
	auditRows, err := readAuditRowsExcludingWrapper(writer)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if len(auditRows) != 1 || auditRows[0]["event_type"] != "admin_export_failed" {
		t.Fatalf("audit rows = %#v, want dead letter failed audit", auditRows)
	}
	metadata := auditRows[0]["metadata"].(map[string]any)
	if metadata["dead_letter_reason"] != "max_attempts_exhausted" || metadata["export_worker_task_id"] != document.ID {
		t.Fatalf("audit metadata = %#v", metadata)
	}
}

func TestLocalQueuedAdminExportWorkerAuditsDeadLetterBridgeFailure(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	now := time.Date(2026, 5, 23, 1, 0, 0, 0, time.UTC)
	req := adminExportJobRequest{
		Stream: "access",
		Format: "ndjson",
		From:   "2026-05-23T00:00:00Z",
		To:     "2026-05-23T01:00:00Z",
	}
	exportJobs := newAdminExportJobStore()
	job := exportJobs.Create(req, "tenant_lab_001", "admin_lab_bypass", now)
	document, err := adminExportWorkerTaskDocumentFromJob(job, req, "127.0.0.1")
	if err != nil {
		t.Fatalf("adminExportWorkerTaskDocumentFromJob returned error: %v", err)
	}
	if _, err := exportJobs.MarkFailed(job.ID, "query_failed", now.Add(time.Minute)); err != nil {
		t.Fatalf("MarkFailed returned error: %v", err)
	}
	task := adminExportTask{
		Writer:    writer,
		Store:     exportJobs,
		Evaluator: testEvaluator(),
		Request:   req,
		TenantID:  "tenant_lab_001",
		SourceIP:  "127.0.0.1",
	}
	adminExportMarkDeadLettered(adminExportQueuedTask{Document: document, Task: task, Job: job}, now.Add(2*time.Minute))

	auditRows, err := readAuditRowsExcludingWrapper(writer)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if len(auditRows) != 1 || auditRows[0]["event_type"] != "admin_export_dead_letter_bridge_failed" {
		t.Fatalf("audit rows = %#v, want bridge failure audit", auditRows)
	}
	metadata := auditRows[0]["metadata"].(map[string]any)
	if metadata["export_job_id"] != job.ID || metadata["dead_letter_reason"] != "max_attempts_exhausted" || metadata["job_store_error"] == "" {
		t.Fatalf("audit metadata = %#v", metadata)
	}
}

func TestLocalQueuedAdminExportWorkerLeasesRunsAndCompletes(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	if err := writer.Append("access.log.jsonl", map[string]any{
		"id":         "alog_queue_worker_001",
		"tenant_id":  "tenant_lab_001",
		"event_type": "access_allowed",
		"timestamp":  "2026-05-23T01:10:00Z",
	}); err != nil {
		t.Fatalf("append access log: %v", err)
	}
	objectStore, err := objectstore.NewLocalStore(logDir)
	if err != nil {
		t.Fatalf("NewLocalStore returned error: %v", err)
	}
	exportJobs := newAdminExportJobStore()
	queue := newLocalAdminExportTaskQueue()
	worker := localQueuedAdminExportWorker{
		Queue:         queue,
		Timeout:       2 * time.Second,
		LeaseDuration: time.Minute,
		PollInterval:  10 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- worker.Run(ctx)
	}()
	job, err := worker.Enqueue(context.Background(), adminExportTask{
		Writer:      writer,
		ObjectStore: objectStore,
		HotStore:    hotstore.NewJSONLStore(writer, adminLogStreamFilenameMap()),
		Store:       exportJobs,
		Evaluator:   testEvaluator(),
		Request: adminExportJobRequest{
			Stream: "access",
			Format: "ndjson",
			From:   "2026-05-23T01:00:00Z",
			To:     "2026-05-23T02:00:00Z",
		},
		TenantID:         "tenant_lab_001",
		AdminPrincipalID: "admin_lab_bypass",
		SourceIP:         "127.0.0.1",
		Now:              time.Date(2026, 5, 23, 1, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Enqueue returned error: %v", err)
	}
	if job.Status != "queued" {
		t.Fatalf("initial job status = %s, want queued", job.Status)
	}

	deadline := time.Now().Add(2 * time.Second)
	var completed adminExportJob
	for {
		current, ok := exportJobs.Get(job.ID)
		if !ok {
			t.Fatalf("queued job %s absent", job.ID)
		}
		if current.Status == "completed" {
			completed = current
			break
		}
		if current.Status == "failed" || current.Status == "cancelled" {
			t.Fatalf("queued worker terminal status = %#v, want completed", current)
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for queued worker completion; last job = %#v", current)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if completed.RowCount != 1 || completed.ObjectRef == nil || completed.PayloadChecksum == nil {
		t.Fatalf("completed = %#v, want one-row object export", completed)
	}
	cancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v, want context.Canceled", err)
	}
	taskID := "export_task_" + job.ID
	if _, ok := queue.Get(taskID); ok {
		t.Fatalf("task %s still present after worker complete", taskID)
	}
	if len(queue.order) != 0 {
		t.Fatalf("queue order = %#v, want cleaned after worker complete", queue.order)
	}
	auditRows, err := readAuditRowsExcludingWrapper(writer)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if len(auditRows) != 4 || auditRows[0]["event_type"] != "admin_export_requested" || auditRows[1]["event_type"] != "admin_export_task_enqueued" || auditRows[2]["event_type"] != "admin_export_started" || auditRows[3]["event_type"] != "admin_export_completed" {
		t.Fatalf("audit rows = %#v, want queued worker lifecycle", auditRows)
	}
}

func TestLocalQueuedAdminExportWorkerRequiresQueue(t *testing.T) {
	worker := localQueuedAdminExportWorker{}

	_, err := worker.Enqueue(context.Background(), adminExportTask{})

	if err == nil || !strings.Contains(err.Error(), "export task queue is not configured") {
		t.Fatalf("Enqueue error = %v, want missing queue error", err)
	}
}

func TestLocalQueuedAdminExportWorkerRequiresStore(t *testing.T) {
	worker := localQueuedAdminExportWorker{Queue: newLocalAdminExportTaskQueue()}

	_, err := worker.Enqueue(context.Background(), adminExportTask{})

	if err == nil || !strings.Contains(err.Error(), "export job store is not configured") {
		t.Fatalf("Enqueue error = %v, want missing store error", err)
	}
}

func TestLocalQueuedAdminExportWorkerCompletesNonRetryableFailure(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	objectStore, err := objectstore.NewLocalStore(logDir)
	if err != nil {
		t.Fatalf("NewLocalStore returned error: %v", err)
	}
	exportJobs := newAdminExportJobStore()
	queue := newLocalAdminExportTaskQueue()
	worker := localQueuedAdminExportWorker{
		Queue:         queue,
		Timeout:       2 * time.Second,
		LeaseDuration: time.Minute,
		PollInterval:  10 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- worker.Run(ctx)
	}()
	job, err := worker.Enqueue(context.Background(), adminExportTask{
		Writer:      writer,
		ObjectStore: objectStore,
		HotStore:    nil,
		Store:       exportJobs,
		Evaluator:   testEvaluator(),
		Request: adminExportJobRequest{
			Stream: "access",
			Format: "ndjson",
			From:   "2026-05-23T01:00:00Z",
			To:     "2026-05-23T02:00:00Z",
		},
		TenantID:         "tenant_lab_001",
		AdminPrincipalID: "admin_lab_bypass",
		SourceIP:         "127.0.0.1",
		Now:              time.Date(2026, 5, 23, 1, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Enqueue returned error: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	var failed adminExportJob
	for {
		current, ok := exportJobs.Get(job.ID)
		if !ok {
			t.Fatalf("queued job %s absent", job.ID)
		}
		if current.Status == "failed" {
			failed = current
			break
		}
		if current.Status == "completed" || current.Status == "cancelled" {
			t.Fatalf("queued worker terminal status = %#v, want failed", current)
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for queued worker failure; last job = %#v", current)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if failed.ErrorCode == nil || *failed.ErrorCode != "query_failed" {
		t.Fatalf("failed job = %#v, want query_failed", failed)
	}
	cancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v, want context.Canceled", err)
	}
	taskID := "export_task_" + job.ID
	if _, ok := queue.Get(taskID); ok {
		t.Fatalf("non-retryable task %s still present in active queue", taskID)
	}
	if _, ok := queue.GetDeadLetter(taskID); ok {
		t.Fatalf("non-retryable task %s moved to dead letter queue", taskID)
	}
}

func TestLocalQueuedAdminExportWorkerRunPollsUntilCancelled(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	if err := writer.Append("access.log.jsonl", map[string]any{
		"id":         "alog_queue_loop_001",
		"tenant_id":  "tenant_lab_001",
		"event_type": "access_allowed",
		"timestamp":  "2026-05-23T01:10:00Z",
	}); err != nil {
		t.Fatalf("append access log: %v", err)
	}
	objectStore, err := objectstore.NewLocalStore(logDir)
	if err != nil {
		t.Fatalf("NewLocalStore returned error: %v", err)
	}
	exportJobs := newAdminExportJobStore()
	queue := newLocalAdminExportTaskQueue()
	req := adminExportJobRequest{
		Stream: "access",
		Format: "ndjson",
		From:   "2026-05-23T01:00:00Z",
		To:     "2026-05-23T02:00:00Z",
	}
	task := adminExportTask{
		Writer:      writer,
		ObjectStore: objectStore,
		HotStore:    hotstore.NewJSONLStore(writer, adminLogStreamFilenameMap()),
		Store:       exportJobs,
		Evaluator:   testEvaluator(),
		Request:     req,
		TenantID:    "tenant_lab_001",
		SourceIP:    "127.0.0.1",
	}
	job, document, err := createQueuedAdminExportJob(context.Background(), writer, nil, exportJobs, testEvaluator(), req, "tenant_lab_001", "admin_lab_bypass", "127.0.0.1", time.Date(2026, 5, 23, 1, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("createQueuedAdminExportJob returned error: %v", err)
	}
	if err := queue.Enqueue(adminExportQueuedTask{Document: document, Task: task, Job: job}); err != nil {
		t.Fatalf("queue.Enqueue returned error: %v", err)
	}
	worker := localQueuedAdminExportWorker{
		Queue:         queue,
		Timeout:       2 * time.Second,
		LeaseDuration: time.Minute,
		PollInterval:  10 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- worker.Run(ctx)
	}()

	deadline := time.Now().Add(2 * time.Second)
	var completed adminExportJob
	for {
		current, ok := exportJobs.Get(job.ID)
		if !ok {
			t.Fatalf("queued job %s absent", job.ID)
		}
		if current.Status == "completed" {
			completed = current
			break
		}
		if current.Status == "failed" || current.Status == "cancelled" {
			t.Fatalf("queued loop terminal status = %#v, want completed", current)
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for queued loop completion; last job = %#v", current)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v, want context.Canceled", err)
	}
	if completed.RowCount != 1 || completed.ObjectRef == nil || completed.PayloadChecksum == nil {
		t.Fatalf("completed = %#v, want one-row object export", completed)
	}
	if _, ok := queue.Get(document.ID); ok {
		t.Fatalf("task %s still present after Run complete", document.ID)
	}
}

func TestAdminExportWorkerShouldRetryUsesPolicy(t *testing.T) {
	policy := defaultAdminExportWorkerRetryPolicy()

	if !adminExportWorkerShouldRetry(policy, "worker_context_cancelled") {
		t.Fatalf("worker_context_cancelled should be retryable")
	}
	if adminExportWorkerShouldRetry(policy, "query_failed") {
		t.Fatalf("query_failed should be non-retryable")
	}
	if adminExportWorkerShouldRetry(policy, "unknown_error") {
		t.Fatalf("unknown_error should not be retried")
	}
}

func TestAdminExportPathRejectsUnsafeSegments(t *testing.T) {
	job := adminExportJob{
		ID:        "export_001",
		TenantID:  "tenant_lab_001",
		Format:    "ndjson",
		CreatedAt: "2026-05-23T01:00:00Z",
	}
	if _, err := adminExportLocalFilename(job); err != nil {
		t.Fatalf("adminExportLocalFilename returned error: %v", err)
	}
	job.TenantID = "../tenant_other"
	if _, err := adminExportLocalFilename(job); err == nil {
		t.Fatalf("adminExportLocalFilename accepted unsafe tenant id")
	}
	job.TenantID = "tenant_lab_001"
	job.ID = "export/001"
	if _, err := adminExportObjectRef(job); err == nil {
		t.Fatalf("adminExportObjectRef accepted unsafe job id")
	}
}

func TestAdminExportJobCancelQueuedJob(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	exportJobs := newAdminExportJobStore()
	created := exportJobs.Create(adminExportJobRequest{
		Stream: "access",
		Format: "ndjson",
		From:   "2026-05-23T00:00:00Z",
		To:     "2026-05-23T01:00:00Z",
	}, "tenant_lab_001", "admin_lab_bypass", time.Date(2026, 5, 23, 1, 0, 0, 0, time.UTC))
	outbox := &recordingAdminAuditOutboxDeadReader{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		Registry:         connector.NewRegistry(),
		AdminExportJobs:  exportJobs,
		AdminAuditOutbox: outbox,
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/export-jobs/"+created.ID+"/cancel", strings.NewReader(`{"reason":"operator requested"}`))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var job adminExportJob
	if err := json.NewDecoder(rec.Body).Decode(&job); err != nil {
		t.Fatalf("decode job: %v", err)
	}
	if job.Status != "cancelled" || job.ErrorCode == nil || *job.ErrorCode != "cancelled" || job.CompletedAt == nil {
		t.Fatalf("job = %#v, want cancelled terminal state", job)
	}
	if job.Metadata["cancelled_by_admin_principal_id"] != "admin_lab_bypass" || job.Metadata["cancellation_reason"] != "operator requested" {
		t.Fatalf("metadata = %#v", job.Metadata)
	}
	auditRows, err := readAuditRowsExcludingWrapper(writer)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if len(auditRows) != 1 || auditRows[0]["event_type"] != "admin_export_cancelled" {
		t.Fatalf("audit rows = %#v, want cancellation audit", auditRows)
	}
	if !auditLogEventTypes(outbox.insertedAudits)["admin_export_cancelled"] {
		t.Fatalf("outbox inserted audits = %#v, want admin_export_cancelled", outbox.insertedAudits)
	}
}

func TestAdminExportJobCancelRequiresOwnershipForAnalyst(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	adminAuth := newAdminAuthStore()
	adminAuth.UpsertPrincipal(adminPrincipal{
		ID:        "admin_analyst_001",
		TenantID:  "tenant_lab_001",
		Subject:   "sub_analyst_001",
		Email:     "analyst@example.jp",
		Roles:     []string{"analyst"},
		IDPID:     "keycloak_lab",
		Status:    "active",
		CreatedAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
	})
	adminAuth.UpsertSession(adminSession{
		ID:               "admin_sess_analyst_cancel_001",
		TenantID:         "tenant_lab_001",
		AdminPrincipalID: "admin_analyst_001",
		Subject:          "sub_analyst_001",
		Roles:            []string{"analyst"},
		AuthTime:         time.Now().UTC().Add(-time.Minute).Format(time.RFC3339),
		MFAState:         "fresh",
		CreatedAt:        time.Now().UTC().Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt:        time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		LastActiveAt:     time.Now().UTC().Format(time.RFC3339),
		Status:           "active",
		Metadata:         map[string]any{adminCSRFTokenKey: "csrf-analyst-cancel"},
	})
	exportJobs := newAdminExportJobStore()
	otherJob := exportJobs.Create(adminExportJobRequest{
		Stream: "access",
		Format: "ndjson",
		From:   "2026-05-23T00:00:00Z",
		To:     "2026-05-23T02:00:00Z",
	}, "tenant_lab_001", "admin_other_001", time.Date(2026, 5, 23, 1, 0, 0, 0, time.UTC))
	ownJob := exportJobs.Create(adminExportJobRequest{
		Stream: "access",
		Format: "ndjson",
		From:   "2026-05-23T00:00:00Z",
		To:     "2026-05-23T02:00:00Z",
	}, "tenant_lab_001", "admin_analyst_001", time.Date(2026, 5, 23, 1, 1, 0, 0, time.UTC))
	outbox := &recordingAdminAuditOutboxDeadReader{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		Registry:         connector.NewRegistry(),
		AdminAuth:        adminAuth,
		AdminExportJobs:  exportJobs,
		AdminAuditOutbox: outbox,
	})

	req := httptest.NewRequest(http.MethodPost, "/admin/export-jobs/"+otherJob.ID+"/cancel", strings.NewReader(`{"reason":"not mine"}`))
	req.AddCookie(&http.Cookie{Name: "admin_session", Value: "admin_sess_analyst_cancel_001"})
	req.Header.Set("x-csrf-token", "csrf-analyst-cancel")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cancel other job status = %d, want %d, body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	auditRows, err := readAuditRowsExcludingWrapper(writer)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if len(auditRows) != 1 || auditRows[0]["event_type"] != "admin_rbac_denied" || auditRows[0]["tenant_id"] != "tenant_lab_001" {
		t.Fatalf("audit rows = %#v, want tenant-scoped RBAC denial", auditRows)
	}
	deniedMetadata := auditRows[0]["metadata"].(map[string]any)
	if deniedMetadata["target_tenant_id"] != "tenant_lab_001" || deniedMetadata["export_job_id"] != otherJob.ID {
		t.Fatalf("denied metadata = %#v", deniedMetadata)
	}
	if !auditLogEventTypes(outbox.insertedAudits)["admin_rbac_denied"] {
		t.Fatalf("outbox inserted audits = %#v, want admin_rbac_denied", outbox.insertedAudits)
	}

	req = httptest.NewRequest(http.MethodPost, "/admin/export-jobs/"+ownJob.ID+"/cancel", strings.NewReader(`{"reason":"mine"}`))
	req.AddCookie(&http.Cookie{Name: "admin_session", Value: "admin_sess_analyst_cancel_001"})
	req.Header.Set("x-csrf-token", "csrf-analyst-cancel")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("cancel own job status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var cancelled adminExportJob
	if err := json.NewDecoder(rec.Body).Decode(&cancelled); err != nil {
		t.Fatalf("decode cancelled job: %v", err)
	}
	if cancelled.Status != "cancelled" || cancelled.CreatedByAdminPrincipalID != "admin_analyst_001" {
		t.Fatalf("cancelled = %#v, want analyst-owned cancelled job", cancelled)
	}
}

func TestAdminExportJobCancelAdminCanCancelOthersJob(t *testing.T) {
	if !adminPermissionAllowed([]string{"admin"}, "admin.export.cancel.all") {
		t.Fatalf("admin role should have admin.export.cancel.all")
	}
	if adminPermissionAllowed([]string{"analyst"}, "admin.export.cancel.all") {
		t.Fatalf("analyst role should not have admin.export.cancel.all")
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	adminAuth := newAdminAuthStore()
	adminAuth.UpsertPrincipal(adminPrincipal{
		ID:        "admin_user_cancel_001",
		TenantID:  "tenant_lab_001",
		Subject:   "sub_admin_cancel_001",
		Email:     "admin-cancel@example.jp",
		Roles:     []string{"admin"},
		IDPID:     "keycloak_lab",
		Status:    "active",
		CreatedAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
	})
	adminAuth.UpsertSession(adminSession{
		ID:               "admin_sess_admin_cancel_001",
		TenantID:         "tenant_lab_001",
		AdminPrincipalID: "admin_user_cancel_001",
		Subject:          "sub_admin_cancel_001",
		Roles:            []string{"admin"},
		AuthTime:         time.Now().UTC().Add(-time.Minute).Format(time.RFC3339),
		MFAState:         "fresh",
		CreatedAt:        time.Now().UTC().Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt:        time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		LastActiveAt:     time.Now().UTC().Format(time.RFC3339),
		Status:           "active",
		Metadata:         map[string]any{adminCSRFTokenKey: "csrf-admin-cancel"},
	})
	exportJobs := newAdminExportJobStore()
	otherJob := exportJobs.Create(adminExportJobRequest{
		Stream: "access",
		Format: "ndjson",
		From:   "2026-05-23T00:00:00Z",
		To:     "2026-05-23T02:00:00Z",
	}, "tenant_lab_001", "admin_other_001", time.Date(2026, 5, 23, 1, 2, 0, 0, time.UTC))
	handler := newServerWithConfig(serverConfig{
		Evaluator:       testEvaluator(),
		Writer:          writer,
		Registry:        connector.NewRegistry(),
		AdminAuth:       adminAuth,
		AdminExportJobs: exportJobs,
	})

	req := httptest.NewRequest(http.MethodPost, "/admin/export-jobs/"+otherJob.ID+"/cancel", strings.NewReader(`{"reason":"admin override"}`))
	req.AddCookie(&http.Cookie{Name: "admin_session", Value: "admin_sess_admin_cancel_001"})
	req.Header.Set("x-csrf-token", "csrf-admin-cancel")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("cancel other job as admin status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var cancelled adminExportJob
	if err := json.NewDecoder(rec.Body).Decode(&cancelled); err != nil {
		t.Fatalf("decode cancelled job: %v", err)
	}
	if cancelled.Status != "cancelled" || cancelled.CreatedByAdminPrincipalID != "admin_other_001" {
		t.Fatalf("cancelled = %#v, want other admin user's cancelled job", cancelled)
	}
}

func TestAdminExportJobStopsGracefullyWhenProgressSeesCancelledJob(t *testing.T) {
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
	exportJobs := newAdminExportJobStore()
	hotStore := &cancellingHotStore{
		jobStore: exportJobs,
	}

	job, err := createAndCompleteAdminExportJob(context.Background(), writer, nil, objectStore, hotStore, exportJobs, testEvaluator(), adminExportJobRequest{
		Stream:  "access",
		Format:  "ndjson",
		Filters: map[string]string{"event_type": "access_allowed"},
		From:    "2026-05-23T00:00:00Z",
		To:      "2026-05-23T02:00:00Z",
	}, "tenant_lab_001", "admin_lab_bypass", "127.0.0.1", now)
	if err != nil {
		t.Fatalf("createAndCompleteAdminExportJob returned error: %v", err)
	}
	if job.Status != "cancelled" {
		t.Fatalf("job = %#v, want graceful cancelled job", job)
	}
	matches, err := filepath.Glob(filepath.Join(logDir, "exports", "tenant_lab_001", "*", "*", "*", "*.ndjson.gz"))
	if err != nil {
		t.Fatalf("glob export files: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("partial export files = %#v, want cleanup after stopped job", matches)
	}
}

func TestAdminExportJobMarksFailedWhenWorkerContextIsCancelled(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	objectStore, err := objectstore.NewLocalStore(logDir)
	if err != nil {
		t.Fatalf("NewLocalStore returned error: %v", err)
	}
	now := time.Date(2026, 5, 23, 1, 10, 0, 0, time.UTC)
	exportJobs := newAdminExportJobStore()
	ctx, cancel := context.WithCancel(context.Background())
	hotStore := &contextCancellingHotStore{cancel: cancel}

	_, err = createAndCompleteAdminExportJob(ctx, writer, nil, objectStore, hotStore, exportJobs, testEvaluator(), adminExportJobRequest{
		Stream:  "access",
		Format:  "ndjson",
		Filters: map[string]string{"event_type": "access_allowed"},
		From:    "2026-05-23T00:00:00Z",
		To:      "2026-05-23T02:00:00Z",
	}, "tenant_lab_001", "admin_lab_bypass", "127.0.0.1", now)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	jobs := exportJobs.List("tenant_lab_001")
	if len(jobs) != 1 {
		t.Fatalf("jobs = %#v, want one recorded job", jobs)
	}
	job := jobs[0]
	if job.Status != "failed" || job.ErrorCode == nil || *job.ErrorCode != "worker_context_cancelled" {
		t.Fatalf("job = %#v, want failed worker_context_cancelled", job)
	}
	matches, err := filepath.Glob(filepath.Join(logDir, "exports", "tenant_lab_001", "*", "*", "*", "*.ndjson.gz"))
	if err != nil {
		t.Fatalf("glob export files: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("partial export files = %#v, want cleanup after worker context cancellation", matches)
	}
}

func TestAdminExportJobStoreRejectsInvalidStatusTransitions(t *testing.T) {
	store := newAdminExportJobStore()
	now := time.Date(2026, 5, 23, 1, 0, 0, 0, time.UTC)
	job := store.Create(adminExportJobRequest{
		Stream: "access",
		Format: "ndjson",
		From:   "2026-05-23T00:00:00Z",
		To:     "2026-05-23T01:00:00Z",
	}, "tenant_lab_001", "admin_lab_bypass", now)

	if _, err := store.MarkCompleted(job.ID, 1, 1, false, "evidence://tenant/tenant_lab_001/export.ndjson.gz", "sha256:test", nil, now); err == nil {
		t.Fatalf("MarkCompleted from queued returned nil error")
	}
	running, err := store.MarkRunning(job.ID, now)
	if err != nil {
		t.Fatalf("MarkRunning returned error: %v", err)
	}
	completed, err := store.MarkCompleted(running.ID, 1, 1, false, "evidence://tenant/tenant_lab_001/export.ndjson.gz", "sha256:test", nil, now)
	if err != nil {
		t.Fatalf("MarkCompleted returned error: %v", err)
	}
	if _, err := store.MarkRunning(completed.ID, now); err == nil {
		t.Fatalf("MarkRunning from completed returned nil error")
	}
	if _, err := store.MarkFailed(completed.ID, "late_failure", now); err == nil {
		t.Fatalf("MarkFailed from completed returned nil error")
	}
}
