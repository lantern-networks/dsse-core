package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	_ "net/http/pprof" // DIAGNOSTIC: registers /debug/pprof on http.DefaultServeMux; served only when -pprof-listen is set
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"

	// The IANA timezone database, compiled in. The runtime image is FROM scratch, so there is no
	// /usr/share/zoneinfo and time.LoadLocation would fail for EVERY zone — including the ones an operator
	// just typed into the Console. Validation that passes on a developer's machine and rejects everything in
	// the container is worse than no validation, because it looks like the operator's mistake.
	_ "time/tzdata"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/hotstore"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

type adminExportObjectStore interface {
	WriteGzipJSONL(filename string, values []map[string]any) (string, error)
	WriteGzipJSONLStream(filename string, next func() (map[string]any, bool, error)) (string, error)
	ReadGeneratedFile(filename string) ([]byte, error)
	ListGeneratedFiles(prefix, suffix string, limit int) ([]string, error)
}

type adminExportWorker interface {
	Enqueue(ctx context.Context, task adminExportTask) (adminExportJob, error)
}

type synchronousAdminExportWorker struct{}

type localAsyncAdminExportWorker struct {
	Timeout time.Duration
}

type localQueuedAdminExportWorker struct {
	Queue         adminExportTaskQueue
	Timeout       time.Duration
	LeaseDuration time.Duration
	PollInterval  time.Duration
}

type postgresQueueAdminExportWorker struct {
	Queue                   postgresExportTaskQueueAdapter
	DB                      *sql.DB
	DisableDirectAuditJSONL bool
}

type adminExportTaskQueue interface {
	Enqueue(adminExportQueuedTask) error
	Lease(time.Time, time.Duration) (adminExportQueuedTask, bool)
	Complete(string) error
	Release(string) error
	ExtendLease(string, time.Time, time.Duration) (adminExportQueuedTask, error)
	Retry(string, time.Time) (adminExportQueuedTask, bool, error)
}

type adminExportQueuedTask struct {
	Document adminExportWorkerTaskDocument
	Task     adminExportTask
	Job      adminExportJob
}

type localAdminExportTaskQueue struct {
	mu          sync.RWMutex
	tasks       map[string]adminExportQueuedTask
	deadLetters map[string]adminExportQueuedTask
	order       []string
}

type adminExportTask struct {
	Writer           *logs.Writer
	AdminAuditOutbox adminAuditOutboxDeadReader
	ObjectStore      adminExportObjectStore
	HotStore         hotstore.Store
	Store            adminExportJobRuntimeStore
	Evaluator        decision.Evaluator
	Request          adminExportJobRequest
	TenantID         string
	AdminPrincipalID string
	SourceIP         string
	Now              time.Time
}

type adminExportWorkerTaskDocument struct {
	ID                        string                       `json:"id"`
	TenantID                  string                       `json:"tenant_id"`
	ExportJobID               string                       `json:"export_job_id"`
	CreatedByAdminPrincipalID string                       `json:"created_by_admin_principal_id"`
	IdempotencyKey            string                       `json:"idempotency_key"`
	Stream                    string                       `json:"stream"`
	Format                    string                       `json:"format"`
	Filters                   map[string]string            `json:"filters"`
	From                      string                       `json:"from"`
	To                        string                       `json:"to"`
	Limit                     int                          `json:"limit"`
	OutputRefPrefix           string                       `json:"output_ref_prefix"`
	RequestedAt               string                       `json:"requested_at"`
	StartedAt                 *string                      `json:"started_at"`
	LeaseExpiresAt            *string                      `json:"lease_expires_at"`
	TimeoutSeconds            int                          `json:"timeout_seconds"`
	CancelCheckIntervalRows   int                          `json:"cancel_check_interval_rows"`
	RetryPolicy               adminExportWorkerRetryPolicy `json:"retry_policy"`
	Attempt                   int                          `json:"attempt"`
	MaxAttempts               int                          `json:"max_attempts"`
	Status                    string                       `json:"status"`
	TraceID                   *string                      `json:"trace_id"`
	SourceIP                  *string                      `json:"source_ip"`
	Metadata                  map[string]any               `json:"metadata"`
}

type adminExportWorkerRetryPolicy struct {
	RetryableErrorCodes    []string `json:"retryable_error_codes"`
	NonRetryableErrorCodes []string `json:"non_retryable_error_codes"`
	BackoffSeconds         []int    `json:"backoff_seconds"`
}

const (
	defaultAdminExportWorkerTimeoutSeconds          = 3600
	defaultAdminExportWorkerCancelCheckIntervalRows = 1000
	defaultAdminExportWorkerMaxAttempts             = 3
	// Fail closed when a worker error cannot be mapped from Job Store state.
	adminExportWorkerDefaultErrorCode = "write_failed"
)

func (worker synchronousAdminExportWorker) Enqueue(ctx context.Context, task adminExportTask) (adminExportJob, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return adminExportJob{}, err
	}
	producer, err := adminExportProducerStore(task.Store)
	if err != nil {
		return adminExportJob{}, err
	}
	return createAndCompleteAdminExportJob(ctx, task.Writer, task.AdminAuditOutbox, task.ObjectStore, task.HotStore, producer, task.Evaluator, task.Request, task.TenantID, task.AdminPrincipalID, task.SourceIP, task.Now)
}

func (worker localAsyncAdminExportWorker) Enqueue(ctx context.Context, task adminExportTask) (adminExportJob, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return adminExportJob{}, err
	}
	producer, err := adminExportProducerStore(task.Store)
	if err != nil {
		return adminExportJob{}, err
	}
	job, _, err := createQueuedAdminExportJob(ctx, task.Writer, task.AdminAuditOutbox, producer, task.Evaluator, task.Request, task.TenantID, task.AdminPrincipalID, task.SourceIP, task.Now)
	if err != nil {
		return adminExportJob{}, err
	}
	timeout := worker.Timeout
	if timeout <= 0 {
		timeout = time.Duration(defaultAdminExportWorkerTimeoutSeconds) * time.Second
	}
	go func() {
		workerCtx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		_, _ = runAdminExportJob(workerCtx, task.Writer, task.AdminAuditOutbox, task.ObjectStore, task.HotStore, task.Store, task.Evaluator, job, task.Request, task.SourceIP, time.Now())
	}()
	return job, nil
}

func (worker localQueuedAdminExportWorker) Enqueue(ctx context.Context, task adminExportTask) (adminExportJob, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return adminExportJob{}, err
	}
	queue := worker.Queue
	if queue == nil {
		return adminExportJob{}, fmt.Errorf("export task queue is not configured")
	}
	if task.Store == nil {
		return adminExportJob{}, fmt.Errorf("export job store is not configured")
	}
	producer, err := adminExportProducerStore(task.Store)
	if err != nil {
		return adminExportJob{}, err
	}
	job, document, err := createQueuedAdminExportJob(ctx, task.Writer, task.AdminAuditOutbox, producer, task.Evaluator, task.Request, task.TenantID, task.AdminPrincipalID, task.SourceIP, task.Now)
	if err != nil {
		return adminExportJob{}, err
	}
	if err := queue.Enqueue(adminExportQueuedTask{Document: document, Task: task, Job: job}); err != nil {
		return adminExportJob{}, err
	}
	return job, nil
}

func (worker postgresQueueAdminExportWorker) Enqueue(ctx context.Context, task adminExportTask) (adminExportJob, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return adminExportJob{}, err
	}
	if worker.DB != nil {
		return worker.enqueueTransactional(ctx, task)
	}
	if worker.Queue.DB == nil {
		return adminExportJob{}, fmt.Errorf("postgres export task queue db is not configured")
	}
	if task.Store == nil {
		return adminExportJob{}, fmt.Errorf("export job store is not configured")
	}
	producer, err := adminExportProducerStore(task.Store)
	if err != nil {
		return adminExportJob{}, err
	}
	job, document, err := createQueuedAdminExportJob(ctx, task.Writer, task.AdminAuditOutbox, producer, task.Evaluator, task.Request, task.TenantID, task.AdminPrincipalID, task.SourceIP, task.Now)
	if err != nil {
		return adminExportJob{}, err
	}
	if err := worker.Queue.Enqueue(ctx, adminExportQueuedTask{Document: document}); err != nil {
		failed, markErr := task.Store.MarkFailed(job.ID, "queue_enqueue_failed", time.Now())
		if markErr == nil && task.Writer != nil {
			_ = appendAdminAudit(ctx, task.Writer, task.AdminAuditOutbox, adminExportJobAuditLog("admin_export_failed", failed, task.Evaluator, task.SourceIP), time.Now())
		}
		if markErr != nil {
			return adminExportJob{}, fmt.Errorf("enqueue export task: %w; mark job failed: %v", err, markErr)
		}
		return adminExportJob{}, err
	}
	return job, nil
}

func (worker postgresQueueAdminExportWorker) enqueueTransactional(ctx context.Context, task adminExportTask) (adminExportJob, error) {
	if worker.DB == nil {
		return adminExportJob{}, fmt.Errorf("postgres export task queue db is not configured")
	}
	if task.Store == nil {
		return adminExportJob{}, fmt.Errorf("export job store is not configured")
	}
	switch task.Store.(type) {
	case postgresAdminExportJobStore, *postgresAdminExportJobStore:
	default:
		return adminExportJob{}, fmt.Errorf("postgres queue producer requires postgres export job store")
	}
	if err := validateAdminExportJobRequest(task.Request); err != nil {
		return adminExportJob{}, err
	}
	now := task.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	job := newAdminExportJob(task.Request, task.TenantID, task.AdminPrincipalID, now)
	document, err := adminExportWorkerTaskDocumentFromJob(job, task.Request, task.SourceIP)
	if err != nil {
		return adminExportJob{}, err
	}
	requestedAudit := adminExportJobAuditLog("admin_export_requested", job, task.Evaluator, task.SourceIP)
	taskAudit := adminExportWorkerTaskAuditLog(document, task.Evaluator, task.SourceIP)
	requestedOutbox, err := buildPostgresAdminAuditOutboxInsertStatement(requestedAudit, now)
	if err != nil {
		return adminExportJob{}, err
	}
	taskOutbox, err := buildPostgresAdminAuditOutboxInsertStatement(taskAudit, now)
	if err != nil {
		return adminExportJob{}, err
	}
	tx, err := worker.DB.BeginTx(ctx, nil)
	if err != nil {
		return adminExportJob{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	jobStatement, err := buildPostgresAdminExportJobUpsertStatement(job, now)
	if err != nil {
		return adminExportJob{}, err
	}
	if _, err := tx.ExecContext(ctx, jobStatement.SQL, jobStatement.Args...); err != nil {
		return adminExportJob{}, err
	}
	queueAdapter := worker.Queue
	queueAdapter.DB = postgresExportTaskTxDB{Tx: tx}
	if err := queueAdapter.Enqueue(ctx, adminExportQueuedTask{Document: document}); err != nil {
		return adminExportJob{}, err
	}
	if _, err := tx.ExecContext(ctx, requestedOutbox.SQL, requestedOutbox.Args...); err != nil {
		return adminExportJob{}, err
	}
	if _, err := tx.ExecContext(ctx, taskOutbox.SQL, taskOutbox.Args...); err != nil {
		return adminExportJob{}, err
	}
	if err := tx.Commit(); err != nil {
		return adminExportJob{}, err
	}
	committed = true
	if worker.DisableDirectAuditJSONL {
		return job, nil
	}
	if err := task.Writer.Append("audit.log.jsonl", requestedAudit); err != nil {
		log.Printf("admin export audit jsonl write after commit failed event_type=%s job_id=%s: %v", requestedAudit.EventType, job.ID, err)
	}
	if err := task.Writer.Append("audit.log.jsonl", taskAudit); err != nil {
		log.Printf("admin export audit jsonl write after commit failed event_type=%s job_id=%s: %v", taskAudit.EventType, job.ID, err)
	}
	return job, nil
}

func adminExportProducerStore(store adminExportJobRuntimeStore) (adminExportJobProducerStore, error) {
	if store == nil {
		return nil, fmt.Errorf("export job store is not configured")
	}
	producer, ok := store.(adminExportJobProducerStore)
	if !ok {
		return nil, fmt.Errorf("export job store does not support producer operations")
	}
	return producer, nil
}

func (worker localQueuedAdminExportWorker) Run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	queue := worker.Queue
	if queue == nil {
		return fmt.Errorf("export task queue is not configured")
	}
	pollInterval := worker.PollInterval
	if pollInterval <= 0 {
		pollInterval = 100 * time.Millisecond
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if worker.runOne(queue) {
			continue
		}
		timer := time.NewTimer(pollInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (worker localQueuedAdminExportWorker) runOne(queue adminExportTaskQueue) bool {
	leaseDuration := worker.LeaseDuration
	if leaseDuration <= 0 {
		leaseDuration = 30 * time.Second
	}
	item, ok := queue.Lease(time.Now(), leaseDuration)
	if !ok {
		return false
	}
	timeout := worker.Timeout
	if timeout <= 0 {
		timeout = time.Duration(defaultAdminExportWorkerTimeoutSeconds) * time.Second
	}
	workerCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_, err := runAdminExportJob(workerCtx, item.Task.Writer, item.Task.AdminAuditOutbox, item.Task.ObjectStore, item.Task.HotStore, item.Task.Store, item.Task.Evaluator, item.Job, item.Task.Request, item.Task.SourceIP, time.Now())
	if err != nil {
		errorCode := adminExportWorkerJobErrorCode(item.Task.Store, item.Job.ID, adminExportWorkerDefaultErrorCode)
		// Phase 1 runAdminExportJob usually terminalizes failures before returning.
		// The Retry branch is the Alpha Worker contract for pre-terminal transient failures.
		if adminExportWorkerShouldRetry(item.Document.RetryPolicy, errorCode) && adminExportWorkerJobRetryable(item.Task.Store, item.Job.ID) {
			retried, queued, retryErr := queue.Retry(item.Document.ID, time.Now())
			if retryErr == nil && !queued {
				adminExportMarkDeadLettered(retried, time.Now())
			}
			return true
		}
		_ = queue.Complete(item.Document.ID)
		return true
	}
	_ = queue.Complete(item.Document.ID)
	return true
}

func adminExportMarkDeadLettered(item adminExportQueuedTask, now time.Time) {
	if item.Task.Store == nil || item.Task.Writer == nil {
		return
	}
	reason := strings.TrimSpace(stringMetadata(item.Document.Metadata, "dead_letter_reason"))
	if reason == "" {
		reason = "max_attempts_exhausted"
	}
	metadata := map[string]any{
		"export_worker_task_id": item.Document.ID,
		"attempt":               item.Document.Attempt,
		"max_attempts":          item.Document.MaxAttempts,
	}
	for key, value := range item.Document.Metadata {
		if strings.TrimSpace(key) != "" {
			metadata[key] = value
		}
	}
	failed, err := item.Task.Store.MarkFailedWithMetadata(item.Job.ID, reason, metadata, now)
	if err != nil {
		_ = appendAdminAudit(context.Background(), item.Task.Writer, item.Task.AdminAuditOutbox, adminExportDeadLetterBridgeFailureAuditLog(item, reason, err.Error(), now), now)
		return
	}
	_ = appendAdminAudit(context.Background(), item.Task.Writer, item.Task.AdminAuditOutbox, adminExportJobAuditLog("admin_export_failed", failed, item.Task.Evaluator, item.Task.SourceIP), now)
}

func adminExportWorkerJobErrorCode(store adminExportJobRuntimeStore, jobID, fallback string) string {
	if store != nil {
		if job, ok := store.Get(jobID); ok && job.ErrorCode != nil && strings.TrimSpace(*job.ErrorCode) != "" {
			return strings.TrimSpace(*job.ErrorCode)
		}
	}
	return strings.TrimSpace(fallback)
}

func adminExportWorkerJobRetryable(store adminExportJobRuntimeStore, jobID string) bool {
	if store == nil {
		return false
	}
	job, ok := store.Get(jobID)
	if !ok {
		return false
	}
	return job.Status == "queued" || job.Status == "running"
}

func adminExportWorkerShouldRetry(policy adminExportWorkerRetryPolicy, errorCode string) bool {
	errorCode = strings.TrimSpace(errorCode)
	if errorCode == "" {
		return false
	}
	if stringSliceContains(policy.NonRetryableErrorCodes, errorCode) {
		return false
	}
	return stringSliceContains(policy.RetryableErrorCodes, errorCode)
}

func newLocalAdminExportTaskQueue() *localAdminExportTaskQueue {
	return &localAdminExportTaskQueue{
		tasks:       map[string]adminExportQueuedTask{},
		deadLetters: map[string]adminExportQueuedTask{},
	}
}

func (queue *localAdminExportTaskQueue) Enqueue(item adminExportQueuedTask) error {
	if queue == nil {
		return fmt.Errorf("export task queue is not configured")
	}
	id := strings.TrimSpace(item.Document.ID)
	if id == "" {
		return fmt.Errorf("export task id is required")
	}
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if queue.tasks == nil {
		queue.tasks = map[string]adminExportQueuedTask{}
	}
	if queue.deadLetters == nil {
		queue.deadLetters = map[string]adminExportQueuedTask{}
	}
	if _, exists := queue.tasks[id]; !exists {
		queue.order = append(queue.order, id)
	}
	item.Document.Status = "queued"
	item.Document.LeaseExpiresAt = nil
	queue.tasks[id] = item
	return nil
}

func (queue *localAdminExportTaskQueue) Lease(now time.Time, leaseDuration time.Duration) (adminExportQueuedTask, bool) {
	if queue == nil {
		return adminExportQueuedTask{}, false
	}
	if leaseDuration <= 0 {
		leaseDuration = 30 * time.Second
	}
	queue.mu.Lock()
	defer queue.mu.Unlock()
	for _, id := range queue.order {
		item, ok := queue.tasks[id]
		if !ok || item.Document.Status != "queued" {
			continue
		}
		if !adminExportQueuedTaskReadyForLease(item, now) {
			continue
		}
		leaseExpiresAt := now.UTC().Add(leaseDuration).Format(time.RFC3339)
		item.Document.Status = "running"
		item.Document.LeaseExpiresAt = &leaseExpiresAt
		queue.tasks[id] = item
		return item, true
	}
	return adminExportQueuedTask{}, false
}

func (queue *localAdminExportTaskQueue) Complete(id string) error {
	if queue == nil {
		return fmt.Errorf("export task queue is not configured")
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("export task id is required")
	}
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if _, ok := queue.tasks[id]; !ok {
		return fmt.Errorf("export task %s is absent", id)
	}
	delete(queue.tasks, id)
	queue.removeOrderIDLocked(id)
	return nil
}

func (queue *localAdminExportTaskQueue) Release(id string) error {
	if queue == nil {
		return fmt.Errorf("export task queue is not configured")
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("export task id is required")
	}
	queue.mu.Lock()
	defer queue.mu.Unlock()
	item, ok := queue.tasks[id]
	if !ok {
		return fmt.Errorf("export task %s is absent", id)
	}
	item.Document.Status = "queued"
	item.Document.LeaseExpiresAt = nil
	queue.removeOrderIDLocked(id)
	queue.order = append(queue.order, id)
	queue.tasks[id] = item
	return nil
}

func (queue *localAdminExportTaskQueue) ExtendLease(id string, now time.Time, leaseDuration time.Duration) (adminExportQueuedTask, error) {
	if queue == nil {
		return adminExportQueuedTask{}, fmt.Errorf("export task queue is not configured")
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return adminExportQueuedTask{}, fmt.Errorf("export task id is required")
	}
	if leaseDuration <= 0 {
		leaseDuration = 30 * time.Second
	}
	queue.mu.Lock()
	defer queue.mu.Unlock()
	item, ok := queue.tasks[id]
	if !ok {
		return adminExportQueuedTask{}, fmt.Errorf("export task %s is absent", id)
	}
	if item.Document.Status != "running" {
		return adminExportQueuedTask{}, fmt.Errorf("export task %s cannot extend lease while %s", id, item.Document.Status)
	}
	leaseExpiresAt := now.UTC().Add(leaseDuration).Format(time.RFC3339)
	item.Document.LeaseExpiresAt = &leaseExpiresAt
	if item.Document.Metadata == nil {
		item.Document.Metadata = map[string]any{}
	}
	item.Document.Metadata["lease_extended_at"] = now.UTC().Format(time.RFC3339)
	queue.tasks[id] = item
	return item, nil
}

func (queue *localAdminExportTaskQueue) Retry(id string, now time.Time) (adminExportQueuedTask, bool, error) {
	if queue == nil {
		return adminExportQueuedTask{}, false, fmt.Errorf("export task queue is not configured")
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return adminExportQueuedTask{}, false, fmt.Errorf("export task id is required")
	}
	queue.mu.Lock()
	defer queue.mu.Unlock()
	item, ok := queue.tasks[id]
	if !ok {
		return adminExportQueuedTask{}, false, fmt.Errorf("export task %s is absent", id)
	}
	failedAttempt := item.Document.Attempt
	nextAttempt := failedAttempt + 1
	if nextAttempt >= item.Document.MaxAttempts {
		item.Document.Status = "failed"
		item.Document.LeaseExpiresAt = nil
		if item.Document.Metadata == nil {
			item.Document.Metadata = map[string]any{}
		}
		item.Document.Metadata["dead_lettered_at"] = now.UTC().Format(time.RFC3339)
		item.Document.Metadata["dead_letter_reason"] = "max_attempts_exhausted"
		delete(queue.tasks, id)
		queue.removeOrderIDLocked(id)
		if queue.deadLetters == nil {
			queue.deadLetters = map[string]adminExportQueuedTask{}
		}
		queue.deadLetters[id] = item
		return item, false, nil
	}
	item.Document.Attempt = nextAttempt
	item.Document.Status = "queued"
	item.Document.LeaseExpiresAt = nil
	if item.Document.Metadata == nil {
		item.Document.Metadata = map[string]any{}
	}
	backoffSeconds := adminExportWorkerRetryBackoffSeconds(item.Document.RetryPolicy, failedAttempt)
	item.Document.Metadata["retry_scheduled_at"] = now.UTC().Format(time.RFC3339)
	item.Document.Metadata["retry_backoff_seconds"] = backoffSeconds
	item.Document.Metadata["retry_not_before"] = now.UTC().Add(time.Duration(backoffSeconds) * time.Second).Format(time.RFC3339)
	queue.removeOrderIDLocked(id)
	queue.order = append(queue.order, id)
	queue.tasks[id] = item
	return item, true, nil
}

func adminExportQueuedTaskReadyForLease(item adminExportQueuedTask, now time.Time) bool {
	if item.Document.Metadata == nil {
		return true
	}
	raw, ok := item.Document.Metadata["retry_not_before"]
	if !ok {
		return true
	}
	notBefore, err := time.Parse(time.RFC3339, strings.TrimSpace(fmt.Sprint(raw)))
	if err != nil {
		return true
	}
	return !now.UTC().Before(notBefore)
}

func adminExportWorkerRetryBackoffSeconds(policy adminExportWorkerRetryPolicy, attempt int) int {
	if attempt < 0 || attempt >= len(policy.BackoffSeconds) {
		return 0
	}
	if policy.BackoffSeconds[attempt] < 0 {
		return 0
	}
	return policy.BackoffSeconds[attempt]
}

func (queue *localAdminExportTaskQueue) Get(id string) (adminExportQueuedTask, bool) {
	if queue == nil {
		return adminExportQueuedTask{}, false
	}
	queue.mu.RLock()
	defer queue.mu.RUnlock()
	item, ok := queue.tasks[strings.TrimSpace(id)]
	return item, ok
}

func (queue *localAdminExportTaskQueue) GetDeadLetter(id string) (adminExportQueuedTask, bool) {
	if queue == nil {
		return adminExportQueuedTask{}, false
	}
	queue.mu.RLock()
	defer queue.mu.RUnlock()
	item, ok := queue.deadLetters[strings.TrimSpace(id)]
	return item, ok
}

func (queue *localAdminExportTaskQueue) removeOrderIDLocked(id string) {
	if len(queue.order) == 0 {
		return
	}
	filtered := queue.order[:0]
	for _, candidate := range queue.order {
		if candidate != id {
			filtered = append(filtered, candidate)
		}
	}
	queue.order = filtered
}

type adminExportJobStore struct {
	mu       sync.RWMutex
	jobs     map[string]adminExportJob
	order    []string
	capacity int
}

type adminExportJobRuntimeStore interface {
	Get(id string) (adminExportJob, bool)
	MarkRunning(id string, now time.Time) (adminExportJob, error)
	MarkProgress(id string, rowsExported int, phase string, now time.Time) (adminExportJob, error)
	MarkCompleted(id string, rowCount, totalMatches int, truncated bool, objectRef, checksum string, coverage *adminExportRegionCoverage, now time.Time) (adminExportJob, error)
	MarkFailed(id, code string, now time.Time) (adminExportJob, error)
	MarkFailedWithMetadata(id, code string, metadata map[string]any, now time.Time) (adminExportJob, error)
	MarkCancelled(id, tenantID, cancelledBy, reason string, now time.Time) (adminExportJob, error)
}

type adminExportJobProducerStore interface {
	adminExportJobRuntimeStore
	Create(req adminExportJobRequest, tenantID, adminPrincipalID string, now time.Time) adminExportJob
}

type adminExportJobAdminStore interface {
	adminExportJobProducerStore
	List(tenantID string) []adminExportJob
}

type adminExportJobCreatePersister interface {
	PersistCreated(ctx context.Context, job adminExportJob, now time.Time) error
}

type adminExportJobTenantReader interface {
	GetByTenant(ctx context.Context, tenantID, jobID string) (adminExportJob, bool, error)
	ListByTenant(ctx context.Context, tenantID string, limit int) ([]adminExportJob, error)
}

type adminExportJobStoppedError struct {
	ID     string
	Status string
}

func adminExportJobGetForTenant(store adminExportJobAdminStore, tenantID, jobID string) (adminExportJob, bool, error) {
	if reader, ok := store.(adminExportJobTenantReader); ok {
		return adminExportJobGetForTenantReader(reader, tenantID, jobID)
	}
	job, ok := store.Get(jobID)
	if !ok || job.TenantID != tenantID {
		return adminExportJob{}, false, nil
	}
	return job, true, nil
}

func adminExportJobGetForTenantReader(reader adminExportJobTenantReader, tenantID, jobID string) (adminExportJob, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), postgresAdminExportJobUpdateTimeout)
	defer cancel()
	return reader.GetByTenant(ctx, tenantID, jobID)
}

func adminExportJobListForTenant(store adminExportJobAdminStore, tenantID string) ([]adminExportJob, error) {
	if reader, ok := store.(adminExportJobTenantReader); ok {
		ctx, cancel := context.WithTimeout(context.Background(), postgresAdminExportJobUpdateTimeout)
		defer cancel()
		return reader.ListByTenant(ctx, tenantID, 200)
	}
	return store.List(tenantID), nil
}

func (err adminExportJobStoppedError) Error() string {
	return fmt.Sprintf("export job %s stopped while %s", err.ID, err.Status)
}

type adminDownloadTokenStore struct {
	mu        sync.RWMutex
	tokens    map[string]adminDownloadToken
	persister blobstore.Persister
	known     bool
	loadErr   error
}

// SetPersister replaces the cache only after a checked load. Shared writes always
// use the latest locked row, so a startup snapshot is never a write authority.
func (s *adminDownloadTokenStore) SetPersister(p blobstore.Persister) error {
	if s == nil || p == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.persister = p
	raw, err := p.Load()
	var next map[string]adminDownloadToken
	if err == nil {
		next, err = decodeDownloadTokens(raw, s.known)
	}
	if err != nil {
		s.loadErr = errDownloadStoreUnavailable
		return s.loadErr
	}
	s.tokens, s.loadErr = next, nil
	s.known = s.known || len(raw) > 0
	return nil
}

type adminExportJobRequest struct {
	Stream  string            `json:"stream"`
	Format  string            `json:"format"`
	Filters map[string]string `json:"filters"`
	From    string            `json:"from"`
	To      string            `json:"to"`
	Limit   int               `json:"limit"`
}

type adminExportJobCancelRequest struct {
	Reason string `json:"reason"`
}

type adminExportJob struct {
	ID                        string            `json:"id"`
	TenantID                  string            `json:"tenant_id"`
	CreatedByAdminPrincipalID string            `json:"created_by_admin_principal_id"`
	Stream                    string            `json:"stream"`
	Format                    string            `json:"format"`
	Filters                   map[string]string `json:"filters"`
	From                      string            `json:"from"`
	To                        string            `json:"to"`
	Status                    string            `json:"status"`
	RowCount                  int               `json:"row_count"`
	ObjectRef                 *string           `json:"object_ref"`
	PayloadChecksum           *string           `json:"payload_checksum"`
	CreatedAt                 string            `json:"created_at"`
	StartedAt                 *string           `json:"started_at"`
	CompletedAt               *string           `json:"completed_at"`
	ExpiresAt                 string            `json:"expires_at"`
	ErrorCode                 *string           `json:"error_code"`
	Metadata                  map[string]any    `json:"metadata"`
}

type adminDownloadToken struct {
	Token                    string `json:"token"`
	TenantID                 string `json:"tenant_id"`
	ExportJobID              string `json:"export_job_id"`
	ObjectRef                string `json:"object_ref"`
	LocalFilename            string `json:"local_filename"`
	PayloadChecksum          string `json:"payload_checksum"`
	IssuedByAdminPrincipalID string `json:"issued_by_admin_principal_id"`
	IssuedAt                 string `json:"issued_at"`
	ExpiresAt                string `json:"expires_at"`
	Status                   string `json:"status"`
	// Payload is the generated export itself.
	//
	// ★★★ A LINK THAT ONLY WORKED ON THE EDGE THAT MINTED IT (2026-08-21, measured). The token map lived in
	// one process and the file on that node's own disk, so a link issued by region-a answered 404 on region-b
	// and 200 with 2573 bytes on region-a, seconds apart. Behind a load balancer an export downloaded only
	// when the browser happened to land back on the node that produced it, and the refusal said "absent or
	// expired", which sends an administrator to export again at the same odds.
	//
	// An Edge fleet's members are interchangeable, so the answer has to be too. The bytes travel with the
	// token in the shared store; they live at most as long as the token (fifteen minutes, one use) and are
	// dropped the moment it is spent or expires.
	Payload []byte `json:"payload,omitempty"`
}

func newAdminExportJobStore() *adminExportJobStore {
	return &adminExportJobStore{jobs: map[string]adminExportJob{}, capacity: inMemoryEventStoreCapacity()}
}

func newAdminDownloadTokenStore() *adminDownloadTokenStore {
	return &adminDownloadTokenStore{tokens: map[string]adminDownloadToken{}}
}

func (s *adminExportJobStore) Create(req adminExportJobRequest, tenantID, adminPrincipalID string, now time.Time) adminExportJob {
	s.mu.Lock()
	defer s.mu.Unlock()
	job := newAdminExportJob(req, tenantID, adminPrincipalID, now)
	s.order = append(s.order, job.ID)
	s.jobs[job.ID] = job
	s.order = evictFIFO(s.order, len(s.jobs), s.capacity, func(k string) { delete(s.jobs, k) })
	return job
}

func newAdminExportJob(req adminExportJobRequest, tenantID, adminPrincipalID string, now time.Time) adminExportJob {
	format := strings.TrimSpace(req.Format)
	if format == "" {
		format = "ndjson"
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	job := adminExportJob{
		ID:                        randomEdgeID("export_", now),
		TenantID:                  tenantID,
		CreatedByAdminPrincipalID: adminPrincipalID,
		Stream:                    strings.TrimSpace(req.Stream),
		Format:                    format,
		Filters:                   copyStringMap(req.Filters),
		From:                      strings.TrimSpace(req.From),
		To:                        strings.TrimSpace(req.To),
		Status:                    "queued",
		RowCount:                  0,
		CreatedAt:                 now.UTC().Format(time.RFC3339),
		ExpiresAt:                 now.UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339),
		Metadata:                  map[string]any{"export_mode": "async_lab"},
	}
	return job
}

func (s *adminExportJobStore) Get(id string) (adminExportJob, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	job, ok := s.jobs[id]
	return job, ok
}

func (s *adminExportJobStore) GetByTenant(ctx context.Context, tenantID, jobID string) (adminExportJob, bool, error) {
	if err := ctx.Err(); err != nil {
		return adminExportJob{}, false, err
	}
	job, ok := s.Get(jobID)
	if !ok || job.TenantID != tenantID {
		return adminExportJob{}, false, nil
	}
	return job, true, nil
}

func (s *adminExportJobStore) ListByTenant(ctx context.Context, tenantID string, limit int) ([]adminExportJob, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	jobs := s.List(tenantID)
	if limit > 0 && len(jobs) > limit {
		jobs = jobs[:limit]
	}
	return jobs, nil
}

func (s *adminExportJobStore) List(tenantID string) []adminExportJob {
	s.mu.RLock()
	defer s.mu.RUnlock()
	jobs := []adminExportJob{}
	for _, job := range s.jobs {
		if job.TenantID == tenantID {
			jobs = append(jobs, job)
		}
	}
	sort.Slice(jobs, func(i, j int) bool {
		return jobs[i].CreatedAt > jobs[j].CreatedAt
	})
	return jobs
}

func (s *adminExportJobStore) MarkRunning(id string, now time.Time) (adminExportJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.jobs[id]
	if !ok {
		return adminExportJob{}, fmt.Errorf("export job %s is absent", id)
	}
	if job.Status != "queued" {
		return adminExportJob{}, fmt.Errorf("export job %s cannot transition from %s to running", id, job.Status)
	}
	startedAt := now.UTC().Format(time.RFC3339)
	job.Status = "running"
	job.StartedAt = &startedAt
	if job.Metadata == nil {
		job.Metadata = map[string]any{}
	}
	job.Metadata["progress_phase"] = "running"
	job.Metadata["rows_exported"] = 0
	job.Metadata["last_progress_at"] = startedAt
	s.jobs[id] = job
	return job, nil
}

func (s *adminExportJobStore) MarkProgress(id string, rowsExported int, phase string, now time.Time) (adminExportJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.jobs[id]
	if !ok {
		return adminExportJob{}, fmt.Errorf("export job %s is absent", id)
	}
	if job.Status != "running" {
		return adminExportJob{}, adminExportJobStoppedError{ID: id, Status: job.Status}
	}
	if rowsExported < 0 {
		rowsExported = 0
	}
	if strings.TrimSpace(phase) == "" {
		phase = "exporting"
	}
	job.RowCount = rowsExported
	if job.Metadata == nil {
		job.Metadata = map[string]any{}
	}
	job.Metadata["progress_phase"] = strings.TrimSpace(phase)
	job.Metadata["rows_exported"] = rowsExported
	job.Metadata["last_progress_at"] = now.UTC().Format(time.RFC3339)
	s.jobs[id] = job
	return job, nil
}

func (s *adminExportJobStore) MarkCompleted(id string, rowCount, totalMatches int, truncated bool, objectRef, checksum string, coverage *adminExportRegionCoverage, now time.Time) (adminExportJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.jobs[id]
	if !ok {
		return adminExportJob{}, fmt.Errorf("export job %s is absent", id)
	}
	if job.Status != "running" {
		return adminExportJob{}, fmt.Errorf("export job %s cannot transition from %s to completed", id, job.Status)
	}
	completedAt := now.UTC().Format(time.RFC3339)
	job.Status = "completed"
	job.RowCount = rowCount
	job.ObjectRef = &objectRef
	job.PayloadChecksum = &checksum
	job.CompletedAt = &completedAt
	if job.Metadata == nil {
		job.Metadata = map[string]any{}
	}
	if coverage != nil {
		job.Metadata["region_coverage"] = coverage
	}
	job.Metadata["total_matches"] = totalMatches
	job.Metadata["truncated"] = truncated
	job.Metadata["progress_phase"] = "completed"
	job.Metadata["rows_exported"] = rowCount
	job.Metadata["last_progress_at"] = completedAt
	s.jobs[id] = job
	return job, nil
}

func (s *adminExportJobStore) MarkFailed(id, code string, now time.Time) (adminExportJob, error) {
	return s.MarkFailedWithMetadata(id, code, nil, now)
}

func (s *adminExportJobStore) MarkFailedWithMetadata(id, code string, metadata map[string]any, now time.Time) (adminExportJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.jobs[id]
	if !ok {
		return adminExportJob{}, fmt.Errorf("export job %s is absent", id)
	}
	if job.Status != "queued" && job.Status != "running" {
		return adminExportJob{}, fmt.Errorf("export job %s cannot transition from %s to failed", id, job.Status)
	}
	completedAt := now.UTC().Format(time.RFC3339)
	job.Status = "failed"
	job.ErrorCode = &code
	job.CompletedAt = &completedAt
	if job.Metadata == nil {
		job.Metadata = map[string]any{}
	}
	job.Metadata["progress_phase"] = "failed"
	job.Metadata["last_progress_at"] = completedAt
	for key, value := range metadata {
		if strings.TrimSpace(key) != "" {
			job.Metadata[key] = value
		}
	}
	s.jobs[id] = job
	return job, nil
}

func (s *adminExportJobStore) MarkCancelled(id, tenantID, cancelledBy, reason string, now time.Time) (adminExportJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.jobs[id]
	if !ok || job.TenantID != tenantID {
		return adminExportJob{}, fmt.Errorf("export job %s is absent", id)
	}
	if job.Status != "queued" && job.Status != "running" {
		return adminExportJob{}, fmt.Errorf("export job %s cannot transition from %s to cancelled", id, job.Status)
	}
	completedAt := now.UTC().Format(time.RFC3339)
	code := "cancelled"
	job.Status = "cancelled"
	job.ErrorCode = &code
	job.CompletedAt = &completedAt
	if job.Metadata == nil {
		job.Metadata = map[string]any{}
	}
	job.Metadata["cancelled_at"] = completedAt
	job.Metadata["cancelled_by_admin_principal_id"] = strings.TrimSpace(cancelledBy)
	job.Metadata["progress_phase"] = "cancelled"
	job.Metadata["last_progress_at"] = completedAt
	if trimmed := strings.TrimSpace(reason); trimmed != "" {
		job.Metadata["cancellation_reason"] = trimmed
	}
	s.jobs[id] = job
	return job, nil
}

func (s *adminDownloadTokenStore) Create(job adminExportJob, localFilename, issuedBy string, payload []byte, now time.Time) (adminDownloadToken, error) {
	return s.CreateContext(context.Background(), job, localFilename, issuedBy, payload, now)
}
func (s *adminDownloadTokenStore) CreateContext(ctx context.Context, job adminExportJob, localFilename, issuedBy string, payload []byte, now time.Time) (adminDownloadToken, error) {
	if s == nil {
		return adminDownloadToken{}, fmt.Errorf("download token store is not configured")
	}
	if job.ObjectRef == nil || strings.TrimSpace(*job.ObjectRef) == "" {
		return adminDownloadToken{}, fmt.Errorf("export job object_ref is absent")
	}
	if job.PayloadChecksum == nil || strings.TrimSpace(*job.PayloadChecksum) == "" {
		return adminDownloadToken{}, fmt.Errorf("export job payload_checksum is absent")
	}
	rawToken, err := randomURLToken(32)
	if err != nil {
		return adminDownloadToken{}, err
	}
	token := adminDownloadToken{
		Token:                    rawToken,
		TenantID:                 job.TenantID,
		ExportJobID:              job.ID,
		ObjectRef:                strings.TrimSpace(*job.ObjectRef),
		LocalFilename:            localFilename,
		PayloadChecksum:          strings.TrimSpace(*job.PayloadChecksum),
		IssuedByAdminPrincipalID: issuedBy,
		IssuedAt:                 now.UTC().Format(time.RFC3339),
		ExpiresAt:                now.UTC().Add(15 * time.Minute).Format(time.RFC3339),
		Status:                   "active",
		Payload:                  payload,
	}
	err = s.updateTokens(ctx, now, func(tokens map[string]adminDownloadToken) error {
		tokens[token.Token] = token
		return nil
	})
	if err != nil {
		return adminDownloadToken{}, err
	}
	return token, nil
}

func (s *adminDownloadTokenStore) Consume(tokenValue string, now time.Time) (adminDownloadToken, bool) {
	token, ok, _ := s.ConsumeContext(context.Background(), tokenValue, now)
	return token, ok
}

// On failure only non-secret audit metadata may be returned; bytes and the
// bearer credential are released only after the shared spend has committed.
func (s *adminDownloadTokenStore) ConsumeContext(ctx context.Context, tokenValue string, now time.Time) (adminDownloadToken, bool, error) {
	var token adminDownloadToken
	ok := false
	err := s.updateTokens(ctx, now, func(tokens map[string]adminDownloadToken) error {
		candidate, found := tokens[strings.TrimSpace(tokenValue)]
		if !found || candidate.Status != "active" {
			return errDownloadTokenAbsent
		}
		expiresAt, err := time.Parse(time.RFC3339, candidate.ExpiresAt)
		if err != nil || !now.UTC().Before(expiresAt) {
			return errDownloadTokenAbsent
		}
		token = candidate
		candidate.Status, candidate.Payload = "used", nil
		tokens[candidate.Token] = candidate
		ok = true
		return nil
	})
	if err != nil {
		// A refusal before the transaction callback may still be attributable
		// to a token this process previously issued/loaded. This cache is used
		// only for audit metadata, never to authorize delivery.
		if token.TenantID == "" && s != nil {
			s.mu.RLock()
			token = s.tokens[strings.TrimSpace(tokenValue)]
			s.mu.RUnlock()
		}
		token.Token, token.Payload, token.LocalFilename = "", nil, ""
		if errors.Is(err, errDownloadTokenAbsent) {
			return adminDownloadToken{}, false, nil
		}
		return token, false, err
	}
	return token, ok, nil
}

func createAndCompleteAdminExportJob(ctx context.Context, writer *logs.Writer, adminAuditOutbox adminAuditOutboxDeadReader, objectStore adminExportObjectStore, hotStore hotstore.Store, store adminExportJobProducerStore, evaluator decision.Evaluator, req adminExportJobRequest, tenantID, adminPrincipalID, sourceIP string, now time.Time) (adminExportJob, error) {
	job, _, err := createQueuedAdminExportJob(ctx, writer, adminAuditOutbox, store, evaluator, req, tenantID, adminPrincipalID, sourceIP, now)
	if err != nil {
		return adminExportJob{}, err
	}
	return runAdminExportJob(ctx, writer, adminAuditOutbox, objectStore, hotStore, store, evaluator, job, req, sourceIP, now)
}

func createQueuedAdminExportJob(ctx context.Context, writer *logs.Writer, adminAuditOutbox adminAuditOutboxDeadReader, store adminExportJobProducerStore, evaluator decision.Evaluator, req adminExportJobRequest, tenantID, adminPrincipalID, sourceIP string, now time.Time) (adminExportJob, adminExportWorkerTaskDocument, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return adminExportJob{}, adminExportWorkerTaskDocument{}, err
	}
	if err := validateAdminExportJobRequest(req); err != nil {
		return adminExportJob{}, adminExportWorkerTaskDocument{}, err
	}
	job := store.Create(req, tenantID, adminPrincipalID, now)
	if persister, ok := store.(adminExportJobCreatePersister); ok {
		if err := persister.PersistCreated(ctx, job, now); err != nil {
			return adminExportJob{}, adminExportWorkerTaskDocument{}, err
		}
	}
	taskDocument, err := adminExportWorkerTaskDocumentFromJob(job, req, sourceIP)
	if err != nil {
		return adminExportJob{}, adminExportWorkerTaskDocument{}, err
	}
	if err := appendAdminAudit(ctx, writer, adminAuditOutbox, adminExportJobAuditLog("admin_export_requested", job, evaluator, sourceIP), now); err != nil {
		return adminExportJob{}, adminExportWorkerTaskDocument{}, err
	}
	if err := appendAdminAudit(ctx, writer, adminAuditOutbox, adminExportWorkerTaskAuditLog(taskDocument, evaluator, sourceIP), now); err != nil {
		return adminExportJob{}, adminExportWorkerTaskDocument{}, err
	}
	return job, taskDocument, nil
}

func runAdminExportJob(ctx context.Context, writer *logs.Writer, adminAuditOutbox adminAuditOutboxDeadReader, objectStore adminExportObjectStore, hotStore hotstore.Store, store adminExportJobRuntimeStore, evaluator decision.Evaluator, job adminExportJob, req adminExportJobRequest, sourceIP string, now time.Time) (adminExportJob, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	running, err := store.MarkRunning(job.ID, now)
	if err != nil {
		return adminExportJob{}, err
	}
	if err := appendAdminAudit(ctx, writer, adminAuditOutbox, adminExportJobAuditLog("admin_export_started", running, evaluator, sourceIP), now); err != nil {
		return adminExportJob{}, err
	}
	if _, err := store.MarkProgress(job.ID, 0, "exporting", now); err != nil {
		return adminExportJob{}, err
	}

	query := url.Values{}
	for key, value := range req.Filters {
		if strings.TrimSpace(key) != "" && strings.TrimSpace(value) != "" {
			query.Set(key, value)
		}
	}
	query.Set("from", strings.TrimSpace(req.From))
	query.Set("to", strings.TrimSpace(req.To))
	if req.Limit > 0 {
		query.Set("limit", strconv.Itoa(req.Limit))
	} else {
		query.Set("limit", "1000000")
	}
	searchQuery, err := adminLogSearchQuery(job.TenantID, req.Stream, query, 1000000, 1000000)
	if err != nil {
		failed, markErr := store.MarkFailed(job.ID, "query_failed", now)
		if markErr == nil {
			_ = appendAdminAudit(ctx, writer, adminAuditOutbox, adminExportJobAuditLog("admin_export_failed", failed, evaluator, sourceIP), now)
		}
		return adminExportJob{}, err
	}
	if hotStore == nil {
		failed, markErr := store.MarkFailed(job.ID, "query_failed", now)
		if markErr == nil {
			_ = appendAdminAudit(ctx, writer, adminAuditOutbox, adminExportJobAuditLog("admin_export_failed", failed, evaluator, sourceIP), now)
		}
		return adminExportJob{}, fmt.Errorf("hot store is not configured")
	}
	objectRef, err := adminExportObjectRef(job)
	if err != nil {
		failed, markErr := store.MarkFailed(job.ID, "invalid_object_ref", now)
		if markErr == nil {
			_ = appendAdminAudit(ctx, writer, adminAuditOutbox, adminExportJobAuditLog("admin_export_failed", failed, evaluator, sourceIP), now)
		}
		return adminExportJob{}, err
	}
	localFilename, err := adminExportLocalFilename(job)
	if err != nil {
		failed, markErr := store.MarkFailed(job.ID, "invalid_local_filename", now)
		if markErr == nil {
			_ = appendAdminAudit(ctx, writer, adminAuditOutbox, adminExportJobAuditLog("admin_export_failed", failed, evaluator, sourceIP), now)
		}
		return adminExportJob{}, err
	}
	coverage := exportRegionCoverage(ctx, hotStore, searchQuery)
	if coverage != nil {
		objectStore = exportCommentObjectStore{adminExportObjectStore: objectStore, coverage: coverage}
	}
	checksum, exportResult, err := writeHotStoreExportRows(ctx, hotStore, searchQuery, objectStore, localFilename, func(rowsExported int) error {
		if rowsExported == 1 || rowsExported%1000 == 0 {
			_, err := store.MarkProgress(job.ID, rowsExported, "exporting", time.Now())
			return err
		}
		return nil
	})
	if err != nil {
		var stopped adminExportJobStoppedError
		if errors.As(err, &stopped) {
			if stoppedJob, ok := store.Get(job.ID); ok {
				return stoppedJob, nil
			}
		}
		errorCode := "write_failed"
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			errorCode = "worker_context_cancelled"
		}
		failed, markErr := store.MarkFailed(job.ID, errorCode, now)
		if markErr == nil {
			_ = appendAdminAudit(ctx, writer, adminAuditOutbox, adminExportJobAuditLog("admin_export_failed", failed, evaluator, sourceIP), now)
		}
		return adminExportJob{}, err
	}
	truncated := exportResult.TotalMatches > exportResult.RowsExported
	completed, err := store.MarkCompleted(job.ID, exportResult.RowsExported, exportResult.TotalMatches, truncated, objectRef, checksum, coverage, now)
	if err != nil {
		return adminExportJob{}, err
	}
	if err := appendAdminAudit(ctx, writer, adminAuditOutbox, adminExportJobAuditLog("admin_export_completed", completed, evaluator, sourceIP), now); err != nil {
		return adminExportJob{}, err
	}
	return completed, nil
}

func validateAdminExportJobRequest(req adminExportJobRequest) error {
	if _, ok := adminLogStreamFilename(req.Stream); !ok {
		return unknownAdminLogStreamError{stream: req.Stream}
	}
	if req.Limit < 0 || req.Limit > 1000000 {
		return fmt.Errorf("export limit must be between 0 and 1000000")
	}
	format := strings.TrimSpace(req.Format)
	if format == "" {
		format = "ndjson"
	}
	if format != "ndjson" {
		return fmt.Errorf("unsupported export format %q", req.Format)
	}
	if strings.TrimSpace(req.From) == "" || strings.TrimSpace(req.To) == "" {
		return fmt.Errorf("export job requires from and to")
	}
	from, err := time.Parse(time.RFC3339, strings.TrimSpace(req.From))
	if err != nil {
		return fmt.Errorf("parse export from: %w", err)
	}
	to, err := time.Parse(time.RFC3339, strings.TrimSpace(req.To))
	if err != nil {
		return fmt.Errorf("parse export to: %w", err)
	}
	if to.Before(from) {
		return fmt.Errorf("export to must not precede from")
	}
	return nil
}

func adminExportObjectRef(job adminExportJob) (string, error) {
	prefix, err := adminExportObjectRefPrefix(job)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s%s.%s.gz", prefix, job.ID, job.Format), nil
}

func adminExportObjectRefPrefix(job adminExportJob) (string, error) {
	if err := validateExportPathSegments(job); err != nil {
		return "", err
	}
	createdAt, err := time.Parse(time.RFC3339, job.CreatedAt)
	if err != nil {
		createdAt = time.Now().UTC()
	}
	return fmt.Sprintf("evidence://tenant/%s/exports/%04d/%02d/%02d/", job.TenantID, createdAt.Year(), createdAt.Month(), createdAt.Day()), nil
}

func adminExportLocalFilename(job adminExportJob) (string, error) {
	if err := validateExportPathSegments(job); err != nil {
		return "", err
	}
	createdAt, err := time.Parse(time.RFC3339, job.CreatedAt)
	if err != nil {
		createdAt = time.Now().UTC()
	}
	return filepath.Join("exports", job.TenantID, fmt.Sprintf("%04d", createdAt.Year()), fmt.Sprintf("%02d", createdAt.Month()), fmt.Sprintf("%02d", createdAt.Day()), fmt.Sprintf("%s.%s.gz", job.ID, job.Format)), nil
}

func adminExportWorkerTaskIdempotencyKey(job adminExportJob) string {
	return fmt.Sprintf("export_job:%s:%s:%s", job.TenantID, job.ID, job.CreatedAt)
}

func defaultAdminExportWorkerRetryPolicy() adminExportWorkerRetryPolicy {
	return adminExportWorkerRetryPolicy{
		RetryableErrorCodes: []string{
			"worker_context_cancelled",
			"object_store_timeout",
			"hot_store_timeout",
			"temporary_write_failed",
		},
		NonRetryableErrorCodes: []string{
			"cancelled",
			"invalid_object_ref",
			"invalid_local_filename",
			"query_failed",
			"write_failed",
		},
		BackoffSeconds: []int{30, 120, 300},
	}
}

func adminExportWorkerTaskDocumentFromJob(job adminExportJob, req adminExportJobRequest, sourceIP string) (adminExportWorkerTaskDocument, error) {
	outputPrefix, err := adminExportObjectRefPrefix(job)
	if err != nil {
		return adminExportWorkerTaskDocument{}, err
	}
	limit := req.Limit
	if limit <= 0 {
		limit = 1000000
	}
	traceID := fmt.Sprintf("trace_%s", job.ID)
	return adminExportWorkerTaskDocument{
		ID:                        "export_task_" + job.ID,
		TenantID:                  job.TenantID,
		ExportJobID:               job.ID,
		CreatedByAdminPrincipalID: job.CreatedByAdminPrincipalID,
		IdempotencyKey:            adminExportWorkerTaskIdempotencyKey(job),
		Stream:                    job.Stream,
		Format:                    job.Format,
		Filters:                   copyStringMap(job.Filters),
		From:                      job.From,
		To:                        job.To,
		Limit:                     limit,
		OutputRefPrefix:           outputPrefix,
		RequestedAt:               job.CreatedAt,
		StartedAt:                 job.StartedAt,
		LeaseExpiresAt:            nil,
		TimeoutSeconds:            defaultAdminExportWorkerTimeoutSeconds,
		CancelCheckIntervalRows:   defaultAdminExportWorkerCancelCheckIntervalRows,
		RetryPolicy:               defaultAdminExportWorkerRetryPolicy(),
		Attempt:                   0,
		MaxAttempts:               defaultAdminExportWorkerMaxAttempts,
		Status:                    "queued",
		TraceID:                   &traceID,
		SourceIP:                  stringPtr(sourceIP),
		Metadata: map[string]any{
			"worker_mode": "phase1_sync_boundary",
			"export_mode": stringValue(job.Metadata["export_mode"]),
		},
	}, nil
}

func adminExportJobRequestFromWorkerTaskDocument(document adminExportWorkerTaskDocument) adminExportJobRequest {
	return adminExportJobRequest{
		Stream:  document.Stream,
		Format:  document.Format,
		Filters: copyStringMap(document.Filters),
		From:    document.From,
		To:      document.To,
		Limit:   document.Limit,
	}
}

func createAdminExportDownloadURL(r *http.Request, store *adminDownloadTokenStore, objects adminExportObjectStore,
	job adminExportJob, issuedBy string, now time.Time) (adminDownloadURLResponse, adminDownloadToken, error) {
	if job.Status != "completed" {
		return adminDownloadURLResponse{}, adminDownloadToken{}, fmt.Errorf("export job %s is not completed", job.ID)
	}
	localFilename, err := adminExportLocalFilename(job)
	if err != nil {
		return adminDownloadURLResponse{}, adminDownloadToken{}, err
	}
	// The bytes are read HERE, on the node that produced them, and travel with the token — so the link works
	// on whichever Edge the administrator's browser reaches next. A read failure is not fatal: the token is
	// still minted and this node can still serve it from disk, which is exactly what happened before.
	var payload []byte
	if objects != nil {
		if data, rerr := objects.ReadGeneratedFile(localFilename); rerr == nil {
			payload = data
		} else {
			log.Printf("export download: could not read %q to share it with the fleet (%v) — this link will only "+
				"work on this node", localFilename, rerr)
		}
	}
	token, err := store.CreateContext(r.Context(), job, localFilename, issuedBy, payload, now)
	if err != nil {
		return adminDownloadURLResponse{}, adminDownloadToken{}, err
	}
	response := adminDownloadURLResponse{
		DownloadURL:     absoluteURLForRequest(r, "/admin/export-downloads/"+url.PathEscape(token.Token)),
		ExpiresAt:       token.ExpiresAt,
		PayloadChecksum: token.PayloadChecksum,
		RowCount:        job.RowCount,
	}
	return response, token, nil
}

func adminExportJobAuditLog(eventType string, job adminExportJob, evaluator decision.Evaluator, sourceIP string) model.AuditLog {
	action := "export"
	result := "success"
	if strings.HasSuffix(eventType, "_failed") {
		result = "failure"
	}
	metadata := map[string]any{
		"stream":           job.Stream,
		"format":           job.Format,
		"status":           job.Status,
		"row_count":        job.RowCount,
		"object_ref":       stringPtrValue(job.ObjectRef),
		"payload_checksum": stringPtrValue(job.PayloadChecksum),
		"from":             job.From,
		"to":               job.To,
	}
	for key, value := range job.Metadata {
		if strings.TrimSpace(key) != "" {
			metadata[key] = value
		}
	}
	// ★★★ THE EXPORT'S OWN ORGANIZATION, NOT THE NODE'S (2026-08-21, read on a customer's audit screen).
	// This filed every export under evaluator.PolicyBundle.TenantID — the organization the NODE belongs to —
	// so an export of tenant_acme's audit stream, requested by Acme's own administrator, landed in
	// tenant_reference_lab's trail carrying the object reference, the row count and the payload checksum.
	// Two harms in one row: the organization whose data left has no record that it did, and an unrelated
	// organization reads about it. Same shape as the sign-in audit that was filed under the node.
	//
	// The job knows whose it is; it has since it was created, and every other reader of it uses that field.
	tenantID := strings.TrimSpace(job.TenantID)
	if tenantID == "" {
		// Never silently the node's: an export we cannot attribute is stated as unattributed rather than
		// handed to whoever happens to own this Edge.
		tenantID = evaluator.PolicyBundle.TenantID
		metadata["tenant_attribution"] = "the export job named no organization; filed under this node's"
	}
	return model.AuditLog{
		ID:            randomEdgeID("audit_"+eventType+"_", time.Now().UTC()),
		TenantID:      tenantID,
		ActorUserID:   &job.CreatedByAdminPrincipalID,
		EventType:     eventType,
		TargetType:    stringPtr("export_job"),
		TargetID:      stringPtr(job.ID),
		Action:        &action,
		Result:        &result,
		EdgeRegionID:  &evaluator.EdgeRegionID,
		EdgeClusterID: &evaluator.EdgeClusterID,
		SourceIP:      stringPtr(sourceIP),
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Metadata:      metadata,
	}
}

func adminExportDeadLetterBridgeFailureAuditLog(item adminExportQueuedTask, deadLetterReason, failureReason string, now time.Time) model.AuditLog {
	action := "export_dead_letter_bridge"
	result := "failure"
	reason := strings.TrimSpace(failureReason)
	tenantID := strings.TrimSpace(item.Document.TenantID)
	if tenantID == "" && item.Task.Evaluator.PolicyBundle.TenantID != "" {
		tenantID = item.Task.Evaluator.PolicyBundle.TenantID
	}
	actorUserID := strings.TrimSpace(item.Document.CreatedByAdminPrincipalID)
	if actorUserID == "" {
		actorUserID = item.Job.CreatedByAdminPrincipalID
	}
	return model.AuditLog{
		ID:            randomEdgeID("audit_admin_export_dead_letter_bridge_failed_", now),
		TenantID:      tenantID,
		ActorUserID:   stringPtr(actorUserID),
		EventType:     "admin_export_dead_letter_bridge_failed",
		TargetType:    stringPtr("export_worker_task"),
		TargetID:      stringPtr(item.Document.ID),
		Action:        &action,
		Result:        &result,
		Reason:        &reason,
		EdgeRegionID:  &item.Task.Evaluator.EdgeRegionID,
		EdgeClusterID: &item.Task.Evaluator.EdgeClusterID,
		SourceIP:      stringPtr(item.Task.SourceIP),
		Timestamp:     now.UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"export_job_id":         item.Document.ExportJobID,
			"dead_letter_reason":    deadLetterReason,
			"job_store_error":       failureReason,
			"attempt":               item.Document.Attempt,
			"max_attempts":          item.Document.MaxAttempts,
			"export_worker_task_id": item.Document.ID,
		},
	}
}

func adminExportWorkerTaskAuditLog(task adminExportWorkerTaskDocument, evaluator decision.Evaluator, sourceIP string) model.AuditLog {
	action := "export_worker_task"
	result := "success"
	return model.AuditLog{
		ID:            randomEdgeID("audit_admin_export_task_enqueued_", time.Now().UTC()),
		TenantID:      task.TenantID,
		ActorUserID:   &task.CreatedByAdminPrincipalID,
		EventType:     "admin_export_task_enqueued",
		TargetType:    stringPtr("export_worker_task"),
		TargetID:      stringPtr(task.ID),
		Action:        &action,
		Result:        &result,
		EdgeRegionID:  &evaluator.EdgeRegionID,
		EdgeClusterID: &evaluator.EdgeClusterID,
		SourceIP:      stringPtr(sourceIP),
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"export_job_id":              task.ExportJobID,
			"idempotency_key":            task.IdempotencyKey,
			"stream":                     task.Stream,
			"format":                     task.Format,
			"limit":                      task.Limit,
			"output_ref_prefix":          task.OutputRefPrefix,
			"lease_expires_at":           stringPtrValue(task.LeaseExpiresAt),
			"timeout_seconds":            task.TimeoutSeconds,
			"cancel_check_interval_rows": task.CancelCheckIntervalRows,
			"retry_policy":               task.RetryPolicy,
			"attempt":                    task.Attempt,
			"max_attempts":               task.MaxAttempts,
			"trace_id":                   stringPtrValue(task.TraceID),
			"worker_task_status":         task.Status,
		},
	}
}

// Export-job admin routes (create/list/detail/cancel/download-url). // Moved verbatim out of newServerWithConfig (Phase 2 route-registration split,
func registerExportJobRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, config serverConfig, evaluator decision.Evaluator, writer *logs.Writer, adminAuditOutbox adminAuditOutboxDeadReader, adminExportJobs adminExportJobAdminStore, adminExportWorker adminExportWorker, adminDownloadTokens *adminDownloadTokenStore, exportObjectStore adminExportObjectStore, adminHotStore hotstore.Store) {
	mux.HandleFunc("POST /admin/export-jobs", adminEndpoint("admin.export.create", func(w http.ResponseWriter, r *http.Request) {
		var req adminExportJobRequest
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode export job request: %w", err))
			return
		}
		if err := validateAdminExportJobRequest(req); err != nil {
			writeError(w, statusForAdminLogQueryError(err), err)
			return
		}
		job, err := adminExportWorker.Enqueue(r.Context(), adminExportTask{
			Writer:           writer,
			AdminAuditOutbox: adminAuditOutbox,
			ObjectStore:      exportObjectStore,
			HotStore:         adminHotStore,
			Store:            adminExportJobs,
			Evaluator:        evaluator,
			Request:          req,
			TenantID:         adminTenantIDFromRequest(r),
			AdminPrincipalID: adminPrincipalIDFromRequest(r),
			SourceIP:         sourceIPFromRequest(r),
			Now:              time.Now(),
		})
		if err != nil {
			writeError(w, statusForAdminLogQueryError(err), err)
			return
		}
		writeJSON(w, http.StatusAccepted, job)
	}))
	mux.HandleFunc("GET /admin/export-jobs", adminEndpoint("admin.export.read", func(w http.ResponseWriter, r *http.Request) {
		jobs, err := adminExportJobListForTenant(adminExportJobs, adminTenantIDFromRequest(r))
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"jobs": jobs})
	}))
	mux.HandleFunc("GET /admin/export-jobs/{job_id}", adminEndpoint("admin.export.read", func(w http.ResponseWriter, r *http.Request) {
		job, ok, err := adminExportJobGetForTenant(adminExportJobs, adminTenantIDFromRequest(r), r.PathValue("job_id"))
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if !ok {
			writeError(w, http.StatusNotFound, fmt.Errorf("export job %s is absent", r.PathValue("job_id")))
			return
		}
		writeJSON(w, http.StatusOK, job)
	}))
	mux.HandleFunc("POST /admin/export-jobs/{job_id}/cancel", adminEndpoint("admin.export.cancel", func(w http.ResponseWriter, r *http.Request) {
		var req adminExportJobCancelRequest
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode export job cancel request: %w", err))
			return
		}
		jobID := r.PathValue("job_id")
		job, ok, err := adminExportJobGetForTenant(adminExportJobs, adminTenantIDFromRequest(r), jobID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if !ok {
			writeError(w, http.StatusNotFound, fmt.Errorf("export job %s is absent", jobID))
			return
		}
		identity, _ := adminIdentityFromRequest(r)
		if !adminCanCancelExportJob(identity, job) {
			audit := adminRBACDeniedAuditLog(identity, "admin.export.cancel.owned", evaluator, sourceIPFromRequest(r), r.UserAgent())
			audit.Metadata["target_tenant_id"] = job.TenantID
			audit.Metadata["export_job_id"] = job.ID
			audit.Metadata["created_by_admin_principal_id"] = job.CreatedByAdminPrincipalID
			_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, audit, time.Now())
			writeError(w, http.StatusForbidden, fmt.Errorf("admin can only cancel permitted export jobs"))
			return
		}
		cancelled, err := adminExportJobs.MarkCancelled(jobID, adminTenantIDFromRequest(r), adminPrincipalIDFromRequest(r), req.Reason, time.Now())
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminExportJobAuditLog("admin_export_cancelled", cancelled, evaluator, sourceIPFromRequest(r)), time.Now())
		writeJSON(w, http.StatusOK, cancelled)
	}))
	mux.HandleFunc("POST /admin/export-jobs/{job_id}/download-url", adminEndpoint("admin.export.read", func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(retentionWriteContext(r.Context()))
		job, ok, err := adminExportJobGetForTenant(adminExportJobs, adminTenantIDFromRequest(r), r.PathValue("job_id"))
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if !ok {
			writeError(w, http.StatusNotFound, fmt.Errorf("export job %s is absent", r.PathValue("job_id")))
			return
		}
		response, token, err := createAdminExportDownloadURL(r, adminDownloadTokens, exportObjectStore, job, adminPrincipalIDFromRequest(r), time.Now())
		if err != nil {
			if errors.Is(err, errDownloadStoreUnavailable) {
				writeError(w, http.StatusServiceUnavailable, errDownloadStoreUnavailable)
				return
			}
			writeError(w, http.StatusBadRequest, err)
			return
		}
		_ = appendAdminAudit(r.Context(), writer, adminAuditOutbox, adminDownloadAuditLog("admin_export_url_issued", token, evaluator, sourceIPFromRequest(r), r.UserAgent()), time.Now())
		writeJSON(w, http.StatusCreated, response)
	}))
}
