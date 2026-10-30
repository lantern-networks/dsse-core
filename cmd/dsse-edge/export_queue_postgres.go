package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type postgresExportTaskQueueStatement struct {
	SQL  string
	Args []any
}

type postgresExportTaskDB interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) postgresExportTaskRow
}

type postgresExportTaskRow interface {
	Scan(...any) error
}

type postgresExportTaskSQLDB struct {
	DB *sql.DB
}

type postgresExportTaskTxDB struct {
	Tx *sql.Tx
}

func (db postgresExportTaskSQLDB) ExecContext(ctx context.Context, statement string, args ...any) (sql.Result, error) {
	if db.DB == nil {
		return nil, fmt.Errorf("postgres export task queue db is not configured")
	}
	return db.DB.ExecContext(ctx, statement, args...)
}

func (db postgresExportTaskSQLDB) QueryRowContext(ctx context.Context, statement string, args ...any) postgresExportTaskRow {
	if db.DB == nil {
		return postgresExportTaskErrorRow{err: fmt.Errorf("postgres export task queue db is not configured")}
	}
	return db.DB.QueryRowContext(ctx, statement, args...)
}

func (db postgresExportTaskTxDB) ExecContext(ctx context.Context, statement string, args ...any) (sql.Result, error) {
	if db.Tx == nil {
		return nil, fmt.Errorf("postgres export task queue transaction is not configured")
	}
	return db.Tx.ExecContext(ctx, statement, args...)
}

func (db postgresExportTaskTxDB) QueryRowContext(ctx context.Context, statement string, args ...any) postgresExportTaskRow {
	if db.Tx == nil {
		return postgresExportTaskErrorRow{err: fmt.Errorf("postgres export task queue transaction is not configured")}
	}
	return db.Tx.QueryRowContext(ctx, statement, args...)
}

type postgresExportTaskErrorRow struct {
	err error
}

func (row postgresExportTaskErrorRow) Scan(...any) error {
	return row.err
}

type postgresExportTaskQueueAdapter struct {
	DB            postgresExportTaskDB
	TenantID      string
	WorkerID      string
	LeaseDuration time.Duration
	SchemaData    []byte
	Resolver      adminExportRuntimeResolver
}

type postgresQueuedAdminExportWorker struct {
	Queue                  postgresExportTaskQueueAdapter
	Timeout                time.Duration
	PollInterval           time.Duration
	LeaseExtensionInterval time.Duration
}

const defaultPostgresExportTaskAckTimeout = 30 * time.Second

func (worker postgresQueuedAdminExportWorker) Run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	pollInterval := worker.PollInterval
	if pollInterval <= 0 {
		pollInterval = 100 * time.Millisecond
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		processed, err := worker.runOne(ctx, time.Now())
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			// PostgreSQL Queue errors are process-level signals: a supervisor should restart
			// the Worker or alert rather than hiding a DB outage inside the poll loop.
			return err
		}
		if processed {
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

func (worker postgresQueuedAdminExportWorker) runOne(ctx context.Context, now time.Time) (bool, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	wallStartedAt := time.Now()
	item, ok, err := worker.Queue.Lease(ctx, now)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}
	leaseQueue := worker.Queue
	leaseQueue.WorkerID = item.LeaseToken
	if store, ok := item.Task.Store.(postgresAdminExportJobStore); ok {
		store.LeaseToken = item.LeaseToken
		store.LeaseTaskID = item.Document.ID
		store.LeaseTenantID = item.Document.TenantID
		item.Task.Store = store
	}
	if item.Job.Status == "completed" || item.Job.Status == "cancelled" {
		return true, leaseQueue.Complete(ctx, item.Document.ID)
	}
	if item.Job.Status == "failed" {
		code := adminExportWorkerJobErrorCode(item.Task.Store, item.Job.ID, adminExportWorkerDefaultErrorCode)
		if !adminExportWorkerShouldRetry(item.Document.RetryPolicy, code) {
			return true, leaseQueue.Complete(ctx, item.Document.ID)
		}
		store, ok := item.Task.Store.(postgresAdminExportJobStore)
		if !ok {
			return true, fmt.Errorf("postgres export task %s cannot reset a failed job without a fenced store", item.Document.ID)
		}
		if _, err := store.ResetForRetry(item.Job.ID, now); err != nil {
			return true, err
		}
		item.Job.Status = "queued"
	}
	if item.Document.Attempt >= item.Document.MaxAttempts {
		return true, worker.deadLetterClaimed(ctx, leaseQueue, item, now, "max_attempts_exhausted")
	}
	timeout := worker.Timeout
	if timeout <= 0 {
		timeout = time.Duration(defaultAdminExportWorkerTimeoutSeconds) * time.Second
	}
	leaseDuration := worker.Queue.LeaseDuration
	if leaseDuration <= 0 {
		leaseDuration = 30 * time.Second
	}
	workerCtx, cancel := context.WithTimeout(context.Background(), timeout)
	stopLeaseExtension := worker.startLeaseExtension(leaseQueue, workerCtx, cancel, item.Document.ID, leaseDuration)
	_, err = runAdminExportJob(workerCtx, item.Task.Writer, item.Task.AdminAuditOutbox, item.Task.ObjectStore, item.Task.HotStore, item.Task.Store, item.Task.Evaluator, item.Job, item.Task.Request, item.Task.SourceIP, now)
	leaseErr := stopLeaseExtension()
	finishedAt := postgresExportTaskFinishedAt(now, wallStartedAt, time.Now())
	ackCtx, ackCancel := context.WithTimeout(context.Background(), defaultPostgresExportTaskAckTimeout)
	defer ackCancel()
	if err != nil {
		current, found := item.Task.Store.Get(item.Job.ID)
		if !found {
			return true, fmt.Errorf("export job %s state unavailable after worker failure: %w", item.Job.ID, err)
		}
		errorCode := adminExportWorkerDefaultErrorCode
		if current.ErrorCode != nil && strings.TrimSpace(*current.ErrorCode) != "" {
			errorCode = strings.TrimSpace(*current.ErrorCode)
		}
		if adminExportWorkerShouldRetry(item.Document.RetryPolicy, errorCode) &&
			(current.Status == "queued" || current.Status == "running" || current.Status == "failed") {
			if store, ok := item.Task.Store.(postgresAdminExportJobStore); ok {
				if _, resetErr := store.ResetForRetry(item.Job.ID, finishedAt); resetErr != nil {
					return true, resetErr
				}
			} else if current.Status == "failed" {
				return true, fmt.Errorf("export job %s retry requires a fenced store", item.Job.ID)
			}
			_, queued, retryErr := leaseQueue.Retry(ackCtx, item, finishedAt)
			if retryErr != nil {
				return true, retryErr
			}
			if !queued {
				return true, worker.deadLetterClaimed(ackCtx, leaseQueue, item, finishedAt, "max_attempts_exhausted")
			}
			return true, leaseErr
		}
		if current.Status == "queued" || current.Status == "running" {
			if _, markErr := item.Task.Store.MarkFailed(item.Job.ID, errorCode, finishedAt); markErr != nil {
				return true, markErr
			}
		} else if current.Status != "failed" && current.Status != "completed" && current.Status != "cancelled" {
			return true, fmt.Errorf("export job %s has unexpected state %s after worker failure", item.Job.ID, current.Status)
		}
		if completeErr := leaseQueue.Complete(ackCtx, item.Document.ID); completeErr != nil {
			return true, completeErr
		}
		return true, leaseErr
	}
	if completeErr := leaseQueue.Complete(ackCtx, item.Document.ID); completeErr != nil {
		return true, completeErr
	}
	return true, leaseErr
}

// The caller's logical claim time may be fixed in tests or supplied by a scheduler.
// Retry backoff nevertheless starts after processing ends, never before a slow failure.
func postgresExportTaskFinishedAt(claimAt, wallStartedAt, wallFinishedAt time.Time) time.Time {
	if wallFinishedAt.Before(wallStartedAt) {
		return claimAt
	}
	return claimAt.Add(wallFinishedAt.Sub(wallStartedAt))
}

func (worker postgresQueuedAdminExportWorker) deadLetterClaimed(ctx context.Context, queue postgresExportTaskQueueAdapter, item adminExportQueuedTask, now time.Time, reason string) error {
	if store, ok := item.Task.Store.(postgresAdminExportJobStore); ok {
		_, audit, err := store.DeadLetterTask(ctx, item.Document.ID, item.Job.ID, item.Document.Attempt, item.Document.MaxAttempts, now, reason, item.Task.Evaluator, item.Task.SourceIP)
		if err != nil {
			return err
		}
		// The matching outbox row committed with the job and dead letter. A local
		// JSONL failure cannot erase the only durable record of this terminal act.
		if item.Task.Writer == nil {
			logErrorf("admin export dead-letter local audit writer is not configured")
		} else if err := item.Task.Writer.Append("audit.log.jsonl", audit); err != nil {
			logErrorf("admin export dead-letter local audit write failed: %v", err)
		}
		return nil
	}
	dead, moved, err := queue.DeadLetter(ctx, item.Document.ID, now, reason)
	if err != nil {
		return err
	}
	if !moved {
		return fmt.Errorf("postgres export task %s lost its lease before dead letter", item.Document.ID)
	}
	adminExportMarkDeadLettered(dead, now)
	return nil
}

func (worker postgresQueuedAdminExportWorker) startLeaseExtension(queue postgresExportTaskQueueAdapter, ctx context.Context, cancel context.CancelFunc, taskID string, leaseDuration time.Duration) func() error {
	taskID = strings.TrimSpace(taskID)
	if taskID == "" || leaseDuration <= 0 {
		return func() error {
			cancel()
			return nil
		}
	}
	interval := worker.LeaseExtensionInterval
	if interval <= 0 {
		interval = leaseDuration / 2
	}
	if interval <= 0 {
		return func() error {
			cancel()
			return nil
		}
	}
	extensionCtx, stop := context.WithCancel(ctx)
	stopping := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-extensionCtx.Done():
				done <- nil
				return
			case tick := <-ticker.C:
				if _, ok, err := queue.ExtendLease(extensionCtx, taskID, tick, leaseDuration); err != nil {
					select {
					case <-stopping:
						done <- nil
					default:
						cancel()
						done <- err
					}
					return
				} else if !ok {
					select {
					case <-stopping:
						done <- nil
					default:
						cancel()
						done <- fmt.Errorf("postgres export task lease extension lost task %s", taskID)
					}
					return
				}
			}
		}
	}()
	return func() error {
		close(stopping)
		stop()
		cancel()
		return <-done
	}
}

func (adapter postgresExportTaskQueueAdapter) Enqueue(ctx context.Context, item adminExportQueuedTask) error {
	if adapter.DB == nil {
		return fmt.Errorf("postgres export task queue db is not configured")
	}
	statement, err := buildPostgresExportTaskEnqueueStatement(item)
	if err != nil {
		return err
	}
	ctx = normalizePostgresExportTaskContext(ctx)
	_, err = adapter.DB.ExecContext(ctx, statement.SQL, statement.Args...)
	return err
}

func (adapter postgresExportTaskQueueAdapter) Lease(ctx context.Context, now time.Time) (adminExportQueuedTask, bool, error) {
	if adapter.DB == nil {
		return adminExportQueuedTask{}, false, fmt.Errorf("postgres export task queue db is not configured")
	}
	duration := adapter.LeaseDuration
	if duration <= 0 {
		duration = 30 * time.Second
	}
	nonce, err := randomURLToken(32)
	if err != nil {
		return adminExportQueuedTask{}, false, fmt.Errorf("create export task lease token: %w", err)
	}
	leaseToken := adapter.WorkerID + ":" + nonce
	statement, err := buildPostgresExportTaskLeaseStatement(adapter.TenantID, leaseToken, now, duration)
	if err != nil {
		return adminExportQueuedTask{}, false, err
	}
	item, ok, err := adapter.queryTaskPayload(ctx, statement, now)
	if err == nil && ok {
		item.LeaseToken = leaseToken
	}
	return item, ok, err
}

func (adapter postgresExportTaskQueueAdapter) Complete(ctx context.Context, taskID string) error {
	if adapter.DB == nil {
		return fmt.Errorf("postgres export task queue db is not configured")
	}
	statement, err := buildPostgresExportTaskCompleteStatement(adapter.TenantID, taskID, adapter.WorkerID)
	if err != nil {
		return err
	}
	ctx = normalizePostgresExportTaskContext(ctx)
	result, err := adapter.DB.ExecContext(ctx, statement.SQL, statement.Args...)
	if err != nil {
		return err
	}
	if result == nil {
		return fmt.Errorf("postgres export task %s completion returned no result", taskID)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return fmt.Errorf("postgres export task %s lost its lease before completion", taskID)
	}
	return nil
}

func (adapter postgresExportTaskQueueAdapter) Release(ctx context.Context, taskID string, now time.Time) (adminExportQueuedTask, bool, error) {
	if adapter.DB == nil {
		return adminExportQueuedTask{}, false, fmt.Errorf("postgres export task queue db is not configured")
	}
	statement, err := buildPostgresExportTaskReleaseStatement(adapter.TenantID, taskID, adapter.WorkerID, now)
	if err != nil {
		return adminExportQueuedTask{}, false, err
	}
	return adapter.queryTaskPayload(ctx, statement, now)
}

func (adapter postgresExportTaskQueueAdapter) ExtendLease(ctx context.Context, taskID string, now time.Time, leaseDuration time.Duration) (adminExportQueuedTask, bool, error) {
	if adapter.DB == nil {
		return adminExportQueuedTask{}, false, fmt.Errorf("postgres export task queue db is not configured")
	}
	statement, err := buildPostgresExportTaskExtendLeaseStatement(adapter.TenantID, taskID, adapter.WorkerID, now, leaseDuration)
	if err != nil {
		return adminExportQueuedTask{}, false, err
	}
	return adapter.queryTaskPayload(ctx, statement, now)
}

func (adapter postgresExportTaskQueueAdapter) Retry(ctx context.Context, item adminExportQueuedTask, now time.Time) (adminExportQueuedTask, bool, error) {
	if adapter.DB == nil {
		return adminExportQueuedTask{}, false, fmt.Errorf("postgres export task queue db is not configured")
	}
	backoffSeconds := adminExportWorkerRetryBackoffSeconds(item.Document.RetryPolicy, item.Document.Attempt)
	statement, err := buildPostgresExportTaskRetryStatement(adapter.TenantID, item.Document.ID, adapter.WorkerID, now, backoffSeconds)
	if err != nil {
		return adminExportQueuedTask{}, false, err
	}
	return adapter.queryTaskPayload(ctx, statement, now)
}

func (adapter postgresExportTaskQueueAdapter) DeadLetter(ctx context.Context, taskID string, now time.Time, reason string) (adminExportQueuedTask, bool, error) {
	if adapter.DB == nil {
		return adminExportQueuedTask{}, false, fmt.Errorf("postgres export task queue db is not configured")
	}
	statement, err := buildPostgresExportTaskDeadLetterStatement(adapter.TenantID, taskID, adapter.WorkerID, now, reason)
	if err != nil {
		return adminExportQueuedTask{}, false, err
	}
	return adapter.queryTaskPayload(ctx, statement, now)
}

func (adapter postgresExportTaskQueueAdapter) queryTaskPayload(ctx context.Context, statement postgresExportTaskQueueStatement, now time.Time) (adminExportQueuedTask, bool, error) {
	var payload []byte
	ctx = normalizePostgresExportTaskContext(ctx)
	if err := adapter.DB.QueryRowContext(ctx, statement.SQL, statement.Args...).Scan(&payload); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return adminExportQueuedTask{}, false, nil
		}
		return adminExportQueuedTask{}, false, err
	}
	item, err := adapter.Resolver.HydratePayload(payload, adapter.SchemaData, "", now)
	if err != nil {
		return adminExportQueuedTask{}, false, err
	}
	return item, true, nil
}

func normalizePostgresExportTaskContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func postgresExportTaskQueueSchemaSQL() []string {
	return []string{
		strings.Join([]string{
			"CREATE TABLE IF NOT EXISTS export_worker_tasks (",
			"tenant_id text NOT NULL,",
			"task_id text NOT NULL,",
			"export_job_id text NOT NULL,",
			"status text NOT NULL CHECK (status IN ('queued', 'running')),",
			"attempt integer NOT NULL DEFAULT 0 CHECK (attempt >= 0),",
			"max_attempts integer NOT NULL DEFAULT 3 CHECK (max_attempts > 0),",
			"retry_not_before timestamptz,",
			"lease_owner text,",
			"lease_expires_at timestamptz,",
			"payload jsonb NOT NULL,",
			"created_at timestamptz NOT NULL DEFAULT now(),",
			"updated_at timestamptz NOT NULL DEFAULT now(),",
			"PRIMARY KEY (tenant_id, task_id)",
			")",
		}, " "),
		"CREATE INDEX IF NOT EXISTS export_worker_tasks_lease_idx ON export_worker_tasks (tenant_id, status, retry_not_before, created_at, task_id)",
		"CREATE INDEX IF NOT EXISTS export_worker_tasks_job_idx ON export_worker_tasks (tenant_id, export_job_id)",
		strings.Join([]string{
			"CREATE TABLE IF NOT EXISTS export_worker_task_dead_letters (",
			"tenant_id text NOT NULL,",
			"task_id text NOT NULL,",
			"export_job_id text NOT NULL,",
			"attempt integer NOT NULL CHECK (attempt >= 0),",
			"max_attempts integer NOT NULL CHECK (max_attempts > 0),",
			"dead_letter_reason text NOT NULL,",
			"dead_lettered_at timestamptz NOT NULL,",
			"payload jsonb NOT NULL,",
			"PRIMARY KEY (tenant_id, task_id)",
			")",
		}, " "),
		"CREATE INDEX IF NOT EXISTS export_worker_task_dead_letters_job_idx ON export_worker_task_dead_letters (tenant_id, export_job_id)",
	}
}

func buildPostgresExportTaskEnqueueStatement(item adminExportQueuedTask) (postgresExportTaskQueueStatement, error) {
	document := item.Document
	if strings.TrimSpace(document.TenantID) == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("tenant_id is required")
	}
	if strings.TrimSpace(document.ID) == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("export task id is required")
	}
	if strings.TrimSpace(document.ExportJobID) == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("export job id is required")
	}
	payload, err := json.Marshal(document)
	if err != nil {
		return postgresExportTaskQueueStatement{}, err
	}
	statement := strings.Join([]string{
		"INSERT INTO export_worker_tasks",
		"(tenant_id, task_id, export_job_id, status, attempt, max_attempts, retry_not_before, lease_owner, lease_expires_at, payload, created_at, updated_at)",
		"VALUES ($1, $2, $3, 'queued', $4, $5, NULL, NULL, NULL, $6::jsonb, now(), now())",
		"ON CONFLICT (tenant_id, task_id) DO NOTHING",
	}, " ")
	return postgresExportTaskQueueStatement{
		SQL:  statement,
		Args: []any{document.TenantID, document.ID, document.ExportJobID, document.Attempt, document.MaxAttempts, string(payload)},
	}, nil
}

func buildPostgresExportTaskLeaseStatement(tenantID, workerID string, now time.Time, leaseDuration time.Duration) (postgresExportTaskQueueStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	workerID = strings.TrimSpace(workerID)
	if tenantID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("tenant_id is required")
	}
	if workerID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("worker_id is required")
	}
	if leaseDuration <= 0 {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("lease duration must be greater than zero")
	}
	leaseExpiresAt := now.UTC().Add(leaseDuration)
	statement := strings.Join([]string{
		"UPDATE export_worker_tasks",
		"SET status = 'running', lease_owner = $2, lease_expires_at = $3::timestamptz, retry_not_before = NULL, updated_at = $4::timestamptz,",
		"attempt = CASE WHEN status = 'running' THEN attempt + 1 ELSE attempt END,",
		"payload = jsonb_set(jsonb_set(jsonb_set(payload, '{status}', to_jsonb('running'::text), true), '{lease_expires_at}', to_jsonb($3::timestamptz), true), '{attempt}', to_jsonb(CASE WHEN status = 'running' THEN attempt + 1 ELSE attempt END), true)",
		"WHERE tenant_id = $1 AND task_id = (",
		"SELECT task_id FROM export_worker_tasks",
		"WHERE tenant_id = $1 AND ((status = 'queued' AND (retry_not_before IS NULL OR retry_not_before <= $4::timestamptz))",
		"OR (status = 'running' AND lease_expires_at <= $4::timestamptz))",
		"ORDER BY created_at ASC, task_id ASC",
		"FOR UPDATE SKIP LOCKED LIMIT 1",
		")",
		"RETURNING payload",
	}, " ")
	return postgresExportTaskQueueStatement{SQL: statement, Args: []any{tenantID, workerID, leaseExpiresAt, now.UTC()}}, nil
}

func buildPostgresExportTaskCompleteStatement(tenantID, taskID, leaseToken string) (postgresExportTaskQueueStatement, error) {
	tenantID, taskID, err := normalizePostgresExportTaskIDs(tenantID, taskID)
	if err != nil {
		return postgresExportTaskQueueStatement{}, err
	}
	if strings.TrimSpace(leaseToken) == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("export task lease token is required")
	}
	statement := "DELETE FROM export_worker_tasks WHERE tenant_id = $1 AND task_id = $2 AND status = 'running' AND lease_owner = $3"
	return postgresExportTaskQueueStatement{SQL: statement, Args: []any{tenantID, taskID, leaseToken}}, nil
}

func buildPostgresExportTaskReleaseStatement(tenantID, taskID, leaseToken string, now time.Time) (postgresExportTaskQueueStatement, error) {
	tenantID, taskID, err := normalizePostgresExportTaskIDs(tenantID, taskID)
	if err != nil {
		return postgresExportTaskQueueStatement{}, err
	}
	if strings.TrimSpace(leaseToken) == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("export task lease token is required")
	}
	statement := strings.Join([]string{
		"UPDATE export_worker_tasks",
		"SET status = 'queued', lease_owner = NULL, lease_expires_at = NULL, updated_at = $4,",
		"payload = jsonb_set(jsonb_set(payload, '{status}', to_jsonb('queued'::text), true), '{lease_expires_at}', 'null'::jsonb, true)",
		"WHERE tenant_id = $1 AND task_id = $2 AND status = 'running' AND lease_owner = $3",
		"RETURNING payload",
	}, " ")
	return postgresExportTaskQueueStatement{SQL: statement, Args: []any{tenantID, taskID, leaseToken, now.UTC()}}, nil
}

func buildPostgresExportTaskExtendLeaseStatement(tenantID, taskID, workerID string, now time.Time, leaseDuration time.Duration) (postgresExportTaskQueueStatement, error) {
	tenantID, taskID, err := normalizePostgresExportTaskIDs(tenantID, taskID)
	if err != nil {
		return postgresExportTaskQueueStatement{}, err
	}
	workerID = strings.TrimSpace(workerID)
	if workerID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("worker_id is required")
	}
	if leaseDuration <= 0 {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("lease duration must be greater than zero")
	}
	leaseExpiresAt := now.UTC().Add(leaseDuration)
	statement := strings.Join([]string{
		"UPDATE export_worker_tasks",
		"SET lease_expires_at = $4::timestamptz, updated_at = $5::timestamptz,",
		"payload = jsonb_set(jsonb_set(payload, '{lease_expires_at}', to_jsonb($4::timestamptz), true), '{metadata,lease_extended_at}', to_jsonb($5::timestamptz), true)",
		"WHERE tenant_id = $1 AND task_id = $2 AND lease_owner = $3 AND status = 'running'",
		"RETURNING payload",
	}, " ")
	return postgresExportTaskQueueStatement{SQL: statement, Args: []any{tenantID, taskID, workerID, leaseExpiresAt, now.UTC()}}, nil
}

func buildPostgresExportTaskRetryStatement(tenantID, taskID, leaseToken string, now time.Time, backoffSeconds int) (postgresExportTaskQueueStatement, error) {
	tenantID, taskID, err := normalizePostgresExportTaskIDs(tenantID, taskID)
	if err != nil {
		return postgresExportTaskQueueStatement{}, err
	}
	if strings.TrimSpace(leaseToken) == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("export task lease token is required")
	}
	if backoffSeconds < 0 {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("backoff_seconds must be greater than or equal to zero")
	}
	retryNotBefore := now.UTC().Add(time.Duration(backoffSeconds) * time.Second)
	statement := strings.Join([]string{
		"UPDATE export_worker_tasks",
		"SET status = 'queued', attempt = attempt + 1, lease_owner = NULL, lease_expires_at = NULL, retry_not_before = $4::timestamptz, updated_at = $5::timestamptz,",
		"payload = jsonb_set(jsonb_set(jsonb_set(jsonb_set(jsonb_set(jsonb_set(payload, '{status}', to_jsonb('queued'::text), true), '{attempt}', to_jsonb(attempt + 1), true), '{lease_expires_at}', 'null'::jsonb, true), '{metadata,retry_not_before}', to_jsonb($4::timestamptz), true), '{metadata,retry_scheduled_at}', to_jsonb($5::timestamptz), true), '{metadata,retry_backoff_seconds}', to_jsonb($6::int), true)",
		"WHERE tenant_id = $1 AND task_id = $2 AND lease_owner = $3 AND status = 'running' AND attempt + 1 < max_attempts",
		"RETURNING payload",
	}, " ")
	return postgresExportTaskQueueStatement{SQL: statement, Args: []any{tenantID, taskID, leaseToken, retryNotBefore, now.UTC(), backoffSeconds}}, nil
}

func buildPostgresExportTaskDeadLetterStatement(tenantID, taskID, leaseToken string, now time.Time, reason string) (postgresExportTaskQueueStatement, error) {
	tenantID, taskID, err := normalizePostgresExportTaskIDs(tenantID, taskID)
	if err != nil {
		return postgresExportTaskQueueStatement{}, err
	}
	if strings.TrimSpace(leaseToken) == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("export task lease token is required")
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "max_attempts_exhausted"
	}
	statement := strings.Join([]string{
		"WITH moved AS (",
		"DELETE FROM export_worker_tasks",
		"WHERE tenant_id = $1 AND task_id = $2 AND lease_owner = $3 AND status = 'running' AND attempt + 1 >= max_attempts",
		"RETURNING tenant_id, task_id, export_job_id, attempt, max_attempts, payload",
		")",
		"INSERT INTO export_worker_task_dead_letters",
		"(tenant_id, task_id, export_job_id, attempt, max_attempts, dead_letter_reason, dead_lettered_at, payload)",
		"SELECT tenant_id, task_id, export_job_id, attempt, max_attempts, $4, $5,",
		"jsonb_set(jsonb_set(payload, '{status}', to_jsonb('failed'::text), true), '{metadata,dead_letter_reason}', to_jsonb($4::text), true)",
		"FROM moved",
		"RETURNING payload",
	}, " ")
	return postgresExportTaskQueueStatement{SQL: statement, Args: []any{tenantID, taskID, leaseToken, reason, now.UTC()}}, nil
}

func normalizePostgresExportTaskIDs(tenantID, taskID string) (string, string, error) {
	tenantID = strings.TrimSpace(tenantID)
	taskID = strings.TrimSpace(taskID)
	if tenantID == "" {
		return "", "", fmt.Errorf("tenant_id is required")
	}
	if taskID == "" {
		return "", "", fmt.Errorf("export task id is required")
	}
	return tenantID, taskID, nil
}
