package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

type postgresAdminExportJobStore struct {
	DB            *sql.DB
	LeaseTenantID string
	LeaseTaskID   string
	LeaseToken    string
}

const postgresAdminExportJobUpdateTimeout = 30 * time.Second

func (store postgresAdminExportJobStore) Create(req adminExportJobRequest, tenantID, adminPrincipalID string, now time.Time) adminExportJob {
	return newAdminExportJob(req, tenantID, adminPrincipalID, now)
}

func (store postgresAdminExportJobStore) PersistCreated(ctx context.Context, job adminExportJob, now time.Time) error {
	return store.Upsert(ctx, job, now)
}

func (store postgresAdminExportJobStore) List(tenantID string) []adminExportJob {
	ctx, cancel := context.WithTimeout(context.Background(), postgresAdminExportJobUpdateTimeout)
	defer cancel()
	jobs, err := store.ListByTenant(ctx, tenantID, 200)
	if err != nil {
		return nil
	}
	return jobs
}

func postgresAdminExportJobSchemaSQL() []string {
	return []string{
		strings.Join([]string{
			"CREATE TABLE IF NOT EXISTS admin_export_jobs (",
			"tenant_id text NOT NULL,",
			"export_job_id text NOT NULL,",
			"status text NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled')),",
			"created_at timestamptz NOT NULL,",
			"updated_at timestamptz NOT NULL DEFAULT now(),",
			"payload jsonb NOT NULL,",
			"PRIMARY KEY (tenant_id, export_job_id)",
			")",
		}, " "),
		"CREATE UNIQUE INDEX IF NOT EXISTS admin_export_jobs_export_job_id_unique_idx ON admin_export_jobs (export_job_id)",
		"CREATE INDEX IF NOT EXISTS admin_export_jobs_tenant_created_idx ON admin_export_jobs (tenant_id, created_at DESC, export_job_id)",
		"CREATE INDEX IF NOT EXISTS admin_export_jobs_tenant_status_idx ON admin_export_jobs (tenant_id, status, created_at DESC)",
	}
}

func (store postgresAdminExportJobStore) Upsert(ctx context.Context, job adminExportJob, now time.Time) error {
	if store.DB == nil {
		return fmt.Errorf("postgres admin export job db is not configured")
	}
	statement, err := buildPostgresAdminExportJobUpsertStatement(job, now)
	if err != nil {
		return err
	}
	ctx = normalizePostgresExportTaskContext(ctx)
	_, err = store.DB.ExecContext(ctx, statement.SQL, statement.Args...)
	return err
}

func (store postgresAdminExportJobStore) GetByTenant(ctx context.Context, tenantID, jobID string) (adminExportJob, bool, error) {
	if store.DB == nil {
		return adminExportJob{}, false, fmt.Errorf("postgres admin export job db is not configured")
	}
	statement, err := buildPostgresAdminExportJobGetStatement(tenantID, jobID)
	if err != nil {
		return adminExportJob{}, false, err
	}
	ctx = normalizePostgresExportTaskContext(ctx)
	var payload []byte
	if err := store.DB.QueryRowContext(ctx, statement.SQL, statement.Args...).Scan(&payload); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return adminExportJob{}, false, nil
		}
		return adminExportJob{}, false, err
	}
	job, err := decodePostgresAdminExportJobPayload(payload)
	if err != nil {
		return adminExportJob{}, false, err
	}
	return job, true, nil
}

func (store postgresAdminExportJobStore) ListByTenant(ctx context.Context, tenantID string, limit int) ([]adminExportJob, error) {
	if store.DB == nil {
		return nil, fmt.Errorf("postgres admin export job db is not configured")
	}
	statement, err := buildPostgresAdminExportJobListStatement(tenantID, limit)
	if err != nil {
		return nil, err
	}
	ctx = normalizePostgresExportTaskContext(ctx)
	rows, err := store.DB.QueryContext(ctx, statement.SQL, statement.Args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var jobs []adminExportJob
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		job, err := decodePostgresAdminExportJobPayload(payload)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return jobs, nil
}

func (store postgresAdminExportJobStore) Get(id string) (adminExportJob, bool) {
	job, ok, err := store.getByID(context.Background(), id)
	if err != nil {
		return adminExportJob{}, false
	}
	return job, ok
}

func (store postgresAdminExportJobStore) MarkRunning(id string, now time.Time) (adminExportJob, error) {
	return store.updateByID(id, now, func(job *adminExportJob) error {
		if job.Status != "queued" && !(store.LeaseToken != "" && job.Status == "running") {
			return fmt.Errorf("export job %s cannot transition from %s to running", id, job.Status)
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
		return nil
	})
}

func (store postgresAdminExportJobStore) MarkProgress(id string, rowsExported int, phase string, now time.Time) (adminExportJob, error) {
	return store.updateByID(id, now, func(job *adminExportJob) error {
		if job.Status != "running" {
			return adminExportJobStoppedError{ID: id, Status: job.Status}
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
		return nil
	})
}

func (store postgresAdminExportJobStore) MarkCompleted(id string, rowCount, totalMatches int, truncated bool, objectRef, checksum string, coverage *adminExportRegionCoverage, now time.Time) (adminExportJob, error) {
	return store.updateByID(id, now, func(job *adminExportJob) error {
		if job.Status != "running" {
			return fmt.Errorf("export job %s cannot transition from %s to completed", id, job.Status)
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
		return nil
	})
}

func (store postgresAdminExportJobStore) MarkFailed(id, code string, now time.Time) (adminExportJob, error) {
	return store.MarkFailedWithMetadata(id, code, nil, now)
}

func (store postgresAdminExportJobStore) MarkFailedWithMetadata(id, code string, metadata map[string]any, now time.Time) (adminExportJob, error) {
	return store.updateByID(id, now, func(job *adminExportJob) error {
		return failPostgresAdminExportJob(job, id, code, metadata, now)
	})
}

func failPostgresAdminExportJob(job *adminExportJob, id, code string, metadata map[string]any, now time.Time) error {
	if job.Status != "queued" && job.Status != "running" {
		return fmt.Errorf("export job %s cannot transition from %s to failed", id, job.Status)
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
	return nil
}

func (store postgresAdminExportJobStore) ResetForRetry(id string, now time.Time) (adminExportJob, error) {
	if store.LeaseToken == "" {
		return adminExportJob{}, fmt.Errorf("export job retry requires a task lease")
	}
	return store.updateByID(id, now, func(job *adminExportJob) error {
		if job.Status != "queued" && job.Status != "running" && job.Status != "failed" {
			return fmt.Errorf("export job %s cannot retry from %s", id, job.Status)
		}
		job.Status = "queued"
		job.ErrorCode = nil
		job.CompletedAt = nil
		job.ObjectRef = nil
		job.PayloadChecksum = nil
		job.RowCount = 0
		if job.Metadata == nil {
			job.Metadata = map[string]any{}
		}
		job.Metadata["progress_phase"] = "queued"
		job.Metadata["rows_exported"] = 0
		job.Metadata["last_progress_at"] = now.UTC().Format(time.RFC3339)
		return nil
	})
}

func (store postgresAdminExportJobStore) DeadLetterTask(ctx context.Context, taskID, jobID string, attempt, maxAttempts int, now time.Time, reason string, evaluator decision.Evaluator, sourceIP string) (adminExportJob, model.AuditLog, error) {
	if store.DB == nil || store.LeaseTenantID == "" || store.LeaseToken == "" || store.LeaseTaskID != taskID {
		return adminExportJob{}, model.AuditLog{}, fmt.Errorf("export task dead letter requires a matching task lease")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	ctx = normalizePostgresExportTaskContext(ctx)
	tx, err := store.DB.BeginTx(ctx, nil)
	if err != nil {
		return adminExportJob{}, model.AuditLog{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	get, err := buildPostgresAdminExportJobGetByIDForUpdateStatement(jobID)
	if err != nil {
		return adminExportJob{}, model.AuditLog{}, err
	}
	var jobPayload []byte
	if err := tx.QueryRowContext(ctx, get.SQL, get.Args...).Scan(&jobPayload); err != nil {
		return adminExportJob{}, model.AuditLog{}, err
	}
	job, err := decodePostgresAdminExportJobPayload(jobPayload)
	if err != nil {
		return adminExportJob{}, model.AuditLog{}, err
	}
	if job.TenantID != store.LeaseTenantID {
		return adminExportJob{}, model.AuditLog{}, fmt.Errorf("export task and job tenant differ")
	}
	metadata := map[string]any{
		"export_worker_task_id": taskID,
		"attempt":               attempt,
		"max_attempts":          maxAttempts,
		"dead_letter_reason":    reason,
	}
	if err := failPostgresAdminExportJob(&job, jobID, reason, metadata, now); err != nil {
		return adminExportJob{}, model.AuditLog{}, err
	}
	audit := adminExportJobAuditLog("admin_export_failed", job, evaluator, sourceIP)
	auditOutbox, err := buildPostgresAdminAuditOutboxInsertStatement(audit, now)
	if err != nil {
		return adminExportJob{}, model.AuditLog{}, err
	}
	move, err := buildPostgresExportTaskDeadLetterStatement(store.LeaseTenantID, taskID, store.LeaseToken, now, reason)
	if err != nil {
		return adminExportJob{}, model.AuditLog{}, err
	}
	var movedPayload []byte
	if err := tx.QueryRowContext(ctx, move.SQL, move.Args...).Scan(&movedPayload); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return adminExportJob{}, model.AuditLog{}, fmt.Errorf("export task %s lost its lease before dead letter", taskID)
		}
		return adminExportJob{}, model.AuditLog{}, err
	}
	upsert, err := buildPostgresAdminExportJobUpsertStatement(job, now)
	if err != nil {
		return adminExportJob{}, model.AuditLog{}, err
	}
	if _, err := tx.ExecContext(ctx, upsert.SQL, upsert.Args...); err != nil {
		return adminExportJob{}, model.AuditLog{}, err
	}
	if _, err := tx.ExecContext(ctx, auditOutbox.SQL, auditOutbox.Args...); err != nil {
		return adminExportJob{}, model.AuditLog{}, err
	}
	if err := tx.Commit(); err != nil {
		return adminExportJob{}, model.AuditLog{}, err
	}
	committed = true
	return job, audit, nil
}

func (store postgresAdminExportJobStore) MarkCancelled(id, tenantID, cancelledBy, reason string, now time.Time) (adminExportJob, error) {
	return store.updateByID(id, now, func(job *adminExportJob) error {
		if job.TenantID != tenantID {
			return fmt.Errorf("export job %s is absent", id)
		}
		if job.Status != "queued" && job.Status != "running" {
			return fmt.Errorf("export job %s cannot transition from %s to cancelled", id, job.Status)
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
		return nil
	})
}

func (store postgresAdminExportJobStore) updateByID(id string, now time.Time, mutate func(*adminExportJob) error) (adminExportJob, error) {
	if store.DB == nil {
		return adminExportJob{}, fmt.Errorf("postgres admin export job db is not configured")
	}
	if mutate == nil {
		return adminExportJob{}, fmt.Errorf("admin export job update function is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	ctx, cancel := context.WithTimeout(context.Background(), postgresAdminExportJobUpdateTimeout)
	defer cancel()
	ctx = normalizePostgresExportTaskContext(ctx)
	tx, err := store.DB.BeginTx(ctx, nil)
	if err != nil {
		return adminExportJob{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	statement, err := buildPostgresAdminExportJobGetByIDForUpdateStatement(id)
	if err != nil {
		return adminExportJob{}, err
	}
	var payload []byte
	if err := tx.QueryRowContext(ctx, statement.SQL, statement.Args...).Scan(&payload); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return adminExportJob{}, fmt.Errorf("export job %s is absent", id)
		}
		return adminExportJob{}, err
	}
	job, err := decodePostgresAdminExportJobPayload(payload)
	if err != nil {
		return adminExportJob{}, err
	}
	if store.LeaseToken != "" {
		if store.LeaseTenantID == "" || store.LeaseTaskID == "" || job.TenantID != store.LeaseTenantID {
			return adminExportJob{}, fmt.Errorf("export job %s has no matching task lease scope", id)
		}
		var present int
		err := tx.QueryRowContext(ctx, strings.Join([]string{
			"SELECT 1 FROM export_worker_tasks",
			"WHERE tenant_id = $1 AND task_id = $2 AND export_job_id = $3",
			"AND status = 'running' AND lease_owner = $4 FOR UPDATE",
		}, " "), store.LeaseTenantID, store.LeaseTaskID, id, store.LeaseToken).Scan(&present)
		if errors.Is(err, sql.ErrNoRows) {
			return adminExportJob{}, fmt.Errorf("export job %s task lease was lost", id)
		}
		if err != nil {
			return adminExportJob{}, err
		}
	}
	if err := mutate(&job); err != nil {
		return adminExportJob{}, err
	}
	upsert, err := buildPostgresAdminExportJobUpsertStatement(job, now)
	if err != nil {
		return adminExportJob{}, err
	}
	if _, err := tx.ExecContext(ctx, upsert.SQL, upsert.Args...); err != nil {
		return adminExportJob{}, err
	}
	if err := tx.Commit(); err != nil {
		return adminExportJob{}, err
	}
	committed = true
	return job, nil
}

func (store postgresAdminExportJobStore) getByID(ctx context.Context, jobID string) (adminExportJob, bool, error) {
	if store.DB == nil {
		return adminExportJob{}, false, fmt.Errorf("postgres admin export job db is not configured")
	}
	statement, err := buildPostgresAdminExportJobGetByIDStatement(jobID)
	if err != nil {
		return adminExportJob{}, false, err
	}
	ctx = normalizePostgresExportTaskContext(ctx)
	var payload []byte
	if err := store.DB.QueryRowContext(ctx, statement.SQL, statement.Args...).Scan(&payload); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return adminExportJob{}, false, nil
		}
		return adminExportJob{}, false, err
	}
	job, err := decodePostgresAdminExportJobPayload(payload)
	if err != nil {
		return adminExportJob{}, false, err
	}
	return job, true, nil
}

func buildPostgresAdminExportJobUpsertStatement(job adminExportJob, now time.Time) (postgresExportTaskQueueStatement, error) {
	tenantID := strings.TrimSpace(job.TenantID)
	jobID := strings.TrimSpace(job.ID)
	status := strings.TrimSpace(job.Status)
	if tenantID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("tenant_id is required")
	}
	if jobID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("export job id is required")
	}
	if status == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("export job status is required")
	}
	createdAt, err := time.Parse(time.RFC3339, strings.TrimSpace(job.CreatedAt))
	if err != nil {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("parse export job created_at: %w", err)
	}
	payload, err := json.Marshal(job)
	if err != nil {
		return postgresExportTaskQueueStatement{}, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	statement := strings.Join([]string{
		"INSERT INTO admin_export_jobs",
		"(tenant_id, export_job_id, status, created_at, updated_at, payload)",
		"VALUES ($1, $2, $3, $4::timestamptz, $5::timestamptz, $6::jsonb)",
		"ON CONFLICT (tenant_id, export_job_id) DO UPDATE SET",
		"status = EXCLUDED.status,",
		"updated_at = EXCLUDED.updated_at,",
		"payload = EXCLUDED.payload",
	}, " ")
	return postgresExportTaskQueueStatement{
		SQL:  statement,
		Args: []any{tenantID, jobID, status, createdAt.UTC(), now.UTC(), string(payload)},
	}, nil
}

func decodePostgresAdminExportJobPayload(payload []byte) (adminExportJob, error) {
	if len(payload) == 0 {
		return adminExportJob{}, fmt.Errorf("admin export job payload is required")
	}
	var job adminExportJob
	if err := json.Unmarshal(payload, &job); err != nil {
		return adminExportJob{}, fmt.Errorf("decode admin export job payload: %w", err)
	}
	if strings.TrimSpace(job.ID) == "" || strings.TrimSpace(job.TenantID) == "" {
		return adminExportJob{}, fmt.Errorf("admin export job payload is missing id or tenant_id")
	}
	return job, nil
}

func buildPostgresAdminExportJobGetStatement(tenantID, jobID string) (postgresExportTaskQueueStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	jobID = strings.TrimSpace(jobID)
	if tenantID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("tenant_id is required")
	}
	if jobID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("export job id is required")
	}
	return postgresExportTaskQueueStatement{
		SQL:  "SELECT payload FROM admin_export_jobs WHERE tenant_id = $1 AND export_job_id = $2",
		Args: []any{tenantID, jobID},
	}, nil
}

func buildPostgresAdminExportJobGetByIDStatement(jobID string) (postgresExportTaskQueueStatement, error) {
	jobID = strings.TrimSpace(jobID)
	if jobID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("export job id is required")
	}
	return postgresExportTaskQueueStatement{
		SQL: strings.Join([]string{
			"SELECT payload FROM admin_export_jobs",
			"WHERE export_job_id = $1",
			"ORDER BY created_at DESC, tenant_id ASC",
			"LIMIT 1",
		}, " "),
		Args: []any{jobID},
	}, nil
}

func buildPostgresAdminExportJobGetByIDForUpdateStatement(jobID string) (postgresExportTaskQueueStatement, error) {
	statement, err := buildPostgresAdminExportJobGetByIDStatement(jobID)
	if err != nil {
		return postgresExportTaskQueueStatement{}, err
	}
	statement.SQL += " FOR UPDATE"
	return statement, nil
}

func buildPostgresAdminExportJobListStatement(tenantID string, limit int) (postgresExportTaskQueueStatement, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return postgresExportTaskQueueStatement{}, fmt.Errorf("tenant_id is required")
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	return postgresExportTaskQueueStatement{
		SQL: strings.Join([]string{
			"SELECT payload FROM admin_export_jobs",
			"WHERE tenant_id = $1",
			"ORDER BY created_at DESC, export_job_id DESC",
			"LIMIT $2",
		}, " "),
		Args: []any{tenantID, limit},
	}, nil
}
