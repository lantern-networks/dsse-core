package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/hotstore"
	"github.com/lib/pq"
)

// PostgreSQL jobs freeze row receipts. ClickHouse jobs freeze an insertion-time
// predicate and use one asynchronous mutation, regardless of the row count.
// The durable job ledger lives in shared CP PostgreSQL, outside hot_events.
type manualHotLogDeleteManager struct {
	db       *sql.DB
	hotCH    *hotstore.ClickHouseStore
	kind     string
	identity string
	holds    *legalHoldStore
}

type manualHotLogDeleteJob struct {
	ID            string     `json:"job_id"`
	Tenant        string     `json:"tenant_id"`
	Stream        string     `json:"stream"`
	Cutoff        time.Time  `json:"before"`
	PreviewAt     *time.Time `json:"preview_at,omitempty"`
	RequestedBy   string     `json:"requested_by"`
	Status        string     `json:"status"`
	PreviewCount  int64      `json:"preview_count"`
	ConfirmedGone int64      `json:"confirmed_absent_count"`
	PreviewDigest string     `json:"preview_digest"`
	FailureCode   string     `json:"failure_code,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	ConfirmedAt   *time.Time `json:"confirmed_at,omitempty"`
	FinishedAt    *time.Time `json:"finished_at,omitempty"`
}

var manualHotLogStream = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func newManualHotLogDeleteManager(db *sql.DB, store hotstore.Store, cpDSN, hotDSN string, holds *legalHoldStore) *manualHotLogDeleteManager {
	if db == nil || holds == nil {
		return nil
	}
	m := &manualHotLogDeleteManager{db: db, holds: holds}
	switch hot := store.(type) {
	case *hotstore.ClickHouseStore:
		m.hotCH, m.kind, m.identity = hot, "clickhouse", hot.RetentionIdentity()
	case *hotstore.PostgresStore:
		// A PG hot store in another database cannot be atomically journaled with
		// the CP job. Refuse the feature in that topology.
		if strings.TrimSpace(cpDSN) != "" && strings.TrimSpace(cpDSN) == strings.TrimSpace(hotDSN) {
			m.kind = "postgres"
			sum := sha256.Sum256([]byte(cpDSN))
			m.identity = hex.EncodeToString(sum[:])
		}
	}
	if m.kind == "" {
		return nil
	}
	return m
}

func (m *manualHotLogDeleteManager) preview(ctx context.Context, tenant, stream string, cutoff time.Time, actor string) (manualHotLogDeleteJob, error) {
	if m == nil || tenant == "" || actor == "" || !manualHotLogStream.MatchString(stream) || cutoff.IsZero() || !cutoff.Before(time.Now().UTC()) {
		return manualHotLogDeleteJob{}, fmt.Errorf("tenant, stream, past UTC cutoff, and actor are required")
	}
	if !cpLeaderElectorInstance.IsLeader() {
		return manualHotLogDeleteJob{}, fmt.Errorf("only the active CP can prepare deletion")
	}
	_, held, _, err := m.holds.adminStatus(ctx, tenant)
	if err != nil || held {
		return manualHotLogDeleteJob{}, fmt.Errorf("tenant legal hold state forbids deletion")
	}
	job := manualHotLogDeleteJob{ID: randomEdgeID("hot_delete_", time.Now().UTC()), Tenant: tenant, Stream: stream, Cutoff: cutoff.UTC(), RequestedBy: actor, Status: "previewing"}
	_, err = m.db.ExecContext(ctx, `INSERT INTO manual_hot_log_delete_jobs(job_id,tenant_id,stream,cutoff,requested_by,store_kind,store_identity,status)
		VALUES ($1,$2,$3,$4,$5,$6,$7,'previewing')`, job.ID, tenant, stream, job.Cutoff, actor, m.kind, m.identity)
	if err != nil {
		return manualHotLogDeleteJob{}, err
	}
	if m.hotCH == nil {
		_, err = m.db.ExecContext(ctx, `INSERT INTO manual_hot_log_delete_candidates(job_id,receipt,row_at)
			SELECT $1,event_id,received_at FROM hot_events WHERE tenant_id=$2 AND stream=$3 AND occurred_at<$4`, job.ID, tenant, stream, cutoff)
	} else {
		var count int64
		var previewAt time.Time
		count, previewAt, err = m.hotCH.ManualDeletePreview(ctx, tenant, stream, cutoff)
		job.PreviewCount, job.PreviewAt = count, &previewAt
	}
	if err != nil {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), cpStateBlobDBTimeout)
		defer cancel()
		_, _ = m.db.ExecContext(cleanup, `UPDATE manual_hot_log_delete_jobs SET status='failed',failure_code='preview_failed',updated_at=now() WHERE job_id=$1`, job.ID)
		return manualHotLogDeleteJob{}, err
	}
	if m.hotCH == nil {
		if err := m.db.QueryRowContext(ctx, `SELECT count(*) FROM manual_hot_log_delete_candidates WHERE job_id=$1`, job.ID).Scan(&job.PreviewCount); err != nil {
			return manualHotLogDeleteJob{}, err
		}
	}
	job.PreviewDigest = manualHotLogDeleteDigest(job)
	_, err = m.db.ExecContext(ctx, `UPDATE manual_hot_log_delete_jobs SET status='preview_ready',preview_count=$2,preview_digest=$3,preview_at=$4,updated_at=now() WHERE job_id=$1 AND status='previewing'`, job.ID, job.PreviewCount, job.PreviewDigest, job.PreviewAt)
	if err != nil {
		return manualHotLogDeleteJob{}, err
	}
	return m.get(ctx, job.ID)
}

func manualHotLogDeleteDigest(job manualHotLogDeleteJob) string {
	preview := ""
	if job.PreviewAt != nil {
		preview = job.PreviewAt.UTC().Format(time.RFC3339Nano)
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%d\x00%s", job.ID, job.Tenant, job.Stream, job.Cutoff.UTC().Format(time.RFC3339Nano), job.PreviewCount, preview)))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (m *manualHotLogDeleteManager) get(ctx context.Context, id string) (manualHotLogDeleteJob, error) {
	var j manualHotLogDeleteJob
	var finished, confirmed, previewAt sql.NullTime
	err := m.db.QueryRowContext(ctx, `SELECT job_id,tenant_id,stream,cutoff,preview_at,requested_by,status,preview_count,
		deleted_count+already_missing_count,preview_digest,failure_code,created_at,confirmed_at,finished_at
		FROM manual_hot_log_delete_jobs WHERE job_id=$1`, id).Scan(&j.ID, &j.Tenant, &j.Stream, &j.Cutoff, &previewAt, &j.RequestedBy, &j.Status, &j.PreviewCount, &j.ConfirmedGone, &j.PreviewDigest, &j.FailureCode, &j.CreatedAt, &confirmed, &finished)
	if previewAt.Valid {
		j.PreviewAt = &previewAt.Time
	}
	if confirmed.Valid {
		j.ConfirmedAt = &confirmed.Time
	}
	if finished.Valid {
		j.FinishedAt = &finished.Time
	}
	return j, err
}

func (m *manualHotLogDeleteManager) cancel(ctx context.Context, id string) (manualHotLogDeleteJob, error) {
	if m == nil || m.hotCH == nil || !cpLeaderElectorInstance.IsLeader() {
		return manualHotLogDeleteJob{}, fmt.Errorf("active ClickHouse control plane required")
	}
	job, err := m.get(ctx, id)
	if err != nil || job.Status != "running" {
		return job, fmt.Errorf("only a running ClickHouse deletion can be cancelled")
	}
	result, err := m.db.ExecContext(ctx, `UPDATE manual_hot_log_delete_jobs SET failure_code='mutation_cancel_requested',updated_at=now()
		WHERE job_id=$1 AND status='running' AND store_kind='clickhouse' AND store_identity=$2`, id, m.identity)
	if err != nil {
		return job, err
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		return job, fmt.Errorf("deletion job changed before cancellation")
	}
	if err = m.hotCH.ManualDeleteKill(ctx, id); err != nil {
		return job, err
	}
	return m.get(ctx, id)
}

func (m *manualHotLogDeleteManager) list(ctx context.Context, tenant string) ([]manualHotLogDeleteJob, error) {
	query := `SELECT job_id FROM manual_hot_log_delete_jobs`
	args := []any{}
	if tenant != "" {
		query += ` WHERE tenant_id=$1`
		args = append(args, tenant)
	}
	query += ` ORDER BY created_at DESC, job_id DESC LIMIT 100`
	rows, err := m.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			break
		}
		ids = append(ids, id)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return nil, err
	}
	jobs := make([]manualHotLogDeleteJob, 0, len(ids))
	for _, id := range ids {
		job, err := m.get(ctx, id)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	return jobs, nil
}

func (m *manualHotLogDeleteManager) confirm(ctx context.Context, id, tenant, digest string) (manualHotLogDeleteJob, error) {
	if !cpLeaderElectorInstance.IsLeader() {
		return manualHotLogDeleteJob{}, fmt.Errorf("only the active CP can confirm deletion")
	}
	j, err := m.get(ctx, id)
	if err != nil {
		return j, err
	}
	if j.Tenant != tenant || digest != j.PreviewDigest || digest == "" || (j.Status != "preview_ready" && j.Status != "failed") {
		return j, fmt.Errorf("job scope, confirmation digest, or status does not match")
	}
	if m.hotCH != nil && j.Status == "failed" && j.FailureCode != "mutation_not_submitted" && j.FailureCode != "mutation_not_present" {
		// An observed, incomplete mutation may still be deleting rows. Only a
		// definitively unsubmitted or absent mutation can reuse its frozen scope.
		return j, fmt.Errorf("ClickHouse deletion failed; prepare a new preview for remaining rows")
	}
	_, held, _, err := m.holds.adminStatus(ctx, tenant)
	if err != nil || held {
		return j, fmt.Errorf("tenant legal hold state forbids deletion")
	}
	if j.Status == "preview_ready" {
		present, err := m.presentPreviewCount(ctx, j)
		if err != nil {
			return j, err
		}
		if present != j.PreviewCount {
			_, err := m.db.ExecContext(ctx, `UPDATE manual_hot_log_delete_jobs SET status='stale',failure_code='preview_changed',updated_at=now()
				WHERE job_id=$1 AND tenant_id=$2 AND status='preview_ready'`, id, tenant)
			if err != nil {
				return j, err
			}
			return j, fmt.Errorf("preview changed; prepare a new confirmation")
		}
	}
	result, err := m.db.ExecContext(ctx, `UPDATE manual_hot_log_delete_jobs SET status='queued',failure_code='',mutation_id='',confirmed_at=COALESCE(confirmed_at,now()),updated_at=now()
		WHERE job_id=$1 AND tenant_id=$2 AND preview_digest=$3 AND status IN ('preview_ready','failed') AND store_kind=$4 AND store_identity=$5`, id, tenant, digest, m.kind, m.identity)
	if err != nil {
		return j, err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return j, fmt.Errorf("job store identity changed or job is no longer confirmable")
	}
	return m.get(ctx, id)
}

// Recheck the frozen receipts before accepting a first confirmation. A later
// arrival is outside the journal, while a row removed by normal retention or
// another administrator makes the old preview stale. A failed, partially run
// job can be retried from its remaining receipts without a new preview.
func (m *manualHotLogDeleteManager) presentPreviewCount(ctx context.Context, j manualHotLogDeleteJob) (int64, error) {
	if m.hotCH == nil {
		var present int64
		err := m.db.QueryRowContext(ctx, `SELECT count(*) FROM manual_hot_log_delete_candidates c JOIN hot_events h
			ON h.tenant_id=$2 AND h.stream=$3 AND h.event_id=c.receipt AND h.received_at=c.row_at AND h.occurred_at<$4
			WHERE c.job_id=$1`, j.ID, j.Tenant, j.Stream, j.Cutoff).Scan(&present)
		return present, err
	}
	if j.PreviewAt == nil {
		return 0, fmt.Errorf("ClickHouse preview time is missing")
	}
	return m.hotCH.ManualDeleteCount(ctx, j.Tenant, j.Stream, j.Cutoff, *j.PreviewAt)
}

func (m *manualHotLogDeleteManager) run(ctx context.Context) {
	if m == nil {
		return
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		if cpLeaderElectorInstance.IsLeader() {
			stepCtx, cancel := context.WithTimeout(retentionWriteContext(ctx), 90*time.Second)
			_ = m.step(stepCtx)
			cancel()
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (m *manualHotLogDeleteManager) step(ctx context.Context) (err error) {
	if m == nil {
		return nil
	}
	// Lock the legal-hold policy BEFORE the job row. Tenant erasure uses this
	// order too, so the two paths cannot deadlock on opposing lock orders.
	var id, tenant string
	err = m.db.QueryRowContext(ctx, `SELECT job_id,tenant_id FROM manual_hot_log_delete_jobs
		WHERE status IN ('queued','running') ORDER BY CASE WHEN status='queued' THEN 0 ELSE 1 END, created_at LIMIT 1`).Scan(&id, &tenant)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	_, finish, err := beginTenantPurgeHoldGuard(ctx, m.holds, nil, tenant)
	if err != nil {
		if ctx.Err() == nil && cpLeaderElectorInstance.IsLeader() && errors.Is(err, errTenantHeld) {
			_, _ = m.db.ExecContext(ctx, `UPDATE manual_hot_log_delete_jobs SET status='failed',failure_code='legal_hold_or_policy_unavailable',updated_at=now() WHERE job_id=$1 AND status='queued'`, id)
		}
		return err
	}
	defer finish()
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var stream, kind, identity, mutationID, jobStatus string
	defer func() {
		// ClickHouse may accept an asynchronous mutation even when the request
		// later loses its response. Keep its job active while either its issuing
		// query or its asynchronous mutation can still delete rows; retrying a
		// failed job must never submit a second, possibly concurrent, deletion.
		if err != nil && m.hotCH == nil && id != "" && ctx.Err() == nil && cpLeaderElectorInstance.IsLeader() {
			_ = tx.Rollback()
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), cpStateBlobDBTimeout)
			defer cancel()
			_, _ = m.db.ExecContext(cleanup, `UPDATE manual_hot_log_delete_jobs SET status='failed',failure_code='store_operation_failed',updated_at=now() WHERE job_id=$1 AND status IN ('queued','running')`, id)
		}
	}()
	var cutoff time.Time
	var previewAt sql.NullTime
	var previewCount int64
	err = tx.QueryRowContext(ctx, `SELECT stream,cutoff,store_kind,store_identity,preview_at,preview_count,mutation_id,status FROM manual_hot_log_delete_jobs
		WHERE job_id=$1 AND tenant_id=$2 AND status IN ('queued','running') FOR UPDATE`, id, tenant).Scan(&stream, &cutoff, &kind, &identity, &previewAt, &previewCount, &mutationID, &jobStatus)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
		return nil
	}
	if err != nil {
		return err
	}
	if kind != m.kind || identity != m.identity {
		if m.hotCH != nil {
			return fmt.Errorf("ClickHouse job store identity changed; original mutation state requires recovery")
		}
		_, err = tx.ExecContext(ctx, `UPDATE manual_hot_log_delete_jobs SET status='failed',failure_code='store_identity_changed',updated_at=now() WHERE job_id=$1`, id)
		if err == nil {
			err = tx.Commit()
		}
		return err
	}
	if m.hotCH != nil {
		if !previewAt.Valid {
			return fmt.Errorf("ClickHouse manual deletion preview is missing")
		}
		// A lost HTTP response does not stop an ALTER waiting for a table lock.
		// Check its query ID before reading mutations, so an ALTER registering a
		// mutation between these reads cannot be mistaken for an absent write.
		// Failure to observe the server leaves the durable running/hold fence.
		queryRunning, queryErr := m.hotCH.ManualDeleteQueryRunning(ctx, id)
		if queryErr != nil {
			return queryErr
		}
		if queryRunning {
			if jobStatus == "queued" {
				_, err = tx.ExecContext(ctx, `UPDATE manual_hot_log_delete_jobs SET status='running',failure_code='mutation_submission_unconfirmed',updated_at=now() WHERE job_id=$1`, id)
				if err != nil {
					return err
				}
			}
			return tx.Commit()
		}
		var state hotstore.ManualDeleteMutation
		var found bool
		state, found, err = m.hotCH.ManualDeleteMutationState(ctx, id)
		if err != nil {
			return err
		}
		if !found && mutationID == "" && previewCount != 0 && jobStatus == "queued" {
			// Commit the one-shot submission intent before the remote call. A
			// crash or lost response leaves a job requiring investigation, never
			// a queued job that would submit the same ALTER again on promotion.
			_, err = tx.ExecContext(ctx, `UPDATE manual_hot_log_delete_jobs SET status='running',failure_code='mutation_submission_unconfirmed',updated_at=now() WHERE job_id=$1`, id)
			if err != nil {
				return err
			}
			if err = tx.Commit(); err != nil {
				return err
			}
			startErr := m.hotCH.ManualDeleteStart(ctx, id, tenant, stream, cutoff, previewAt.Time)
			var rejected *hotstore.ManualDeleteNotSubmitted
			if errors.As(startErr, &rejected) && ctx.Err() == nil {
				cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), cpStateBlobDBTimeout)
				defer cancel()
				_, updateErr := m.db.ExecContext(cleanup, `UPDATE manual_hot_log_delete_jobs SET status='failed',failure_code='mutation_not_submitted',finished_at=now(),updated_at=now() WHERE job_id=$1 AND status='running' AND mutation_id=''`, id)
				if updateErr != nil {
					return updateErr
				}
			}
			return startErr
		}
		if !found && mutationID == "" && jobStatus == "running" {
			// Absence from both system tables is not proof of rejection. A lost
			// request can still be queued before it enters system.processes; an
			// earlier CP may also have lost its reply before observing a mutation.
			// Keep the durable fence even if the predicate is currently empty.
			// Only a definite submission rejection or an observed mutation can
			// resolve this intent; never resubmit it from an absence observation.
			return tx.Commit()
		}
		if found && mutationID != "" && state.ID != mutationID {
			return fmt.Errorf("ClickHouse mutation identity changed")
		}
		if found && state.Done == 0 {
			// latest_fail_reason can describe a part that ClickHouse will retry.
			// The mutation is not terminal until is_done or an operator resolves
			// its state; marking this job failed would permit a duplicate ALTER.
			failure := ""
			if state.Failed != 0 {
				failure = "mutation_retrying"
			}
			_, err = tx.ExecContext(ctx, `UPDATE manual_hot_log_delete_jobs SET status='running',failure_code=$3,mutation_id=$2,updated_at=now() WHERE job_id=$1`, id, state.ID, failure)
		} else {
			var remaining int64
			remaining, err = m.hotCH.ManualDeleteCount(ctx, tenant, stream, cutoff, previewAt.Time)
			if err != nil {
				return err
			}
			if remaining == 0 {
				// A predicate mutation cannot distinguish rows deleted by us from
				// rows already removed by normal retention. Report confirmed absence.
				_, err = tx.ExecContext(ctx, `UPDATE manual_hot_log_delete_jobs SET status='completed',mutation_id=$2,
					deleted_count=0,already_missing_count=$3,finished_at=now(),updated_at=now() WHERE job_id=$1`, id, mutationIDOrState(mutationID, state.ID), previewCount)
			} else if !found {
				// This deployment uses one non-replicated MergeTree. The issuing
				// ALTER is no longer running and this mutation was observed before
				// disappearing (for example, after the operator killed it).
				_, err = tx.ExecContext(ctx, `UPDATE manual_hot_log_delete_jobs SET status='failed',failure_code='mutation_not_present',finished_at=now(),updated_at=now() WHERE job_id=$1`, id)
			} else {
				_, err = tx.ExecContext(ctx, `UPDATE manual_hot_log_delete_jobs SET status='failed',failure_code='mutation_incomplete',mutation_id=$2,updated_at=now() WHERE job_id=$1`, id, mutationIDOrState(mutationID, state.ID))
			}
		}
		if err == nil {
			err = tx.Commit()
		}
		return err
	}
	// The batch bounds one PostgreSQL transaction's lock and memory footprint;
	// it does not cap the number of rows a confirmed job can delete.
	rows, err := tx.QueryContext(ctx, `SELECT receipt,row_at FROM manual_hot_log_delete_candidates WHERE job_id=$1 AND state='pending' ORDER BY row_at,receipt LIMIT 10000`, id)
	if err != nil {
		return err
	}
	type candidate struct {
		receipt string
		at      time.Time
	}
	var batch []candidate
	for rows.Next() {
		var c candidate
		if err = rows.Scan(&c.receipt, &c.at); err != nil {
			break
		}
		batch = append(batch, c)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	if len(batch) == 0 {
		_, err = tx.ExecContext(ctx, `UPDATE manual_hot_log_delete_jobs SET status='completed',finished_at=now(),updated_at=now() WHERE job_id=$1`, id)
		if err == nil {
			err = tx.Commit()
		}
		return err
	}
	ids := make([]string, 0, len(batch))
	for _, c := range batch {
		ids = append(ids, c.receipt)
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM hot_events h USING manual_hot_log_delete_candidates c
		WHERE c.job_id=$1 AND c.receipt=ANY($2::text[]) AND c.state='pending'
		AND h.tenant_id=$3 AND h.stream=$4 AND h.event_id=c.receipt
		AND h.received_at=c.row_at AND h.occurred_at<$5`, id, pq.Array(ids), tenant, stream, cutoff)
	if err != nil {
		return err
	}
	deleted, err := result.RowsAffected()
	if err != nil || deleted > int64(len(batch)) {
		return fmt.Errorf("hot row receipts are not unique or could not be counted")
	}
	_, err = tx.ExecContext(ctx, `UPDATE manual_hot_log_delete_candidates SET state='done'
		WHERE job_id=$1 AND receipt=ANY($2::text[]) AND state='pending'`, id, pq.Array(ids))
	if err != nil {
		return err
	}
	missing := int64(len(batch)) - deleted
	_, err = tx.ExecContext(ctx, `UPDATE manual_hot_log_delete_jobs SET status='running',deleted_count=deleted_count+$2,already_missing_count=already_missing_count+$3,updated_at=now() WHERE job_id=$1`, id, deleted, missing)
	if err == nil {
		err = tx.Commit()
	}
	return err
}

func mutationIDOrState(saved, observed string) string {
	if observed != "" {
		return observed
	}
	return saved
}
