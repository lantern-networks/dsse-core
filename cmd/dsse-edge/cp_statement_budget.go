package main

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Used by shared blob, enrolment-token and delete-only retention writes on the
// advisory-lock session. lib/pq discards
// that session on client context cancellation. Let PostgreSQL expire each
// statement within the remaining request budget first, while keeping a later
// client deadline as a fallback if the server does not finish normally.
// This does not guarantee a socket-level timeout for all driver operations.
const cpStatementCancelGrace = time.Second

type cpStatementBudget struct {
	request, sqlCtx context.Context
	cancel          context.CancelFunc
	deadline        time.Time
	server          bool
}

func newCPStatementBudget(ctx context.Context) *cpStatementBudget {
	b := &cpStatementBudget{request: ctx, sqlCtx: ctx, cancel: func() {}}
	if _, ok := ctx.Value(cpWriteLeaseKey{}).(cpWriteLease); !ok {
		return b // Pool-only callers retain their existing cancellation behavior.
	}
	b.server = true
	b.deadline = time.Now().Add(cpStateBlobDBTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(b.deadline) {
		b.deadline = d
	}
	b.sqlCtx, b.cancel = context.WithDeadline(context.WithoutCancel(ctx), b.deadline.Add(cpStatementCancelGrace))
	return b
}

// Call before each data statement. COMMIT separately forwards cancellation:
// statement_timeout does not bound all transaction-finalization work.
// Reset the server timeout to the remaining TOTAL budget, not a new five
// seconds per statement. Explicit cancellation is checked between statements;
// an in-flight statement may finish/expire first, then must roll back.
func (b *cpStatementBudget) prepare(tx *sql.Tx) error {
	if err := b.request.Err(); err != nil {
		return err
	}
	if !b.server {
		return nil
	}
	remaining := time.Until(b.deadline)
	if remaining <= 0 {
		return context.DeadlineExceeded
	}
	ms := remaining.Milliseconds()
	if ms < 1 {
		ms = 1 // PostgreSQL's zero means no timeout.
	}
	// Preserve a stricter timeout already configured by the database operator.
	if _, err := tx.ExecContext(b.sqlCtx, `SELECT set_config('statement_timeout', CASE
		WHEN current_setting('statement_timeout')::interval > interval '0'
		 AND current_setting('statement_timeout')::interval < $1::text::interval
		THEN current_setting('statement_timeout') ELSE $1::text END, true)`, fmt.Sprintf("%dms", ms)); err != nil {
		return err
	}
	return b.request.Err()
}

func (b *cpStatementBudget) exec(tx *sql.Tx, query string, args ...any) (sql.Result, error) {
	if err := b.prepare(tx); err != nil {
		return nil, err
	}
	return tx.ExecContext(b.sqlCtx, query, args...)
}

type cpSQLRow interface{ Scan(...any) error }
type cpSQLRowError struct{ err error }

func (r cpSQLRowError) Scan(...any) error { return r.err }

func (b *cpStatementBudget) queryRow(tx *sql.Tx, query string, args ...any) cpSQLRow {
	if err := b.prepare(tx); err != nil {
		return cpSQLRowError{err}
	}
	return tx.QueryRowContext(b.sqlCtx, query, args...)
}

// Preserve client cancellation during COMMIT, including deferred constraints
// which can run beyond statement_timeout. The driver may discard leadership
// here, and commit errors retain the existing unknown-outcome classification.
func (b *cpStatementBudget) forwardCommitCancellation() func() bool {
	if !b.server {
		return func() bool { return true }
	}
	return context.AfterFunc(b.request, b.cancel)
}

// A request canceled
// during a data statement must roll back even if that statement finishes first.
func (b *cpStatementBudget) commit(tx *sql.Tx) error {
	if err := b.request.Err(); err != nil {
		return err
	}
	stop := b.forwardCommitCancellation()
	defer stop()
	return tx.Commit()
}
