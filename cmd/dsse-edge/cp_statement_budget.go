package main

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Used by shared blob, enrolment-token and retention archive/delete writes on the
// advisory-lock session. lib/pq discards
// that session on client context cancellation. Let PostgreSQL expire each
// statement within the remaining request budget first, while keeping a later
// client deadline as a fallback if the server does not finish normally.
// This does not guarantee a socket-level timeout for all driver operations.
const cpStatementCancelGrace = time.Second

// A statement_timeout set within this long before a statement is reused rather
// than set again. Any statement then expires at most this long after the
// budget deadline, which is inside cpStatementCancelGrace, so the server still
// ends it before the client fallback closes the leader's session.
const cpStatementTimeoutReuse = 250 * time.Millisecond

type cpStatementBudget struct {
	request, sqlCtx context.Context
	cancel          context.CancelFunc
	deadline        time.Time
	server          bool
	timeoutSetAt    time.Time
	timeoutSets     int
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
// seconds per statement, unless it was set within cpStatementTimeoutReuse. Explicit cancellation is checked between statements;
// an in-flight statement may finish/expire first, then must roll back.
func (b *cpStatementBudget) prepare(tx *sql.Tx) error {
	if err := b.request.Err(); err != nil {
		return err
	}
	if !b.server {
		return nil
	}
	now := time.Now()
	remaining := b.deadline.Sub(now)
	if remaining <= 0 {
		return context.DeadlineExceeded
	}
	if !b.timeoutSetAt.IsZero() && now.Sub(b.timeoutSetAt) < cpStatementTimeoutReuse {
		return nil // request.Err() was checked above.
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
	b.timeoutSetAt, b.timeoutSets = now, b.timeoutSets+1
	return b.request.Err()
}

func (b *cpStatementBudget) exec(tx *sql.Tx, query string, args ...any) (sql.Result, error) {
	if err := b.prepare(tx); err != nil {
		return nil, err
	}
	return tx.ExecContext(b.sqlCtx, query, args...)
}

func (b *cpStatementBudget) query(tx *sql.Tx, query string, args ...any) (*sql.Rows, error) {
	if err := b.prepare(tx); err != nil {
		return nil, err
	}
	return tx.QueryContext(b.sqlCtx, query, args...)
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

// COMMIT does not forward request cancellation. Once COMMIT is sent, the
// request can no longer roll the change back, and lib/pq answers cancellation
// by closing the advisory-lock session, which hands leadership to a peer. A
// client disconnect or an exhausted request budget must not cost leadership.
// COMMIT (including deferred constraints) is still bounded by sqlCtx: the
// budget deadline plus cpStatementCancelGrace, the same transport backstop
// as data statements. A request canceled before COMMIT still rolls back.
func (b *cpStatementBudget) commit(tx *sql.Tx) error {
	if err := b.request.Err(); err != nil {
		return err
	}
	return tx.Commit()
}
