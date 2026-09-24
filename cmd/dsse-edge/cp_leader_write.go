package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// errCPLeadershipChanged: the request was admitted in a term this process no
// longer holds (or never held: a standby). Retrying here cannot succeed; the
// request belongs on the current leader.
var errCPLeadershipChanged = errors.New("control-plane leadership changed before saving")

type cpWriteLeaseKey struct{}
type cpWriteLease struct {
	elector *cpLeaderElector
	epoch   int64
}

// Capture before authentication/body decoding. Reacquiring leadership cannot
// authorize a request that was admitted in a previous term.
func captureCPWriteLease(ctx context.Context) context.Context {
	if _, captured := ctx.Value(cpWriteLeaseKey{}).(cpWriteLease); captured {
		return ctx
	}
	e := cpLeaderElectorInstance
	if e == nil {
		return ctx
	}
	// Capture the published term without joining a busy SQL writer. The epoch
	// changes across promotions; observing a transition fails closed. The
	// transaction checks this exact term again under the session lock.
	lease := cpWriteLease{elector: e}
	epoch := e.leaderSince.Load()
	if ctx.Err() == nil && e.IsLeader() && e.leaderSince.Load() == epoch {
		lease.epoch = epoch
	}
	return context.WithValue(ctx, cpWriteLeaseKey{}, lease)
}

// Use the session which owns the advisory lock, not a separate pool connection.
// release waits for this transaction; session loss aborts the transaction before
// a peer can acquire the lock. Call finish only after commit/rollback.
func beginCPWriteTransaction(ctx context.Context, fallback *sql.DB) (*sql.Tx, func(), error) {
	return beginCPWriteTransactionOptions(ctx, fallback, nil)
}

func beginCPWriteTransactionOptions(ctx context.Context, fallback *sql.DB, options *sql.TxOptions) (*sql.Tx, func(), error) {
	return beginCPWriteTransactionContexts(ctx, ctx, fallback, options)
}

// Admission/writer waiting retains the request context even when a caller
// supplies a separate, server-budgeted SQL context for the active transaction.
func beginCPWriteTransactionContexts(ctx, sqlCtx context.Context, fallback *sql.DB, options *sql.TxOptions) (*sql.Tx, func(), error) {
	lease, ok := ctx.Value(cpWriteLeaseKey{}).(cpWriteLease)
	if !ok {
		tx, err := fallback.BeginTx(sqlCtx, options)
		return tx, func() {}, err
	}
	e := lease.elector
	waitCtx, cancelWait := context.WithTimeout(ctx, cpStateBlobDBTimeout)
	err := e.mu.LockContext(waitCtx)
	cancelWait()
	if err != nil {
		return nil, func() {}, fmt.Errorf("control-plane writer wait: %w", err)
	}
	if lease.epoch == 0 || !e.IsLeader() || e.conn == nil || e.leaderSince.Load() != lease.epoch {
		e.mu.Unlock()
		return nil, func() {}, errCPLeadershipChanged
	}
	tx, err := e.conn.BeginTx(sqlCtx, options)
	if err != nil {
		e.mu.Unlock()
		return nil, func() {}, err
	}
	return tx, e.mu.Unlock, nil
}
