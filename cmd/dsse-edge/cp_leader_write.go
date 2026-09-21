package main

import (
	"context"
	"database/sql"
	"errors"
)

type cpWriteLeaseKey struct{}
type cpWriteLease struct {
	elector *cpLeaderElector
	epoch   int64
}

// Capture before authentication/body decoding. Reacquiring leadership cannot
// authorize a request that was admitted in a previous term.
func captureCPWriteLease(ctx context.Context) context.Context {
	e := cpLeaderElectorInstance
	if e == nil {
		return ctx
	}
	e.mu.Lock()
	lease := cpWriteLease{elector: e}
	if e.IsLeader() {
		lease.epoch = e.leaderSince.Load()
	}
	e.mu.Unlock()
	return context.WithValue(ctx, cpWriteLeaseKey{}, lease)
}

// Use the session which owns the advisory lock, not a separate pool connection.
// release waits for this transaction; session loss aborts the transaction before
// a peer can acquire the lock. Call finish only after commit/rollback.
func beginCPWriteTransaction(ctx context.Context, fallback *sql.DB) (*sql.Tx, func(), error) {
	return beginCPWriteTransactionOptions(ctx, fallback, nil)
}

func beginCPWriteTransactionOptions(ctx context.Context, fallback *sql.DB, options *sql.TxOptions) (*sql.Tx, func(), error) {
	lease, ok := ctx.Value(cpWriteLeaseKey{}).(cpWriteLease)
	if !ok {
		tx, err := fallback.BeginTx(ctx, options)
		return tx, func() {}, err
	}
	e := lease.elector
	e.mu.Lock()
	if lease.epoch == 0 || !e.IsLeader() || e.conn == nil || e.leaderSince.Load() != lease.epoch {
		e.mu.Unlock()
		return nil, func() {}, errors.New("control-plane leadership changed before saving")
	}
	tx, err := e.conn.BeginTx(ctx, options)
	if err != nil {
		e.mu.Unlock()
		return nil, func() {}, err
	}
	return tx, e.mu.Unlock, nil
}
