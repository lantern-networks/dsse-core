package main

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
)

// Protect one destructive step, not the entire multi-store purge. Holding a CP
// transaction across nested store mutations would deadlock their CP writers.
// Return the policy transaction for reuse only when it uses the target pool.
// Otherwise retain it during the target transaction or filesystem step, subject
// to context cancellation/session loss. The enclosing multi-store purge saves a
// durable erasure fence before these steps; cross-resource atomicity is not provided.
func beginTenantPurgeHoldGuard(ctx context.Context, holds *legalHoldStore, target *sql.DB, tenant string) (*sql.Tx, func(), error) {
	return beginTenantPurgeHoldGuardWithBudget(&cpStatementBudget{request: ctx, sqlCtx: ctx}, holds, target, tenant)
}

// Only a same-pool SQL batch supplies a server budget. Filesystem and separate
// database steps keep their original cancellation and protection boundaries.
func beginTenantPurgeHoldGuardWithBudget(budget *cpStatementBudget, holds *legalHoldStore, target *sql.DB, tenant string) (*sql.Tx, func(), error) {
	ctx := budget.request
	if holds == nil {
		return nil, func() {}, ctx.Err()
	}
	unlock, err := lockPrunePolicy(ctx, retentionConfig{legalHold: holds})
	if err != nil {
		return nil, func() {}, fmt.Errorf("legal_hold: destructive policy wait: %w", err)
	}
	finish := unlock
	fail := func(err error) (*sql.Tx, func(), error) { finish(); return nil, func() {}, err }
	policyDB := target
	if p, ok := holds.persister.(postgresBlobPersister); ok {
		policyDB = p.db
	}
	var tx *sql.Tx
	if policyDB != nil {
		var release func()
		var err error
		tx, release, err = beginCPWriteTransactionContexts(ctx, budget.sqlCtx, policyDB, nil)
		if err != nil {
			return fail(fmt.Errorf("legal_hold: destructive write unavailable"))
		}
		finish = func() { tx.Rollback(); release(); unlock() }
	}
	// Unlike retention, an explicit purge has no time cutoff; only the hold
	// decision is reused, under the same local lock and authoritative row lock.
	_, allowed, err := checkedPruneCutoffWithBudget(budget, tx, retentionConfig{legalHold: holds}, tenant, "", time.Time{}, time.Time{})
	if err != nil {
		return fail(fmt.Errorf("legal_hold: state unavailable"))
	}
	if !allowed {
		return fail(fmt.Errorf("legal_hold: tenant is held"))
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	if policyDB == target {
		return tx, finish, nil
	}
	return nil, finish, nil
}

func purgeTenantLogDirectoryWithHold(ctx context.Context, writer *logs.Writer, tenant string, holds *legalHoldStore) (int64, error) {
	return runTenantFilePurge(ctx, holds, tenant, func(ctx context.Context) (int64, error) {
		return purgeTenantLogDirectoryContext(ctx, writer, tenant)
	})
}

// The worker, not the returning request, owns the guard until real filesystem
// work has ended. Cancellation cannot release exclusion around a live syscall.
func runTenantFilePurge(ctx context.Context, holds *legalHoldStore, tenant string, erase func(context.Context) (int64, error)) (int64, error) {
	ctx = retentionWriteContext(ctx)
	ctx, cancel := context.WithTimeout(ctx, cpStateBlobDBTimeout)
	defer cancel()
	type outcome struct {
		count int64
		err   error
	}
	done := make(chan outcome, 1)
	go func() {
		_, finish, err := beginTenantPurgeHoldGuard(ctx, holds, nil, tenant)
		if err != nil {
			done <- outcome{err: err}
			return
		}
		defer finish()
		if err := ctx.Err(); err != nil {
			done <- outcome{err: err}
			return
		}
		count, err := erase(ctx)
		if ctx.Err() != nil {
			count = 0
			err = fmt.Errorf("log file erasure outcome is unconfirmed: %w", ctx.Err())
		}
		done <- outcome{count: count, err: err}
	}()
	select {
	case result := <-done:
		return result.count, result.err
	case <-ctx.Done():
		return 0, fmt.Errorf("log file erasure outcome is unconfirmed: %w", ctx.Err())
	}
}
