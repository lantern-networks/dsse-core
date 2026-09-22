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
// to context cancellation/session loss. Cross-resource atomicity is not provided.
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
	unlock := lockPrunePolicy(retentionConfig{legalHold: holds})
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
	ctx = retentionWriteContext(ctx)
	ctx, cancel := context.WithTimeout(ctx, cpStateBlobDBTimeout)
	defer cancel()
	_, finish, err := beginTenantPurgeHoldGuard(ctx, holds, nil, tenant)
	if err != nil {
		return 0, err
	}
	defer finish()
	return purgeTenantLogDirectory(writer, tenant)
}
