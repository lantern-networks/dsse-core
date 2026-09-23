package main

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Acquire process-local policy locks BEFORE a CP transaction: SetContext takes
// writeMu before the elector lock too. Holding these in the reverse order would
// deadlock a Console change against a sweep. Shared policy is then read/locked
// in the deletion transaction; writeMu excludes local policy mutations through
// commit. Never hold the state mutex across SQL/file/object I/O: a timed-out
// preservation request must still be able to record its pending intent.
func lockPrunePolicy(ctx context.Context, cfg retentionConfig) (func(), error) {
	var unlock []func()
	finish := func() {
		for i := len(unlock) - 1; i >= 0; i-- {
			unlock[i]()
		}
	}
	if s := cfg.legalHold; s != nil {
		if err := s.writeMu.LockContext(ctx); err != nil {
			return nil, err
		}
		unlock = append(unlock, s.writeMu.Unlock)
	}
	if s := cfg.override; s != nil {
		if err := s.writeMu.LockContext(ctx); err != nil {
			finish()
			return nil, err
		}
		unlock = append(unlock, s.writeMu.Unlock)
	}
	if err := ctx.Err(); err != nil {
		finish()
		return nil, err
	}
	return finish, nil
}

// Materialize an absent key under the same lock as its first administrative
// writer. SELECT FOR UPDATE alone does not lock an absent PostgreSQL row.
func prunePolicyRow(budget *cpStatementBudget, tx *sql.Tx, key, empty string, known bool) ([]byte, error) {
	result, err := budget.exec(tx, `INSERT INTO cp_state_blobs(store_key,payload,updated_at) VALUES($1,$2,now()) ON CONFLICT(store_key) DO NOTHING`, key, []byte(empty))
	if err != nil {
		return nil, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if n == 1 && known {
		return nil, fmt.Errorf("known pruning policy row is missing")
	}
	var raw []byte
	err = budget.queryRow(tx, `SELECT payload FROM cp_state_blobs WHERE store_key=$1 FOR UPDATE`, key).Scan(&raw)
	return raw, err
}

// Caller owns lockPrunePolicy and keeps tx open through deletion/commit. A
// protection committed before these locks wins; a later policy writer waits
// until this deletion ends. Never enlarge a cutoff selected by the caller.
func checkedPruneCutoff(ctx context.Context, tx *sql.Tx, cfg retentionConfig, tenant, stream string, cutoff, now time.Time) (time.Time, bool, error) {
	// Cross-resource purge callers retain their original transaction context.
	// Only callers which created a server-budgeted transaction opt in below.
	return checkedPruneCutoffWithBudget(&cpStatementBudget{request: ctx, sqlCtx: ctx}, tx, cfg, tenant, stream, cutoff, now)
}

func checkedPruneCutoffWithBudget(budget *cpStatementBudget, tx *sql.Tx, cfg retentionConfig, tenant, stream string, cutoff, now time.Time) (time.Time, bool, error) {
	if s := cfg.legalHold; s != nil {
		// The caller owns policy locks. A refresh or SQL read must not bypass
		// a failed local request to preserve this tenant.
		s.mu.RLock()
		pending, held, fences, loadErr := s.pending[tenant], s.held, s.erasures, s.loadErr
		s.mu.RUnlock()
		if pending {
			return cutoff, false, nil
		}
		if p, ok := s.persister.(postgresBlobPersister); ok {
			raw, err := prunePolicyRow(budget, tx, p.key, "[]", s.sharedKnown)
			if err != nil {
				return cutoff, false, err
			}
			snapshot, decodeErr := decodeHoldSnapshot(raw, s.sharedKnown)
			err = decodeErr
			held, fences = snapshot.held(), snapshot.Erasures
			if err != nil {
				return cutoff, false, err
			}
		} else if _, shared := s.persister.(retentionSharedUpdater); shared {
			return cutoff, false, fmt.Errorf("shared pruning policy requires a PostgreSQL transaction")
		} else if loadErr != nil {
			return cutoff, false, loadErr
		}
		if f, busy := fences[tenant]; busy && !ownsTenantErasure(budget.request, tenant, f) {
			return cutoff, false, nil
		}
		if _, ok := held[tenant]; ok {
			return cutoff, false, nil
		}
	}
	if s := cfg.override; s != nil {
		s.mu.RLock()
		pending, days, loadErr := s.pendingForever[stream], s.days, s.loadErr
		s.mu.RUnlock()
		if pending {
			return cutoff, false, nil
		}
		if p, ok := s.persister.(postgresBlobPersister); ok {
			raw, err := prunePolicyRow(budget, tx, p.key, "{}", s.sharedKnown)
			if err != nil {
				return cutoff, false, err
			}
			days, err = decodeSharedRetention(raw, s.sharedKnown)
			if err != nil {
				return cutoff, false, err
			}
		} else if _, shared := s.persister.(retentionSharedUpdater); shared {
			return cutoff, false, fmt.Errorf("shared pruning policy requires a PostgreSQL transaction")
		} else if loadErr != nil {
			return cutoff, false, loadErr
		}
		ret := cfg.hotEvents
		if d, ok := cfg.perStream[stream]; ok {
			ret = d
		}
		if d, ok := days[stream]; ok {
			ret = time.Duration(d) * 24 * time.Hour
		}
		if ret <= 0 {
			return cutoff, false, nil
		}
		if next := now.Add(-ret); next.Before(cutoff) {
			cutoff = next
		}
	}
	return cutoff, true, nil
}

// Both delete-only hot pruning and terminal-outbox cleanup share the term
// fence and hold lock. Outbox retention uses its own TTL, not hot overrides.
func deleteRetentionRows(ctx context.Context, db *sql.DB, cfg retentionConfig, table, where, tenant, stream string, cutoff, now time.Time) {
	ctx = retentionWriteContext(ctx)
	ctx, cancel := context.WithTimeout(ctx, cpStateBlobDBTimeout)
	defer cancel()
	unlock, err := lockPrunePolicy(ctx, cfg)
	if err != nil {
		logPruneFailure(table, err)
		return
	}
	defer unlock()
	budget := newCPStatementBudget(ctx)
	defer budget.cancel()
	tx, finish, err := beginCPWriteTransactionContexts(ctx, budget.sqlCtx, db, nil)
	if err != nil {
		logPruneFailure(table, err)
		return
	}
	defer finish()
	defer tx.Rollback()
	cutoff, allowed, err := checkedPruneCutoffWithBudget(budget, tx, cfg, tenant, stream, cutoff, now)
	if err != nil {
		logPruneFailure(table, err)
		return
	}
	if !allowed {
		return
	}
	args := []any{tenant, cutoff}
	if stream != "" {
		args = append(args, stream)
	}
	result, err := budget.exec(tx, "DELETE FROM "+table+" WHERE tenant_id=$1 AND "+where, args...)
	if err != nil {
		logPruneFailure(table, err)
		return
	}
	if err = budget.commit(tx); err != nil {
		logPruneFailure(table, err)
		return
	}
	adoptPrunePolicy(cfg)
	if n, _ := result.RowsAffected(); n > 0 {
		logPruneDeleted(table, tenant, n, cutoff)
	}
}

// Called under policy locks only after the initializing transaction commits.
func adoptPrunePolicy(cfg retentionConfig) {
	if s := cfg.legalHold; s != nil {
		if _, ok := s.persister.(postgresBlobPersister); ok {
			s.sharedKnown = true
		}
	}
	if s := cfg.override; s != nil {
		if _, ok := s.persister.(postgresBlobPersister); ok {
			s.sharedKnown = true
		}
	}
}
