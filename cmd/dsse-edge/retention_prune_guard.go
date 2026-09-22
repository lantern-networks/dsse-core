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
// in the deletion transaction; local policy stays read-locked through commit.
func lockPrunePolicy(cfg retentionConfig) func() {
	var unlock []func()
	if s := cfg.legalHold; s != nil {
		s.writeMu.Lock()
		unlock = append(unlock, s.writeMu.Unlock)
		if _, shared := s.persister.(retentionSharedUpdater); !shared {
			s.mu.RLock()
			unlock = append(unlock, s.mu.RUnlock)
		}
	}
	if s := cfg.override; s != nil {
		s.writeMu.Lock()
		unlock = append(unlock, s.writeMu.Unlock)
		if _, shared := s.persister.(retentionSharedUpdater); !shared {
			s.mu.RLock()
			unlock = append(unlock, s.mu.RUnlock)
		}
	}
	return func() {
		for i := len(unlock) - 1; i >= 0; i-- {
			unlock[i]()
		}
	}
}

// Materialize an absent key under the same lock as its first administrative
// writer. SELECT FOR UPDATE alone does not lock an absent PostgreSQL row.
func prunePolicyRow(ctx context.Context, tx *sql.Tx, key, empty string, known bool) ([]byte, error) {
	result, err := tx.ExecContext(ctx, `INSERT INTO cp_state_blobs(store_key,payload,updated_at) VALUES($1,$2,now()) ON CONFLICT(store_key) DO NOTHING`, key, []byte(empty))
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
	err = tx.QueryRowContext(ctx, `SELECT payload FROM cp_state_blobs WHERE store_key=$1 FOR UPDATE`, key).Scan(&raw)
	return raw, err
}

// Caller owns lockPrunePolicy and keeps tx open through deletion/commit. A
// protection committed before these locks wins; a later policy writer waits
// until this deletion ends. Never enlarge a cutoff selected by the caller.
func checkedPruneCutoff(ctx context.Context, tx *sql.Tx, cfg retentionConfig, tenant, stream string, cutoff, now time.Time) (time.Time, bool, error) {
	if s := cfg.legalHold; s != nil {
		// The caller owns policy locks. A refresh or SQL read must not bypass
		// a failed local request to preserve this tenant.
		if s.pending[tenant] {
			return cutoff, false, nil
		}
		held := s.held
		if p, ok := s.persister.(postgresBlobPersister); ok {
			raw, err := prunePolicyRow(ctx, tx, p.key, "[]", s.sharedKnown)
			if err != nil {
				return cutoff, false, err
			}
			held, err = decodeSharedHolds(raw, s.sharedKnown)
			if err != nil {
				return cutoff, false, err
			}
		} else if _, shared := s.persister.(retentionSharedUpdater); shared {
			return cutoff, false, fmt.Errorf("shared pruning policy requires a PostgreSQL transaction")
		} else if s.loadErr != nil {
			return cutoff, false, s.loadErr
		}
		if _, ok := held[tenant]; ok {
			return cutoff, false, nil
		}
	}
	if s := cfg.override; s != nil {
		if s.pendingForever[stream] {
			return cutoff, false, nil
		}
		days := s.days
		if p, ok := s.persister.(postgresBlobPersister); ok {
			raw, err := prunePolicyRow(ctx, tx, p.key, "{}", s.sharedKnown)
			if err != nil {
				return cutoff, false, err
			}
			days, err = decodeSharedRetention(raw, s.sharedKnown)
			if err != nil {
				return cutoff, false, err
			}
		} else if _, shared := s.persister.(retentionSharedUpdater); shared {
			return cutoff, false, fmt.Errorf("shared pruning policy requires a PostgreSQL transaction")
		} else if s.loadErr != nil {
			return cutoff, false, s.loadErr
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
	unlock := lockPrunePolicy(cfg)
	defer unlock()
	tx, finish, err := beginCPWriteTransaction(ctx, db)
	if err != nil {
		logPruneFailure(table, err)
		return
	}
	defer finish()
	defer tx.Rollback()
	cutoff, allowed, err := checkedPruneCutoff(ctx, tx, cfg, tenant, stream, cutoff, now)
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
	result, err := tx.ExecContext(ctx, "DELETE FROM "+table+" WHERE tenant_id=$1 AND "+where, args...)
	if err != nil {
		logPruneFailure(table, err)
		return
	}
	if err = tx.Commit(); err != nil {
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
