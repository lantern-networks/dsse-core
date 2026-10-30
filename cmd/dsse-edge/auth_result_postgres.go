package main

import (
	"context"
	"database/sql"
	"errors"
	"hash/fnv"
	"log"
	"sync/atomic"
	"time"
)

// postgresAuthResultStore is the shared CP authority. A request occupies one
// row; the capacity lock is tenant-scoped, so one tenant cannot exhaust another.
// restart-durability: cp_durable — rows live in shared Postgres (migration 053).
type postgresAuthResultStore struct {
	db    *sql.DB
	clock func() time.Time
	limit int
}

var thePostgresAuthResultStore atomic.Pointer[postgresAuthResultStore]

// Sweep idle tenants too. A bounded, leader-leased transaction shares the same
// authority rules as other CP maintenance, without deleting unexpired results.
func (s *postgresAuthResultStore) pruneExpired(ctx context.Context) (int64, error) {
	ctx, cancel := context.WithTimeout(captureCPWriteLease(ctx), 3*time.Second)
	defer cancel()
	tx, finish, err := beginCPWriteTransaction(ctx, s.db)
	if err != nil {
		return 0, err
	}
	defer finish()
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `DELETE FROM auth_flow_results WHERE request_id IN
		(SELECT request_id FROM auth_flow_results WHERE expires_at <= $1
		 ORDER BY expires_at,request_id LIMIT 512 FOR UPDATE SKIP LOCKED)`, s.clock().UTC().Unix())
	if err != nil {
		return 0, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return n, tx.Commit()
}

func maintainAuthResults(ctx context.Context, store *postgresAuthResultStore) {
	if store == nil {
		return
	}
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		if n, err := store.pruneExpired(ctx); err == nil && n > 0 {
			log.Printf("auth_result_retention removed=%d", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func newPostgresAuthResultStore(db *sql.DB) *postgresAuthResultStore {
	return &postgresAuthResultStore{db: db, clock: time.Now, limit: authFlowResultLimit}
}

func authResultTenantLock(tenant string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("dsse-auth-flow-results:"))
	_, _ = h.Write([]byte(tenant))
	return int64(h.Sum64())
}

func (s *postgresAuthResultStore) Record(r authFlowResult) error {
	if s == nil || s.db == nil {
		return errors.New("authentication result authority unavailable")
	}
	now := s.clock().UTC()
	if !validAuthFlowResult(r, now) {
		return errors.New("invalid authentication result")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// The lock serializes capacity decisions only within this tenant. The unique
	// request_id key independently resolves collisions across tenants.
	var ignored any
	if err := tx.QueryRowContext(ctx, "SELECT pg_advisory_xact_lock($1)", authResultTenantLock(r.TenantID)).Scan(&ignored); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM auth_flow_results WHERE tenant_id=$1 AND expires_at<=$2", r.TenantID, now.Unix()); err != nil {
		return err
	}
	old, err := loadAuthResultRow(ctx, tx, r.RequestID)
	if err == nil {
		if old != r {
			return errAuthFlowResultConflict
		}
		return tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM auth_flow_results WHERE tenant_id=$1", r.TenantID).Scan(&count); err != nil {
		return err
	}
	if count >= s.limit {
		return errors.New("authentication result tenant ledger is full")
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO auth_flow_results
		(request_id,tenant_id,device_id,os_principal,os_session,result,final_at,expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (request_id) DO NOTHING`,
		r.RequestID, r.TenantID, r.DeviceID, r.Principal, r.Session, r.Result, r.FinalAt, r.ExpiresAt)
	if err != nil {
		return err
	}
	inserted, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if inserted == 0 {
		// Another tenant or CP won the global request ID while we waited.
		old, err := loadAuthResultRow(ctx, tx, r.RequestID)
		if err != nil {
			return err
		}
		if old != r {
			return errAuthFlowResultConflict
		}
	}
	return tx.Commit()
}

func loadAuthResultRow(ctx context.Context, tx *sql.Tx, id string) (authFlowResult, error) {
	var r authFlowResult
	err := tx.QueryRowContext(ctx, `SELECT request_id,tenant_id,device_id,os_principal,os_session,result,final_at,expires_at
		FROM auth_flow_results WHERE request_id=$1`, id).Scan(&r.RequestID, &r.TenantID, &r.DeviceID, &r.Principal, &r.Session, &r.Result, &r.FinalAt, &r.ExpiresAt)
	return r, err
}

// Missing, expired and incorrectly owned requests all have the same opaque
// answer. Only the already-verified Edge machine route may call this store.
func (s *postgresAuthResultStore) Lookup(id, tenant, device, principal, session string) (string, error) {
	if s == nil || s.db == nil {
		return "", errors.New("authentication result authority unavailable")
	}
	if !validAuthResultRequestID(id) || tenant == "" || device == "" || !validAuthOwner(principal, session) {
		return "", nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var result string
	err := s.db.QueryRowContext(ctx, `SELECT result FROM auth_flow_results
		WHERE request_id=$1 AND tenant_id=$2 AND device_id=$3 AND os_principal=$4 AND os_session=$5 AND expires_at>$6`,
		id, tenant, device, principal, session, s.clock().UTC().Unix()).Scan(&result)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return result, err
}
