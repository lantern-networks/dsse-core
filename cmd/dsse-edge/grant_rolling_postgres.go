package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/grantstore"
	"github.com/lib/pq"
)

const grantEvidenceKey = "grants_evidence_v1"

type postgresGrantPair struct{ db *sql.DB }

func grantRevisionReadError(err error) error {
	var pgErr *pq.Error
	if errors.As(err, &pgErr) && pgErr.Code == "42703" {
		return grantstore.ErrGrantRevisionUnavailable
	}
	return err
}

func (p postgresGrantPair) readPairRevision(parent context.Context, withPayload bool) (grantstore.GrantPairRevision, []byte, []byte, error) {
	ctx, cancel := context.WithTimeout(parent, cpStateBlobDBTimeout)
	defer cancel()
	query := `SELECT store_key,grant_revision FROM cp_state_blobs WHERE store_key IN ('grants','grants_evidence_v1')`
	if withPayload {
		query = `SELECT store_key,grant_revision,payload FROM cp_state_blobs WHERE store_key IN ('grants','grants_evidence_v1')`
	}
	rows, err := p.db.QueryContext(ctx, query)
	if err != nil {
		return grantstore.GrantPairRevision{}, nil, nil, grantRevisionReadError(err)
	}
	defer rows.Close()
	var revision grantstore.GrantPairRevision
	var legacy, evidence []byte
	for rows.Next() {
		var key string
		var number int64
		var payload []byte
		if withPayload {
			err = rows.Scan(&key, &number, &payload)
		} else {
			err = rows.Scan(&key, &number)
		}
		if err != nil {
			return grantstore.GrantPairRevision{}, nil, nil, err
		}
		switch key {
		case "grants":
			revision.LegacyPresent, revision.Legacy, legacy = true, number, payload
		case grantEvidenceKey:
			revision.EvidencePresent, revision.Evidence, evidence = true, number, payload
		}
	}
	return revision, legacy, evidence, rows.Err()
}

func (p postgresGrantPair) GrantPairRevision(ctx context.Context) (grantstore.GrantPairRevision, error) {
	revision, _, _, err := p.readPairRevision(ctx, false)
	return revision, err
}

func (p postgresGrantPair) LoadGrantPairWithRevision(ctx context.Context) (grantstore.GrantPairRevision, []byte, []byte, error) {
	return p.readPairRevision(ctx, true)
}

// One snapshot for both keys; two independent SELECTs could observe a revocation
// only on one side, or an authorization without its immutable evidence.
func (p postgresGrantPair) LoadGrantPair(parent context.Context) ([]byte, []byte, error) {
	ctx, cancel := context.WithTimeout(parent, cpStateBlobDBTimeout)
	defer cancel()
	rows, e := p.db.QueryContext(ctx, `SELECT store_key,payload FROM cp_state_blobs WHERE store_key IN ('grants','grants_evidence_v1')`)
	if e != nil {
		return nil, nil, e
	}
	defer rows.Close()
	var a, b []byte
	for rows.Next() {
		var k string
		var v []byte
		if e := rows.Scan(&k, &v); e != nil {
			return nil, nil, e
		}
		if k == "grants" {
			a = v
		} else {
			b = v
		}
	}
	return a, b, rows.Err()
}
func (p postgresGrantPair) UpdateGrantPair(parent context.Context, edit func([]byte, []byte) ([]byte, []byte, error)) (err error) {
	commitAttempted := false
	defer func() {
		if err != nil && !commitAttempted {
			err = writeNotCommittedError{err}
		}
	}()
	ctx, cancel := context.WithTimeout(parent, cpStateBlobDBTimeout)
	defer cancel()
	budget := newCPStatementBudget(ctx)
	defer budget.cancel()
	tx, finish, err := beginCPWriteTransactionContexts(ctx, budget.sqlCtx, p.db, nil)
	if err != nil {
		return err
	}
	defer finish()
	defer tx.Rollback()
	// Same legacy-row lock as the released transactional writer, then sidecar.
	keys := []string{"grants", grantEvidenceKey}
	data := make([][]byte, 2)
	for i, k := range keys {
		inserted, e := budget.exec(tx, `INSERT INTO cp_state_blobs (store_key,payload,updated_at) VALUES ($1,'{}',now()) ON CONFLICT (store_key) DO NOTHING`, k)
		if e != nil {
			return e
		}
		if e = budget.queryRow(tx, `SELECT payload FROM cp_state_blobs WHERE store_key=$1 FOR UPDATE`, k).Scan(&data[i]); e != nil {
			return e
		}
		n, e := inserted.RowsAffected()
		if e != nil {
			return e
		}
		if n == 1 {
			data[i] = nil
		}
	}
	if e := cpWriteContextError(parent, ctx); e != nil {
		return e
	}
	a, b, e := edit(data[0], data[1])
	if e != nil {
		return e
	}
	for i, next := range [][]byte{a, b} {
		if bytes.Equal(data[i], next) {
			continue
		}
		if _, e = budget.exec(tx, `UPDATE cp_state_blobs SET payload=$2,updated_at=now() WHERE store_key=$1`, keys[i], next); e != nil {
			return e
		}
	}
	if e := cpWriteContextError(parent, ctx); e != nil {
		return e
	}
	commitAttempted = true
	return tx.Commit()
}

func rollingGrantPersister(p blobstore.Persister) blobstore.Persister {
	if pg, ok := p.(postgresBlobPersister); ok && pg.key == "grants" {
		return grantstore.NewCachedRollingPersister(postgresGrantPair{db: pg.db})
	}
	return p
}
