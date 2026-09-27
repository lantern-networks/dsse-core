package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
)

func decodeSharedAuditChain(raw []byte, known bool) (map[string]auditChainState, error) {
	if len(raw) == 0 {
		if known {
			return nil, fmt.Errorf("known audit chain row is missing")
		}
		return map[string]auditChainState{}, nil
	}
	return decodeAuditChainState(raw)
}

// Caller holds mu. A read failure never turns the shared chain into a new chain.
func (s *auditChainStore) refreshSharedLocked() error {
	if _, ok := s.persister.(retentionSharedUpdater); !ok {
		return nil
	}
	raw, err := s.persister.Load()
	var next map[string]auditChainState
	if err == nil {
		next, err = decodeSharedAuditChain(raw, s.sharedKnown)
	}
	if err != nil {
		return fmt.Errorf("audit chain shared state unavailable")
	}
	s.per = next
	s.sharedKnown = s.sharedKnown || len(raw) > 0
	return nil
}
func (s *auditChainStore) commitSharedLocked(ctx context.Context, tenant string, seq int, hash string) error {
	var next map[string]auditChainState
	expected := s.per[tenant]
	err := s.persister.(retentionSharedUpdater).UpdateContext(ctx, func(raw []byte) ([]byte, error) {
		current, err := decodeSharedAuditChain(raw, s.sharedKnown)
		if err != nil {
			return nil, err
		}
		if seq != expected.Seq || current[tenant] != expected {
			return nil, fmt.Errorf("audit chain generation changed")
		}
		current[tenant] = auditChainState{Seq: seq + 1, LastHash: hash}
		next = current
		return json.Marshal(current)
	})
	if err != nil {
		s.stateErr = fmt.Errorf("audit chain shared advance failed; reconciliation required")
		return s.stateErr
	}
	s.per = next
	s.sharedKnown = true
	return nil
}

// The production pruner and shared authority use the same PostgreSQL database.
// Holding its chain row through PUT prevents two writers from choosing the same
// head; head advancement and exact hot-row deletion share this SQL transaction.
// Object storage is not transactional: a PUT followed by SQL failure requires
// reconciliation, and the next fresh process refuses an object-count mismatch.
type sharedAuditArchive struct {
	tx                       *sql.Tx
	release                  func()
	source                   *auditChainStore
	next                     map[string]auditChainState
	key                      string
	objectWritten, committed bool
}

func (s *auditChainStore) beginSharedArchive(budget *cpStatementBudget, db *sql.DB) (*sharedAuditArchive, error) {
	p, ok := s.persister.(postgresBlobPersister)
	if !ok {
		if _, shared := s.persister.(retentionSharedUpdater); shared {
			return nil, fmt.Errorf("shared archive requires a PostgreSQL transaction")
		}
		return nil, nil
	}
	s.mu.Lock()
	if s.stateErr != nil {
		err := s.stateErr
		s.mu.Unlock()
		return nil, err
	}
	tx, release, err := beginCPWriteTransactionContexts(budget.request, budget.sqlCtx, db, nil)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	session := &sharedAuditArchive{tx: tx, release: release, source: s, key: p.key}
	inserted, err := budget.exec(tx, `INSERT INTO cp_state_blobs(store_key,payload,updated_at) VALUES($1,'{}',now()) ON CONFLICT(store_key) DO NOTHING`, p.key)
	var raw []byte
	if err == nil {
		err = budget.queryRow(tx, `SELECT payload FROM cp_state_blobs WHERE store_key=$1 FOR UPDATE`, p.key).Scan(&raw)
	}
	if err == nil {
		var n int64
		n, err = inserted.RowsAffected()
		if n == 1 {
			raw = nil
		}
	}
	if err == nil {
		session.next, err = decodeSharedAuditChain(raw, s.sharedKnown)
	}
	if err != nil {
		session.close()
		return nil, fmt.Errorf("audit chain shared state unavailable")
	}
	return session, nil
}
func (s *sharedAuditArchive) stage(budget *cpStatementBudget, next map[string]auditChainState) error {
	raw, err := json.Marshal(next)
	if err == nil {
		_, err = budget.exec(s.tx, `UPDATE cp_state_blobs SET payload=$2,updated_at=now() WHERE store_key=$1`, s.key, raw)
	}
	if err == nil {
		s.next = next
	}
	return err
}
func (s *sharedAuditArchive) adopt() {
	s.source.per = s.next
	s.source.sharedKnown = true
	s.committed = true
}
func (s *sharedAuditArchive) close() {
	s.tx.Rollback()
	if s.objectWritten && !s.committed {
		s.source.stateErr = fmt.Errorf("audit archive SQL commit unconfirmed; reconciliation required")
	}
	s.release()
	s.source.mu.Unlock()
}
