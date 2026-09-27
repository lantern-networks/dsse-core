package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/archive"
	"github.com/lantern-networks/dsse-core/hotstore"
)

const clickhouseRetentionJournalKey = "clickhouse_retention_batch"
const clickhouseRetentionLock int64 = 5643927851241

type clickhouseRetentionBatch struct {
	Version     int       `json:"version"`
	ID          string    `json:"id"`
	Target      string    `json:"target"`
	Tenant      string    `json:"tenant"`
	Stream      string    `json:"stream"`
	IDs         []string  `json:"ids"`
	Key         string    `json:"key"`
	Payload     []byte    `json:"payload"`
	Hash        string    `json:"hash"`
	Seq         int       `json:"seq"`
	Prev        string    `json:"prev"`
	RetainUntil time.Time `json:"retain_until"`
	Phase       string    `json:"phase"`
}

type clickhouseRetentionLifecycle struct {
	db  *sql.DB
	hot *hotstore.ClickHouseStore
	cfg retentionConfig
}

func (c *clickhouseRetentionLifecycle) ready(ctx context.Context) error {
	if c == nil || c.db == nil || c.hot == nil || c.cfg.archive == nil || c.cfg.legalHold == nil || c.cfg.override == nil || c.cfg.auditChain == nil {
		return fmt.Errorf("ClickHouse retention requires shared policy and an archive")
	}
	for _, p := range []any{c.cfg.legalHold.persister, c.cfg.override.persister, c.cfg.auditChain.persister} {
		v, ok := p.(postgresBlobPersister)
		if !ok || v.db != c.db {
			return fmt.Errorf("ClickHouse retention requires one PostgreSQL policy authority")
		}
	}
	return c.hot.RetentionReady(ctx)
}
func decodeClickhouseRetentionBatch(raw []byte) (*clickhouseRetentionBatch, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	var b clickhouseRetentionBatch
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("invalid ClickHouse retention journal")
	}
	if dec.Decode(new(any)) != io.EOF || b.Version != 1 || len(b.ID) != 32 || len(b.Target) != 64 || b.Tenant == "" || b.Stream == "" || len(b.IDs) == 0 || len(b.IDs) > retentionPruneBatchSize || b.Hash != hashObjectBytes(b.Payload) || (b.Phase != "prepared" && b.Phase != "archived") {
		return nil, fmt.Errorf("invalid ClickHouse retention journal")
	}
	if _, err := hex.DecodeString(b.ID); err != nil {
		return nil, fmt.Errorf("invalid retention batch ID")
	}
	if b.Seq < 0 || !strings.HasPrefix(b.Key, "hot_events/"+b.Tenant+"/"+b.Stream+"/") || !strings.HasSuffix(b.Key, "-"+b.Hash+"-"+b.ID+".ndjson.gz") {
		return nil, fmt.Errorf("invalid retention archive identity")
	}
	seen := map[string]bool{}
	for _, id := range b.IDs {
		compact := strings.ReplaceAll(id, "-", "")
		_, err := hex.DecodeString(compact)
		if len(id) != 36 || len(compact) != 32 || err != nil || seen[id] {
			return nil, fmt.Errorf("invalid retention receipt")
		}
		seen[id] = true
	}
	return &b, nil
}

// Both policy updates and batch admission take this lock before any shared row
// lock. A committed batch keeps its erasure fence even after session/leader loss.
func guardClickhouseRetentionPolicy(budget *cpStatementBudget, tx *sql.Tx, key string) error {
	if key != "legal_hold" && key != "retention_override" {
		return nil
	}
	if _, err := budget.exec(tx, "SELECT pg_advisory_xact_lock($1)", clickhouseRetentionLock); err != nil {
		return err
	}
	if key != "retention_override" {
		return nil
	}
	var raw []byte
	err := budget.queryRow(tx, "SELECT payload FROM cp_state_blobs WHERE store_key=$1", clickhouseRetentionJournalKey).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	batch, err := decodeClickhouseRetentionBatch(raw)
	if err != nil {
		return err
	}
	if batch != nil {
		return fmt.Errorf("log retention batch is in progress; retry the setting after it completes")
	}
	return nil
}
func (c *clickhouseRetentionLifecycle) transaction(ctx context.Context, edit func(*cpStatementBudget, *sql.Tx, *clickhouseRetentionBatch) (*clickhouseRetentionBatch, error)) error {
	ctx = retentionWriteContext(ctx)
	ctx, cancel := context.WithTimeout(ctx, cpStateBlobDBTimeout)
	defer cancel()
	unlock, err := lockPrunePolicy(ctx, c.cfg)
	if err != nil {
		return err
	}
	defer unlock()
	budget := newCPStatementBudget(ctx)
	defer budget.cancel()
	tx, finish, err := beginCPWriteTransactionContexts(ctx, budget.sqlCtx, c.db, nil)
	if err != nil {
		return err
	}
	defer finish()
	defer tx.Rollback()
	if _, err = budget.exec(tx, "SELECT pg_advisory_xact_lock($1)", clickhouseRetentionLock); err != nil {
		return err
	}
	raw, err := prunePolicyRow(budget, tx, clickhouseRetentionJournalKey, "null", false)
	if err != nil {
		return err
	}
	current, err := decodeClickhouseRetentionBatch(raw)
	if err != nil {
		return err
	}
	next, err := edit(budget, tx, current)
	if err != nil {
		return err
	}
	raw, err = json.Marshal(next)
	if err != nil {
		return err
	}
	if _, err = budget.exec(tx, "UPDATE cp_state_blobs SET payload=$2,updated_at=now() WHERE store_key=$1", clickhouseRetentionJournalKey, raw); err != nil {
		return err
	}
	if err = budget.commit(tx); err == nil {
		adoptPrunePolicy(c.cfg)
	}
	return err
}
func (c *clickhouseRetentionLifecycle) pending() (*clickhouseRetentionBatch, error) {
	raw, err := (postgresBlobPersister{db: c.db, key: clickhouseRetentionJournalKey}).Load()
	if err != nil {
		return nil, err
	}
	return decodeClickhouseRetentionBatch(raw)
}
func (c *clickhouseRetentionLifecycle) prepare(ctx context.Context, tenant, stream string, cutoff, now time.Time, rows []hotstore.RetentionRecord) error {
	if len(rows) == 0 {
		return nil
	}
	return c.transaction(ctx, func(budget *cpStatementBudget, tx *sql.Tx, current *clickhouseRetentionBatch) (*clickhouseRetentionBatch, error) {
		if current != nil {
			return nil, fmt.Errorf("another log retention batch is pending")
		}
		effective, allowed, err := checkedPruneCutoffWithBudget(budget, tx, c.cfg, tenant, stream, cutoff, now)
		if err != nil {
			return nil, err
		}
		if !allowed {
			return nil, nil
		}
		var selected []hotstore.RetentionRecord
		for _, row := range rows {
			at, err := time.Parse("2006-01-02 15:04:05.999999999", row.Timestamp)
			if err != nil {
				return nil, err
			}
			if at.Before(effective) {
				selected = append(selected, row)
			}
		}
		if len(selected) == 0 {
			return nil, nil
		}
		var nonce [16]byte
		if _, err = rand.Read(nonce[:]); err != nil {
			return nil, err
		}
		batch := &clickhouseRetentionBatch{Version: 1, ID: hex.EncodeToString(nonce[:]), Target: c.hot.RetentionIdentity(), Tenant: tenant, Stream: stream, Phase: "prepared"}
		if stream == "audit" {
			p := c.cfg.auditChain.persister.(postgresBlobPersister)
			raw, err := prunePolicyRow(budget, tx, p.key, "{}", false)
			if err != nil {
				return nil, err
			}
			state, err := decodeSharedAuditChain(raw, false)
			if err != nil {
				return nil, err
			}
			batch.Seq, batch.Prev = state[tenant].Seq, state[tenant].LastHash
			if c.cfg.auditColdRetain > 0 {
				batch.RetainUntil = now.Add(c.cfg.auditColdRetain)
			}
		}
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		if stream == "audit" {
			if _, err = gz.Write(auditChainHeaderLine(batch.Seq, batch.Prev)); err != nil {
				return nil, err
			}
		}
		for _, row := range selected {
			batch.IDs = append(batch.IDs, row.ID)
			if _, err = gz.Write(append(bytes.TrimRight([]byte(row.Raw), "\n"), '\n')); err != nil {
				return nil, err
			}
		}
		if err = gz.Close(); err != nil {
			return nil, err
		}
		batch.Payload, batch.Hash = buf.Bytes(), hashObjectBytes(buf.Bytes())
		batch.Key = fmt.Sprintf("hot_events/%s/%s/%s-%020d-%s-%s.ndjson.gz", tenant, stream, now.UTC().Format("2006-01-02T150405"), batch.Seq, batch.Hash, batch.ID)
		hp := c.cfg.legalHold.persister.(postgresBlobPersister)
		raw, err := prunePolicyRow(budget, tx, hp.key, "[]", c.cfg.legalHold.sharedKnown)
		if err != nil {
			return nil, err
		}
		hold, err := decodeHoldSnapshot(raw, false)
		if err != nil {
			return nil, err
		}
		hold.Erasures[tenant] = tenantErasureFence{ID: batch.ID, Node: "clickhouse-retention", StartedAt: now.UTC().Format(time.RFC3339Nano)}
		raw, err = encodeHoldSnapshot(hold.held(), hold.Erasures, max(2, hold.Version), hold.DeletionPermit)
		if err != nil {
			return nil, err
		}
		_, err = budget.exec(tx, "UPDATE cp_state_blobs SET payload=$2,updated_at=now() WHERE store_key=$1", hp.key, raw)
		return batch, err
	})
}
func (c *clickhouseRetentionLifecycle) resume(ctx context.Context, b *clickhouseRetentionBatch) error {
	if b == nil {
		return nil
	}
	if b.Target != c.hot.RetentionIdentity() {
		return fmt.Errorf("pending retention belongs to a different ClickHouse store")
	}
	if err := c.ready(ctx); err != nil {
		return err
	}
	if b.Phase == "prepared" {
		objects, err := c.cfg.archive.List(ctx, "hot_events/"+b.Tenant+"/"+b.Stream+"/", 0)
		if err != nil {
			return err
		}
		exists := false
		for _, obj := range objects {
			if obj.Key == b.Key {
				exists = true
			}
		}
		if b.Stream == "audit" {
			expected := b.Seq
			if exists {
				expected++
			}
			if len(objects) != expected {
				return fmt.Errorf("audit archive and journal do not agree")
			}
		}
		if !exists {
			_, err = c.cfg.archive.Put(ctx, b.Key, bytes.NewReader(b.Payload), int64(len(b.Payload)), archive.PutOptions{ContentType: "application/gzip", RetainUntil: b.RetainUntil})
			if err != nil {
				return err
			}
		}
		if err := c.verifyArchive(ctx, b); err != nil {
			return err
		}
		err = c.transaction(ctx, func(budget *cpStatementBudget, tx *sql.Tx, current *clickhouseRetentionBatch) (*clickhouseRetentionBatch, error) {
			if current == nil || current.ID != b.ID {
				return nil, fmt.Errorf("retention journal changed")
			}
			if current.Phase == "archived" {
				return current, nil
			}
			if b.Stream == "audit" {
				p := c.cfg.auditChain.persister.(postgresBlobPersister)
				raw, err := prunePolicyRow(budget, tx, p.key, "{}", true)
				if err != nil {
					return nil, err
				}
				states, err := decodeSharedAuditChain(raw, true)
				if err != nil {
					return nil, err
				}
				if states[b.Tenant].Seq != b.Seq || states[b.Tenant].LastHash != b.Prev {
					return nil, fmt.Errorf("audit chain changed")
				}
				states[b.Tenant] = auditChainState{Seq: b.Seq + 1, LastHash: b.Hash}
				raw, err = json.Marshal(states)
				if err != nil {
					return nil, err
				}
				if _, err = budget.exec(tx, "UPDATE cp_state_blobs SET payload=$2,updated_at=now() WHERE store_key=$1", p.key, raw); err != nil {
					return nil, err
				}
			}
			current.Phase = "archived"
			return current, nil
		})
		if err != nil {
			return err
		}
	}
	// Revalidate the durable fence before every delete attempt, including restart.
	// Policy writers can only clear it in the completion transaction below.
	if err := c.transaction(ctx, func(budget *cpStatementBudget, tx *sql.Tx, current *clickhouseRetentionBatch) (*clickhouseRetentionBatch, error) {
		if current == nil || current.ID != b.ID || current.Phase != "archived" {
			return nil, fmt.Errorf("retention journal changed")
		}
		expected := *b
		expected.Phase = "archived"
		want, _ := json.Marshal(expected)
		got, _ := json.Marshal(current)
		if !bytes.Equal(want, got) {
			return nil, fmt.Errorf("retention batch changed")
		}
		hp := c.cfg.legalHold.persister.(postgresBlobPersister)
		raw, err := prunePolicyRow(budget, tx, hp.key, "[]", true)
		if err != nil {
			return nil, err
		}
		hold, err := decodeHoldSnapshot(raw, true)
		if err != nil {
			return nil, err
		}
		if hold.Erasures[b.Tenant].ID != b.ID || hold.Erasures[b.Tenant].Node != "clickhouse-retention" {
			return nil, fmt.Errorf("retention fence changed")
		}
		if err := c.cfg.legalHold.checkDeletionSafety(budget.request, hold.DeletionPermit); err != nil {
			return nil, err
		}
		return current, nil
	}); err != nil {
		return err
	}
	if err := c.verifyArchive(ctx, b); err != nil {
		return err
	}
	// Exact immutable insertion receipts make a delayed duplicate delete harmless,
	// even after this fence is cleared and a later hold has been accepted.
	if err := c.hot.DeleteRetentionBatch(ctx, b.Tenant, b.Stream, b.IDs); err != nil {
		return err
	}
	return c.transaction(ctx, func(budget *cpStatementBudget, tx *sql.Tx, current *clickhouseRetentionBatch) (*clickhouseRetentionBatch, error) {
		if current == nil {
			return nil, nil
		}
		if current.ID != b.ID {
			return nil, fmt.Errorf("retention journal changed")
		}
		hp := c.cfg.legalHold.persister.(postgresBlobPersister)
		raw, err := prunePolicyRow(budget, tx, hp.key, "[]", true)
		if err != nil {
			return nil, err
		}
		holds, err := decodeHoldSnapshot(raw, true)
		if err != nil {
			return nil, err
		}
		if holds.Erasures[b.Tenant].ID != b.ID {
			return nil, fmt.Errorf("retention fence changed")
		}
		delete(holds.Erasures, b.Tenant)
		raw, err = encodeHoldSnapshot(holds.held(), holds.Erasures, holds.Version, holds.DeletionPermit)
		if err != nil {
			return nil, err
		}
		_, err = budget.exec(tx, "UPDATE cp_state_blobs SET payload=$2,updated_at=now() WHERE store_key=$1", hp.key, raw)
		return nil, err
	})
}
func (c *clickhouseRetentionLifecycle) verifyArchive(ctx context.Context, b *clickhouseRetentionBatch) error {
	reader, err := c.cfg.archive.Get(ctx, b.Key)
	if err != nil {
		return err
	}
	payload, readErr := io.ReadAll(io.LimitReader(reader, int64(len(b.Payload))+1))
	closeErr := reader.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	if !bytes.Equal(payload, b.Payload) {
		return fmt.Errorf("archived log batch verification failed")
	}
	return nil
}

func (c *clickhouseRetentionLifecycle) sweep(ctx context.Context, now time.Time) error {
	if err := c.ready(ctx); err != nil {
		return err
	}
	pending, err := c.pending()
	if err != nil {
		return err
	}
	if pending != nil {
		if err = c.resume(ctx, pending); err != nil {
			return err
		}
	}
	pairs, err := c.hot.RetentionStreams(ctx)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(c.cfg.sweepBudget())
	for _, pair := range pairs {
		for time.Now().Before(deadline) && ctx.Err() == nil {
			if err = c.cfg.override.refreshSharedContext(ctx); err != nil {
				return err
			}
			if c.cfg.legalHold.IsHeld(pair.Tenant) {
				break
			}
			duration := c.cfg.retentionForStream(pair.Stream)
			if duration <= 0 {
				break
			}
			cutoff := now.Add(-duration)
			rows, err := c.hot.RetentionBatch(ctx, pair.Tenant, pair.Stream, cutoff, retentionPruneBatchSize)
			if err != nil {
				return err
			}
			if len(rows) == 0 {
				break
			}
			if err = c.prepare(ctx, pair.Tenant, pair.Stream, cutoff, now, rows); err != nil {
				return err
			}
			batch, err := c.pending()
			if err != nil {
				return err
			}
			if batch == nil {
				break
			}
			if err = c.resume(ctx, batch); err != nil {
				return err
			}
			if len(rows) < retentionPruneBatchSize {
				break
			}
		}
	}
	return ctx.Err()
}
