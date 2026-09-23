package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/archive"
	"github.com/lib/pq"
)

// Retention pruning (W4, docs/feature_inventory_and_production_readiness.md A-1). The postgres log/outbox
// tables (hot_events, admin_audit_outbox, domain_event_outbox) had no retention — published/dead rows and
// mirrored events accumulate forever, bloating storage + degrading queries. This periodically deletes rows
// past their TTL. Runs only where the durable tables live (the control plane, -postgres-dsn set). Pending /
// publishing outbox rows are NEVER pruned (only published + dead, which are terminal).

type retentionConfig struct {
	interval        time.Duration
	hotEvents       time.Duration // move/delete hot_events older than this (0 = keep)
	outboxPublished time.Duration // delete published outbox rows older than this (0 = keep)
	outboxDead      time.Duration // delete dead outbox rows older than this (0 = keep)
	// archive, when set, turns hot_events pruning into TIER-TO-COLD: aged rows are written (per tenant+stream,
	// gzip NDJSON) to the sovereign cold archive BEFORE they are deleted — long-term compliance/DFIR retention
	// on a sovereign store, not a hard delete. nil = delete-only (previous behaviour).
	archive archive.ColdArchive
	// auditColdRetain, when set, WORM-locks (object-lock) the archived AUDIT-stream segments for this long from
	// archive time — tamper-proof compliance retention for the audit trail. 0 = no lock.
	auditColdRetain time.Duration
	// perStream overrides the hot-events retention PER STREAM (e.g. keep audit far longer than access). A stream
	// not listed falls back to hotEvents. A value of 0 = keep that stream in hot forever (never prune it).
	perStream map[string]time.Duration
	// legalHold, when set, freezes retention for tenants under a legal hold: the pruner preserves ALL their
	// logs (no delete, no tier-then-delete) until the hold is released. nil = no holds.
	legalHold *legalHoldStore
	// auditChain, when set, embeds a tamper-evident hash-chain header in each archived AUDIT segment so that
	// deleting/altering/reordering any segment is detectable. nil = no chain.
	auditChain *auditChainStore
	// override, when set, holds admin-configured per-stream retention (Console) that takes precedence over the
	// startup-flag defaults, so retention is tunable without a redeploy. nil = flags only.
	override *retentionOverrideStore
}

func (c retentionConfig) enabled() bool {
	return c.interval > 0 && (c.hotEvents > 0 || len(c.perStream) > 0 || c.override != nil || c.outboxPublished > 0 || c.outboxDead > 0)
}

// retentionForStream is the hot-events retention for a stream. Precedence: admin Console override (runtime) >
// per-stream startup flag > global default.
func (c retentionConfig) retentionForStream(stream string) time.Duration {
	if c.override != nil {
		if d, ok := c.override.Get(stream); ok {
			return time.Duration(d) * 24 * time.Hour // configured in DAYS
		}
	}
	if d, ok := c.perStream[stream]; ok {
		return d
	}
	return c.hotEvents
}

func startRetentionPruner(ctx context.Context, dsn string, cfg retentionConfig) (func() error, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	go func() {
		runRetentionPrune(ctx, db, cfg) // initial sweep
		t := time.NewTicker(cfg.interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				runRetentionPrune(ctx, db, cfg)
			}
		}
	}()
	log.Printf("retention pruner ENABLED (interval=%s hot_events=%s outbox_published=%s outbox_dead=%s)",
		cfg.interval, cfg.hotEvents, cfg.outboxPublished, cfg.outboxDead)
	return db.Close, nil
}

func runRetentionPrune(ctx context.Context, db *sql.DB, cfg retentionConfig) {
	ctx = retentionWriteContext(ctx)
	if err := cfg.override.Health(); err != nil {
		log.Printf("retention paused: %v", err)
		return
	}
	if err := cfg.legalHold.Health(); err != nil {
		log.Printf("retention paused: %v", err)
		return
	}
	// CP HA: only the leader prunes/tiers, so two active CPs don't double-delete rows or double-archive segments
	// to the cold store. A standby simply skips; when it becomes leader it takes over the sweep.
	if !cpLeaderElectorInstance.IsLeader() {
		return
	}
	now := time.Now()
	if cfg.hotEvents > 0 || len(cfg.perStream) > 0 || cfg.override != nil {
		pruneHotEventsPerStream(ctx, db, cfg, now)
	}
	for _, tbl := range []string{"admin_audit_outbox", "domain_event_outbox"} {
		if cfg.outboxPublished > 0 {
			pruneOlderThan(ctx, db, cfg, tbl, "updated_at", "status = 'published'", now.Add(-cfg.outboxPublished))
		}
		if cfg.outboxDead > 0 {
			pruneOlderThan(ctx, db, cfg, tbl, "updated_at", "status = 'dead'", now.Add(-cfg.outboxDead))
		}
	}
}

// pruneHotEventsPerStream applies each stream's own retention (audit/deny kept longer than allow/access) to the
// hot_events table. Per (tenant, stream): compute the stream's cutoff, then either TIER-to-cold-then-delete
// (when a cold archive is configured) or delete-only. A per-stream retention of 0 keeps that stream forever.
func pruneHotEventsPerStream(ctx context.Context, db *sql.DB, cfg retentionConfig, now time.Time) {
	rows, err := db.QueryContext(ctx, "SELECT DISTINCT tenant_id, stream FROM hot_events")
	if err != nil {
		log.Printf("retention: list hot_events streams: %v", err)
		return
	}
	type ts struct{ tenant, stream string }
	var pairs []ts
	for rows.Next() {
		var p ts
		if err := rows.Scan(&p.tenant, &p.stream); err == nil {
			pairs = append(pairs, p)
		}
	}
	rows.Close()
	for _, p := range pairs {
		if cfg.legalHold != nil && cfg.legalHold.IsHeld(p.tenant) {
			continue // legal hold: preserve everything for this tenant (no delete, no tier)
		}
		ret := cfg.retentionForStream(p.stream)
		if ret <= 0 {
			continue // keep this stream in hot forever
		}
		cutoff := now.Add(-ret)
		if cfg.archive != nil {
			archiveThenPruneStream(ctx, db, cfg, p.tenant, p.stream, cutoff, now)
		} else {
			deleteHotStreamOlderThan(ctx, db, cfg, p.tenant, p.stream, cutoff, now)
		}
	}
}

// deleteHotStreamOlderThan is the delete-only path (no cold archive configured) for one stream.
func deleteHotStreamOlderThan(ctx context.Context, db *sql.DB, cfg retentionConfig, tenant, stream string, cutoff, now time.Time) {
	deleteRetentionRows(ctx, db, cfg, "hot_events", "received_at < $2 AND stream=$3", tenant, stream, cutoff, now)
}
func logPruneFailure(table string, err error) {
	log.Printf("retention prune %s paused: %v", table, err)
}
func logPruneDeleted(table, tenant string, n int64, cutoff time.Time) {
	log.Printf("retention prune %s tenant=%s: deleted %d row(s) older than %s", table, tenant, n, cutoff.UTC().Format(time.RFC3339))
}

func archiveThenPruneStream(ctx context.Context, db *sql.DB, cfg retentionConfig, tenant, stream string, cutoff, now time.Time) {
	ctx = retentionWriteContext(ctx)
	// Share one request budget across SQL and object-store work. PostgreSQL
	// expires data statements before the later client fallback can discard the
	// advisory-lock session. Keep the original cancellation for external calls
	// and check it again before advancing the chain or committing deletion.
	archiveCtx, cancel := context.WithTimeout(ctx, cpStateBlobDBTimeout)
	defer cancel()
	budget := newCPStatementBudget(archiveCtx)
	defer budget.cancel()
	unlockPolicy, err := lockPrunePolicy(archiveCtx, cfg)
	if err != nil {
		log.Printf("cold-archive policy wait: %v", err)
		return
	}
	defer unlockPolicy()
	chained := stream == "audit" && cfg.auditChain != nil
	var shared *sharedAuditArchive
	if chained {
		if err := cfg.auditChain.operationMu.LockContext(archiveCtx); err != nil {
			log.Printf("cold-archive chain wait: %v", err)
			return
		}
		defer cfg.auditChain.operationMu.Unlock()
		var err error
		shared, err = cfg.auditChain.beginSharedArchive(budget, db)
		if err != nil {
			log.Printf("cold-archive shared state: %v", err)
			return
		}
		if shared != nil {
			defer shared.close()
			// This detached view is scoped to the locked database row. Its
			// Commit stages the head; the real head and hot deletes commit together.
			cfg.auditChain = &auditChainStore{per: shared.next}
		}
		if err := cfg.auditChain.Health(); err != nil {
			log.Printf("cold-archive paused: %v", err)
			return
		}
	}
	var tx *sql.Tx
	if shared != nil {
		tx = shared.tx
	} else {
		var finish func()
		tx, finish, err = beginCPWriteTransactionContexts(budget.request, budget.sqlCtx, db, nil)
		if err == nil {
			defer finish()
		}
	}
	if err != nil {
		log.Printf("cold-archive begin: %v", err)
		return
	}
	defer tx.Rollback()
	cutoff, allowed, err := checkedPruneCutoffWithBudget(budget, tx, cfg, tenant, stream, cutoff, now)
	if err != nil {
		logPruneFailure("hot_events", err)
		return
	}
	if !allowed {
		return
	}
	rows, err := budget.query(tx, "SELECT event_id, payload FROM hot_events WHERE tenant_id = $1 AND stream = $2 AND received_at < $3 ORDER BY received_at, event_id FOR UPDATE", tenant, stream, cutoff)
	if err != nil {
		log.Printf("cold-archive: read %s/%s: %v", tenant, stream, err)
		return
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	// Tamper-evident chain: the audit stream's segments begin with a chain header binding this segment to the
	// previous one. Written BEFORE the records so it is covered by the segment hash.
	chainSeq := 0
	if chained {
		var prev string
		chainSeq, prev, err = cfg.auditChain.Next(tenant)
		if err != nil {
			rows.Close()
			log.Printf("cold-archive chain: %v", err)
			return
		}
		gz.Write(auditChainHeaderLine(chainSeq, prev))
	}
	n := 0
	var eventIDs []string
	for rows.Next() {
		var payload []byte // jsonb comes back as raw JSON bytes
		var eventID string
		if err := rows.Scan(&eventID, &payload); err != nil {
			rows.Close()
			log.Printf("cold-archive scan: %v", err)
			return
		}
		eventIDs = append(eventIDs, eventID)
		gz.Write(bytes.TrimRight(payload, "\n"))
		gz.Write([]byte("\n"))
		n++
	}
	rowErr := rows.Err()
	closeErr := rows.Close()
	if rowErr != nil || closeErr != nil {
		log.Printf("cold-archive read incomplete: %v / %v", rowErr, closeErr)
		return
	}
	if n == 0 {
		return
	}
	if err := gz.Close(); err != nil {
		log.Printf("cold-archive: gzip %s/%s: %v", tenant, stream, err)
		return
	}
	// Consult the external archive only after the locked policy and hot-row
	// selection establish that there is work to archive. Protected or empty
	// streams must not occupy the CP writer waiting on an unavailable store.
	// Keep this check inside the same head transaction as PUT: moving it
	// outside would miss an orphan left by a competing failed archive.
	if chained {
		objects, err := cfg.archive.List(archiveCtx, "hot_events/"+tenant+"/audit/", 0)
		if err != nil {
			log.Printf("cold-archive paused tenant=%q: archive listing failed; retry on a later sweep: %v", tenant, err)
			return
		}
		if len(objects) != chainSeq {
			log.Printf("cold-archive paused tenant=%q: archive count mismatch expected=%d actual=%d; reconcile archive objects and saved chain state", tenant, chainSeq, len(objects))
			return
		}
	}
	// Sequence and content hash prevent a delete retry from overwriting an earlier segment.
	key := fmt.Sprintf("hot_events/%s/%s/%s-%020d-%s.ndjson.gz", tenant, stream, now.UTC().Format("2006-01-02T150405"), chainSeq, hashObjectBytes(buf.Bytes()))
	opts := archive.PutOptions{ContentType: "application/gzip"}
	if stream == "audit" && cfg.auditColdRetain > 0 {
		opts.RetainUntil = now.Add(cfg.auditColdRetain) // WORM: audit segments are tamper-proof for the retention window
	}
	if _, err := cfg.archive.Put(archiveCtx, key, bytes.NewReader(buf.Bytes()), int64(buf.Len()), opts); err != nil {
		log.Printf("cold-archive: put %s FAILED — leaving %d row(s) in place for retry: %v", key, n, err)
		return
	}
	if shared != nil {
		shared.objectWritten = true
	}
	if err := archiveCtx.Err(); err != nil {
		log.Printf("cold-archive: object written but request canceled; hot rows retained: %v", err)
		return
	}
	// Advance the tamper-evident chain only AFTER the segment is durably written (its hash = the object bytes).
	if chained {
		if err := cfg.auditChain.Commit(tenant, chainSeq, hashObjectBytes(buf.Bytes())); err != nil {
			log.Printf("cold-archive: %s retained in hot after state failure: %v", key, err)
			return
		}
	}
	if shared != nil {
		if err := shared.stage(budget, cfg.auditChain.per); err != nil {
			log.Printf("cold-archive: head update failed; hot rows retained: %v", err)
			return
		}
	}
	// Archived successfully → now safe to delete exactly this stream's aged rows.
	res, err := budget.exec(tx, "DELETE FROM hot_events WHERE tenant_id = $1 AND stream = $2 AND event_id = ANY($3)", tenant, stream, pq.Array(eventIDs))
	if err != nil {
		log.Printf("cold-archive: archived %s but delete failed; hot rows retained, reconcile before retry: %v", key, err)
		return
	}
	if err := budget.commit(tx); err != nil {
		log.Printf("cold-archive: archived %s but delete commit failed: %v", key, err)
		return
	}
	adoptPrunePolicy(cfg)
	if shared != nil {
		shared.adopt()
	}
	deleted, _ := res.RowsAffected()
	worm := ""
	if !opts.RetainUntil.IsZero() {
		worm = fmt.Sprintf(" worm_until=%s", opts.RetainUntil.UTC().Format(time.RFC3339))
	}
	log.Printf("cold-archive: tiered %d row(s) %s/%s to %s (deleted %d from hot)%s", n, tenant, stream, key, deleted, worm)
}

// pruneOlderThan deletes rows whose timeCol is < cutoff, optionally filtered by extraWhere. Best-effort:
// errors are logged (a missing table on a non-CP node is fine — the pruner only runs with -postgres-dsn).
func pruneOlderThan(ctx context.Context, db *sql.DB, cfg retentionConfig, table, timeCol, extraWhere string, cutoff time.Time) {
	rows, err := db.QueryContext(ctx, "SELECT DISTINCT tenant_id FROM "+table+" WHERE "+extraWhere+" AND "+timeCol+" < $1", cutoff)
	if err != nil {
		logPruneFailure(table, err)
		return
	}
	var tenants []string
	for rows.Next() {
		var tenant string
		if err := rows.Scan(&tenant); err != nil {
			rows.Close()
			logPruneFailure(table, err)
			return
		}
		tenants = append(tenants, tenant)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		logPruneFailure(table, err)
		return
	}
	for _, tenant := range tenants {
		deleteRetentionRows(ctx, db, retentionConfig{legalHold: cfg.legalHold}, table, extraWhere+" AND "+timeCol+" < $2", tenant, "", cutoff, time.Now())
	}
}

func ifNonEmpty(s string) string {
	if s == " " {
		return ""
	}
	return s
}

// parseRetentionOverrides parses "stream=duration,stream=duration" (e.g. "audit=8760h,access=168h") into a
// per-stream retention map. Invalid entries are skipped (logged) so a typo can't disable pruning entirely.
func parseRetentionOverrides(spec string) map[string]time.Duration {
	out := map[string]time.Duration{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			log.Printf("retention: ignoring malformed override %q (want stream=duration)", part)
			continue
		}
		stream := strings.TrimSpace(kv[0])
		d, err := time.ParseDuration(strings.TrimSpace(kv[1]))
		if err != nil || stream == "" {
			log.Printf("retention: ignoring override %q: %v", part, err)
			continue
		}
		out[stream] = d
	}
	return out
}
