package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestDeletionSafetyDefaultStartupAndExplicitMode(t *testing.T) {
	for _, version := range []int{0, 2, 3} {
		h, r := newLegalHoldStore(nil), newRetentionOverrideStore(nil)
		h.snapshotVersion = version
		if err := configureExistingDeletionSafety(h, r, false); err != nil {
			t.Fatal(err)
		}
		err := h.checkDeletionSafety(context.Background(), nil)
		if (err != nil) != (version == 3) {
			t.Fatalf("version %d gate=%v", version, err)
		}
	}
}

func TestPostgresRetentionBacklogMakesBoundedProgress(t *testing.T) {
	p, _, _ := blobWriterPostgresFixture(t)
	if _, err := p.db.Exec(`CREATE TABLE hot_events(tenant_id text,stream text,event_id text,received_at timestamptz,payload bytea)`); err != nil {
		t.Fatal(err)
	}
	for _, archived := range []bool{false, true} {
		if _, err := p.db.Exec(`TRUNCATE hot_events; INSERT INTO hot_events SELECT 'tenant','access',n::text,now()-interval '10 days',convert_to('{}','UTF8') FROM generate_series(1,2001) n`); err != nil {
			t.Fatal(err)
		}
		cfg := retentionConfig{hotEvents: 24 * time.Hour}
		arc := &fakeArchive{objs: map[string][]byte{}}
		if archived {
			cfg.archive = arc
		}
		now := time.Now()

		// A statement trigger rejects any transaction deleting more than one batch.
		if _, err := p.db.Exec(`CREATE FUNCTION enforce_batch() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF (SELECT count(*) FROM deleted_rows)>1000 THEN RAISE EXCEPTION 'oversized retention batch'; END IF; RETURN NULL; END $$; CREATE TRIGGER bounded_delete AFTER DELETE ON hot_events REFERENCING OLD TABLE AS deleted_rows FOR EACH STATEMENT EXECUTE FUNCTION enforce_batch()`); err != nil {
			t.Fatal(err)
		}
		if archived {
			archiveThenPruneStream(context.Background(), p.db, cfg, "tenant", "access", now.Add(-24*time.Hour), now)
		} else {
			deleteHotStreamOlderThan(context.Background(), p.db, cfg, "tenant", "access", now.Add(-24*time.Hour), now)
		}
		var n int
		if err := p.db.QueryRow(`SELECT count(*) FROM hot_events`).Scan(&n); err != nil || n != 0 {
			t.Fatalf("archive=%v remaining=%d err=%v", archived, n, err)
		}
		if _, err := p.db.Exec(`DROP TRIGGER bounded_delete ON hot_events; DROP FUNCTION enforce_batch()`); err != nil {
			t.Fatal(err)
		}

		if archived && len(arc.objs) != 3 {
			t.Fatalf("archive segments=%d", len(arc.objs))
		}
	}
}

func TestPostgresRetentionBatchPlans(t *testing.T) {
	p, _, _ := blobWriterPostgresFixture(t)
	_, err := p.db.Exec(`CREATE TABLE hot_events(tenant_id text,stream text,event_id text,received_at timestamptz,payload bytea); CREATE INDEX hot_events_retention_idx ON hot_events(tenant_id,stream,received_at,event_id); INSERT INTO hot_events SELECT 'tenant','access',n::text,now()-interval '10 days',convert_to('{}','UTF8') FROM generate_series(1,100000) n; ANALYZE hot_events`)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ sql, want string }{
		{`SELECT event_id,payload FROM hot_events WHERE tenant_id='tenant' AND stream='access' AND received_at<now()-interval '1 day' ORDER BY received_at,event_id LIMIT 1000 FOR UPDATE`, "hot_events_retention_idx"},
		{`DELETE FROM hot_events WHERE ctid=ANY(ARRAY(SELECT ctid FROM hot_events WHERE tenant_id='tenant' AND stream='access' AND received_at<now()-interval '1 day' LIMIT 1000))`, "Tid Scan"},
	} {
		rows, err := p.db.Query("EXPLAIN " + tc.sql)
		if err != nil {
			t.Fatal(err)
		}
		plan := ""
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				t.Fatal(err)
			}
			plan += line + "\n"
		}
		rows.Close()
		t.Log(plan)
		if !strings.Contains(plan, tc.want) {
			t.Fatal(fmt.Sprintf("expected %s", tc.want))
		}
	}
}

// Reaching the sweep deadline must not cancel an already written audit object
// before its SQL chain head and hot-row deletion are committed.
func TestPostgresAuditRetentionFinishesBatchBeyondSweepBudget(t *testing.T) {
	p, _, _ := blobWriterPostgresFixture(t)
	p.key = "audit_chain"
	if _, err := p.db.Exec(`CREATE TABLE hot_events(tenant_id text,stream text,event_id text,received_at timestamptz,payload bytea); INSERT INTO hot_events SELECT 'tenant','audit',n::text,now()-interval '10 days',convert_to('{}','UTF8') FROM generate_series(1,1001) n`); err != nil {
		t.Fatal(err)
	}
	chain := newAuditChainStore(p)
	arc := &archiveWriteProbe{fakeArchive: fakeArchive{objs: map[string][]byte{}}}
	arc.putHook = func() { time.Sleep(250 * time.Millisecond) }
	cfg := retentionConfig{archive: arc, auditChain: chain, sweepLimit: 100 * time.Millisecond}
	now := time.Now()
	archiveThenPruneStream(context.Background(), p.db, cfg, "tenant", "audit", now.Add(-time.Hour), now)
	if err := chain.Health(); err != nil {
		t.Fatal(err)
	}
	var remaining int
	if err := p.db.QueryRow(`SELECT count(*) FROM hot_events`).Scan(&remaining); err != nil || remaining != 1 {
		t.Fatalf("remaining=%d err=%v", remaining, err)
	}
	if arc.puts != 1 {
		t.Fatalf("puts=%d", arc.puts)
	}
	seq, _, err := newAuditChainStore(p).Next("tenant")
	if err != nil || seq != 1 {
		t.Fatalf("seq=%d err=%v", seq, err)
	}
	verified, err := verifyAuditChain(context.Background(), arc, "tenant")
	if err != nil || !verified.OK || verified.Segments != 1 {
		t.Fatalf("chain=%+v err=%v", verified, err)
	}
}
