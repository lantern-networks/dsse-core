package main

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

func TestPostgresArchiveStatementTimeoutKeepsLeader(t *testing.T) {
	for _, phase := range []string{"head_lock", "hot_lock", "head_update", "delete", "unchained_delete", "cancel_after_put"} {
		t.Run(phase, func(t *testing.T) {
			d, _, leader, peer := trustDistributionPostgresFixture(t)
			p := d.store.(postgresBlobPersister)
			p.key = "audit_chain"
			if err := p.Save([]byte(`{}`)); err != nil {
				t.Fatal(err)
			}
			if _, err := p.db.Exec(`CREATE TABLE hot_events(tenant_id text,stream text,event_id text,received_at timestamptz,payload bytea); INSERT INTO hot_events VALUES('t','audit','old',now()-interval '10 days','{}')`); err != nil {
				t.Fatal(err)
			}
			chain := newAuditChainStore(p)
			arc := &archiveWriteProbe{fakeArchive: fakeArchive{objs: map[string][]byte{}}}
			cfg := retentionConfig{archive: arc, auditChain: chain}
			if phase == "unchained_delete" {
				cfg.auditChain = nil
			}
			var blocker *sql.Tx
			if phase == "head_lock" || phase == "hot_lock" {
				var err error
				blocker, err = p.db.Begin()
				if err != nil {
					t.Fatal(err)
				}
				defer blocker.Rollback()
				q := `SELECT payload FROM cp_state_blobs WHERE store_key='audit_chain' FOR UPDATE`
				if phase == "hot_lock" {
					q = `SELECT payload FROM hot_events FOR UPDATE`
				}
				if _, err = blocker.Exec(q); err != nil {
					t.Fatal(err)
				}
			} else if phase != "cancel_after_put" {
				table, operation := "hot_events", "DELETE"
				if phase == "head_update" {
					table, operation = "cp_state_blobs", "UPDATE"
				}
				if _, err := p.db.Exec(`CREATE FUNCTION slow_archive() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.3); IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF; END $$; CREATE TRIGGER slow_archive BEFORE ` + operation + ` ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION slow_archive()`); err != nil {
					t.Fatal(err)
				}
			}
			var pid int
			if err := leader.conn.QueryRowContext(context.Background(), "SELECT pg_backend_pid()").Scan(&pid); err != nil {
				t.Fatal(err)
			}
			term := leader.leaderSince.Load()
			ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
			if phase == "cancel_after_put" {
				arc.putHook = cancel
			}
			archiveThenPruneStream(ctx, p.db, cfg, "t", "audit", time.Now().Add(-time.Hour), time.Now())
			cancel()
			if blocker != nil {
				blocker.Rollback()
			}
			var count int
			if err := p.db.QueryRow(`SELECT count(*) FROM hot_events`).Scan(&count); err != nil || count != 1 {
				t.Fatalf("hot rows=%d: %v", count, err)
			}
			leader.tick()
			peer.tick()
			if !leader.IsLeader() || peer.IsLeader() {
				t.Fatal("archive SQL timeout lost leader")
			}
			var after int
			var setting string
			if err := leader.conn.QueryRowContext(context.Background(), `SELECT pg_backend_pid(),current_setting('statement_timeout')`).Scan(&after, &setting); err != nil || after != pid || leader.leaderSince.Load() != term || setting != "0" {
				t.Fatalf("leader session/term/setting changed: %v", err)
			}
			if seq, _, err := newAuditChainStore(p).Next("t"); err != nil || seq != 0 {
				t.Fatalf("failed archive advanced head: %d %v", seq, err)
			}
			written := phase == "head_update" || phase == "delete" || phase == "unchained_delete" || phase == "cancel_after_put"
			wantObjects := 0
			if written {
				wantObjects = 1
			}
			if len(arc.objs) != wantObjects {
				t.Fatalf("objects=%d want=%d", len(arc.objs), wantObjects)
			}
			if blocker == nil && phase != "cancel_after_put" {
				table := "hot_events"
				if phase == "head_update" {
					table = "cp_state_blobs"
				}
				if _, err := p.db.Exec("DROP TRIGGER slow_archive ON " + table + "; DROP FUNCTION slow_archive()"); err != nil {
					t.Fatal(err)
				}
			}
			if written && cfg.auditChain != nil {
				if chain.Health() == nil {
					t.Fatal("post-PUT failure did not require reconciliation")
				}
				cfg.auditChain = newAuditChainStore(p)
				archiveThenPruneStream(context.Background(), p.db, cfg, "t", "audit", time.Now().Add(-time.Hour), time.Now())
				if arc.puts != 1 {
					t.Fatal("fresh Store forked orphan on retry")
				}
				if err := p.db.QueryRow(`SELECT count(*) FROM hot_events`).Scan(&count); err != nil || count != 1 {
					t.Fatal("orphan retry removed hot row")
				}
			} else if !written {
				archiveThenPruneStream(context.Background(), p.db, cfg, "t", "audit", time.Now().Add(-time.Hour), time.Now())
				if err := p.db.QueryRow(`SELECT count(*) FROM hot_events`).Scan(&count); err != nil || count != 0 {
					t.Fatal("pre-PUT failure did not recover")
				}
				if seq, _, err := newAuditChainStore(p).Next("t"); err != nil || seq != 1 {
					t.Fatal("successful retry did not advance head")
				}
			}
			t.Logf("same_pid=%d same_term=true timeout_hot_rows=1 objects_after_timeout=%d", pid, wantObjects)
		})
	}
}
