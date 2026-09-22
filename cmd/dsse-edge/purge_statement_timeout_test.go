package main

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

func TestPostgresPurgeBatchCancellationKeepsLeader(t *testing.T) {
	for _, mode := range []string{"delete_deadline", "delete_cancel", "policy_deadline", "credential_deadline"} {
		t.Run(mode, func(t *testing.T) {
			d, _, leader, peer := trustDistributionPostgresFixture(t)
			p := d.store.(postgresBlobPersister)
			p.key = "legal_hold"
			if err := p.Save([]byte(`[]`)); err != nil {
				t.Fatal(err)
			}
			holds := newLegalHoldStore(p)
			table := "hot_events"
			if mode == "credential_deadline" {
				table = "admin_local_credentials"
			}
			if _, err := p.db.Exec("CREATE TABLE " + table + "(tenant_id text); INSERT INTO " + table + " VALUES('target'),('peer')"); err != nil {
				t.Fatal(err)
			}
			var blocker *sql.Tx
			if mode == "policy_deadline" {
				var err error
				blocker, err = p.db.Begin()
				if err != nil {
					t.Fatal(err)
				}
				defer blocker.Rollback()
				if _, err = blocker.Exec(`SELECT payload FROM cp_state_blobs WHERE store_key='legal_hold' FOR UPDATE`); err != nil {
					t.Fatal(err)
				}
			} else {
				protocol := ""
				if mode == "credential_deadline" {
					protocol = `IF current_setting('dsse.credential_write_protocol',true) IS DISTINCT FROM '1' THEN RAISE EXCEPTION 'protocol missing'; END IF;`
				}
				if _, err := p.db.Exec(`CREATE FUNCTION slow_purge() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN ` + protocol + ` PERFORM pg_sleep(0.3); RETURN OLD; END $$; CREATE TRIGGER slow_purge BEFORE DELETE ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION slow_purge()`); err != nil {
					t.Fatal(err)
				}
			}
			statement := "DELETE FROM " + table + " WHERE ctid IN (SELECT ctid FROM " + table + " WHERE tenant_id=$1 LIMIT $2)"
			var pid int
			if err := leader.conn.QueryRowContext(context.Background(), "SELECT pg_backend_pid()").Scan(&pid); err != nil {
				t.Fatal(err)
			}
			term := leader.leaderSince.Load()
			timeout := 80 * time.Millisecond
			if mode == "delete_cancel" {
				timeout = 2 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := executeTenantPurgeBatch(ctx, p.db, table, statement, "target", holds); done <- err }()
			if mode == "delete_cancel" {
				observed := false
				for until := time.Now().Add(time.Second); time.Now().Before(until); {
					var sleeping bool
					if err := p.db.QueryRow(`SELECT coalesce(wait_event,'')='PgSleep' FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&sleeping); err != nil {
						t.Fatal(err)
					}
					if sleeping {
						observed = true
						cancel()
						break
					}
					time.Sleep(5 * time.Millisecond)
				}
				if !observed {
					t.Fatal("DELETE sleep not observed")
				}
			}
			if err := <-done; err == nil {
				t.Fatal("canceled purge reported success")
			}
			if blocker != nil {
				blocker.Rollback()
			}
			var count int
			if err := p.db.QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil || count != 2 {
				t.Fatal("failed purge removed rows")
			}
			leader.tick()
			peer.tick()
			if !leader.IsLeader() || peer.IsLeader() {
				t.Fatal("purge cancellation lost leader")
			}
			var after int
			var setting string
			if err := leader.conn.QueryRowContext(context.Background(), `SELECT pg_backend_pid(),current_setting('statement_timeout')`).Scan(&after, &setting); err != nil || after != pid || leader.leaderSince.Load() != term || setting != "0" {
				t.Fatal("leader session/term/setting changed")
			}
			if blocker == nil {
				if _, err := p.db.Exec("DROP TRIGGER slow_purge ON " + table + "; DROP FUNCTION slow_purge()"); err != nil {
					t.Fatal(err)
				}
			}
			fresh := newLegalHoldStore(p)
			if err := fresh.Set("target", "review", "", true, time.Now()); err != nil {
				t.Fatal(err)
			}
			if _, err := executeTenantPurgeBatch(context.Background(), p.db, table, statement, "target", holds); err == nil {
				t.Fatal("fresh hold bypassed on retry")
			}
			if err := fresh.Set("target", "review", "", false, time.Now()); err != nil {
				t.Fatal(err)
			}
			result, err := executeTenantPurgeBatch(context.Background(), p.db, table, statement, "target", holds)
			if err != nil {
				t.Fatal(err)
			}
			n, err := result.RowsAffected()
			if err != nil || n != 1 {
				t.Fatal("retry count incorrect")
			}
			var tenant string
			if err := p.db.QueryRow("SELECT tenant_id FROM " + table).Scan(&tenant); err != nil || tenant != "peer" {
				t.Fatal("peer row lost")
			}
			t.Logf("same_pid=%d same_term=true failed_rows=2 committed_retry_rows=1 peer_preserved=true", pid)
		})
	}
}
