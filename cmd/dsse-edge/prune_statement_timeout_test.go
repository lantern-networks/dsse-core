package main

import (
	"context"
	"testing"
	"time"
)

func TestPostgresPruneStatementCancellationKeepsLeader(t *testing.T) {
	for _, table := range []string{"hot_events", "admin_audit_outbox", "domain_event_outbox"} {
		for _, mode := range []string{"deadline", "cancel"} {
			t.Run(table+"/"+mode, func(t *testing.T) {
				d, _, leader, peer := trustDistributionPostgresFixture(t)
				p := d.store.(postgresBlobPersister)
				hp := p
				hp.key = "legal_hold"
				rp := p
				rp.key = "retention_override"
				holds := newLegalHoldStore(hp)
				retention := newRetentionOverrideStore(rp)
				now := time.Now()
				tenant := "prune_tenant"
				if err := holds.Set(tenant, "admin", "", false, now); err != nil {
					t.Fatal(err)
				}
				if err := retention.Set("access", 1); err != nil {
					t.Fatal(err)
				}
				if _, err := p.db.Exec("CREATE TABLE " + table + "(tenant_id text,stream text,status text,received_at timestamptz,updated_at timestamptz)"); err != nil {
					t.Fatal(err)
				}
				for _, state := range []string{"published", "pending"} {
					if _, err := p.db.Exec("INSERT INTO "+table+" VALUES($1,'access',$2,$3,$3)", tenant, state, now.Add(-72*time.Hour)); err != nil {
						t.Fatal(err)
					}
				}
				where := "status='published' AND updated_at < $2"
				stream := ""
				if table == "hot_events" {
					where = "received_at < $2 AND stream=$3"
					stream = "access"
				}
				cfg := retentionConfig{legalHold: holds, hotEvents: 24 * time.Hour}
				if stream != "" {
					cfg.override = retention
				}
				var pid int
				if err := leader.conn.QueryRowContext(context.Background(), "SELECT pg_backend_pid()").Scan(&pid); err != nil {
					t.Fatal(err)
				}
				term := leader.leaderSince.Load()
				if _, err := p.db.Exec("CREATE FUNCTION slow_prune() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.3); RETURN OLD; END $$; CREATE TRIGGER slow_prune BEFORE DELETE ON " + table + " FOR EACH ROW EXECUTE FUNCTION slow_prune()"); err != nil {
					t.Fatal(err)
				}
				timeout := 80 * time.Millisecond
				if mode == "cancel" {
					timeout = 2 * time.Second
				}
				ctx, cancel := context.WithTimeout(retentionWriteContext(context.Background()), timeout)
				defer cancel()
				done := make(chan struct{})
				go func() {
					defer close(done)
					deleteRetentionRows(ctx, p.db, cfg, table, where, tenant, stream, now.Add(-24*time.Hour), now)
				}()
				if mode == "cancel" {
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
						t.Fatal("DELETE delay not observed")
					}
				}
				<-done
				count := func(want int) {
					t.Helper()
					var n int
					if err := p.db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil || n != want {
						t.Fatalf("row count %d want %d: %v", n, want, err)
					}
				}
				count(2)
				leader.tick()
				peer.tick()
				if !leader.IsLeader() || peer.IsLeader() {
					t.Fatal("canceled pruning SQL lost leadership")
				}
				var after int
				var setting string
				if err := leader.conn.QueryRowContext(context.Background(), "SELECT pg_backend_pid(), current_setting('statement_timeout')").Scan(&after, &setting); err != nil || after != pid || leader.leaderSince.Load() != term || setting != "0" {
					t.Fatalf("session/term/setting changed: %v", err)
				}
				if _, err := p.db.Exec("DROP TRIGGER slow_prune ON " + table + "; DROP FUNCTION slow_prune()"); err != nil {
					t.Fatal(err)
				}
				// A fresh writer's committed hold must protect the retry even when this
				// sweeper retains its older Store instance.
				if err := newLegalHoldStore(hp).Set(tenant, "admin", "", true, now); err != nil {
					t.Fatal(err)
				}
				run := func() {
					deleteRetentionRows(context.Background(), p.db, cfg, table, where, tenant, stream, now.Add(-24*time.Hour), now)
				}
				run()
				count(2)
				if err := newLegalHoldStore(hp).Set(tenant, "admin", "", false, now); err != nil {
					t.Fatal(err)
				}
				run()
				want := 1
				if table == "hot_events" {
					want = 0
				}
				count(want)
				t.Logf("same_pid=%d same_term=true canceled_rows_preserved=2 hold_protected_retry=true rows_after_release=%d", pid, want)
			})
		}
	}
}

func TestPostgresPrunePolicyLockTimeoutKeepsLeader(t *testing.T) {
	d, _, leader, peer := trustDistributionPostgresFixture(t)
	p := d.store.(postgresBlobPersister)
	p.key = "legal_hold"
	h := newLegalHoldStore(p)
	now := time.Now()
	if err := h.Set("protected", "admin", "", false, now); err != nil {
		t.Fatal(err)
	}
	if _, err := p.db.Exec(`CREATE TABLE hot_events(tenant_id text,stream text,received_at timestamptz); INSERT INTO hot_events VALUES('protected','access',now()-interval '3 days')`); err != nil {
		t.Fatal(err)
	}
	var pid int
	if err := leader.conn.QueryRowContext(context.Background(), "SELECT pg_backend_pid()").Scan(&pid); err != nil {
		t.Fatal(err)
	}
	term := leader.leaderSince.Load()
	blocker, err := p.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback()
	if _, err := blocker.Exec(`SELECT payload FROM cp_state_blobs WHERE store_key='legal_hold' FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(retentionWriteContext(context.Background()), 80*time.Millisecond)
	defer cancel()
	deleteHotStreamOlderThan(ctx, p.db, retentionConfig{legalHold: h}, "protected", "access", now.Add(-time.Hour), now)
	blocker.Rollback()
	leader.tick()
	peer.tick()
	if !leader.IsLeader() || peer.IsLeader() {
		t.Fatal("policy row wait lost leadership")
	}
	var after, n int
	if err := leader.conn.QueryRowContext(context.Background(), "SELECT pg_backend_pid()").Scan(&after); err != nil || after != pid || term != leader.leaderSince.Load() {
		t.Fatalf("session/term changed: %v", err)
	}
	if err := p.db.QueryRow(`SELECT count(*) FROM hot_events`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("policy read timeout erased hot row: %v", err)
	}
	t.Logf("policy_lock_timeout=true same_pid=%d row_preserved=true", pid)
}
