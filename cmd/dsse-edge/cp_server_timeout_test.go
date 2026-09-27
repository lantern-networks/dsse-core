package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lib/pq"
)

// Unlike client cancellation, PostgreSQL's statement timeout must leave the
// advisory-lock session usable after rollback. Keep a longer client bound as
// a transport backstop rather than allowing an unresponsive server to hang.
func TestPostgresCPServerStatementTimeoutKeepsLeadership(t *testing.T) {
	d, _, leader, peer := trustDistributionPostgresFixture(t)
	p := d.store.(postgresBlobPersister)
	var before int
	if err := leader.conn.QueryRowContext(context.Background(), "SELECT pg_backend_pid()").Scan(&before); err != nil {
		t.Fatal(err)
	}
	term := leader.leaderSince.Load()
	ctx, cancel := context.WithTimeout(captureCPWriteLease(context.Background()), 2*time.Second)
	defer cancel()
	tx, finish, err := beginCPWriteTransaction(ctx, p.db)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { tx.Rollback(); finish() }()
	if _, err := tx.ExecContext(ctx, `SET LOCAL statement_timeout = 50`); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = tx.ExecContext(ctx, `SELECT pg_sleep(1)`)
	var pgerr *pq.Error
	if !errors.As(err, &pgerr) || pgerr.Code != "57014" || ctx.Err() != nil {
		t.Fatalf("expected server-only timeout, got %v / %v", err, ctx.Err())
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("statement was not bounded: %v", elapsed)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	finish()
	finish = func() {}
	leader.tick()
	peer.tick()
	var after int
	var setting string
	if err := leader.conn.QueryRowContext(context.Background(), "SELECT pg_backend_pid(), current_setting('statement_timeout')").Scan(&after, &setting); err != nil {
		t.Fatal(err)
	}
	if !leader.IsLeader() || peer.IsLeader() || before != after || term != leader.leaderSince.Load() || setting != "0" {
		t.Fatalf("timeout lost leader or leaked setting: before=%d after=%d setting=%s", before, after, setting)
	}
	t.Logf("server SQLSTATE=%s elapsed=%s same_pid=%d same_term=true peer_leader=false setting_after_rollback=%s", pgerr.Code, time.Since(started), after, setting)
}

func TestPostgresBlobStatementTimeoutKeepsLeaderSession(t *testing.T) {
	d, _, leader, peer := trustDistributionPostgresFixture(t)
	p := d.store.(postgresBlobPersister)
	p.key = "slow_blob"
	if err := p.Save([]byte(`{"original":true}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := p.db.Exec(`CREATE FUNCTION delay_blob() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.3); RETURN NEW; END $$; CREATE TRIGGER delay_blob BEFORE UPDATE ON cp_state_blobs FOR EACH ROW EXECUTE FUNCTION delay_blob()`); err != nil {
		t.Fatal(err)
	}
	var before int
	if err := leader.conn.QueryRowContext(context.Background(), "SELECT pg_backend_pid()").Scan(&before); err != nil {
		t.Fatal(err)
	}
	term := leader.leaderSince.Load()
	ctx, cancel := context.WithTimeout(captureCPWriteLease(context.Background()), 80*time.Millisecond)
	defer cancel()
	err := p.UpdateContext(ctx, func([]byte) ([]byte, error) { return []byte(`{"changed":true}`), nil })
	if err == nil || !errors.Is(err, blobstore.ErrWriteNotCommitted) {
		t.Fatalf("timeout not a definite rollback: %v", err)
	}
	var pgerr *pq.Error
	if !errors.As(err, &pgerr) || pgerr.Code != "57014" {
		t.Fatalf("expected PostgreSQL statement cancellation, got %v", err)
	}
	leader.tick()
	peer.tick()
	if !leader.IsLeader() || peer.IsLeader() {
		t.Fatal("a slow blob statement lost leadership")
	}
	var after int
	if err := leader.conn.QueryRowContext(context.Background(), "SELECT pg_backend_pid()").Scan(&after); err != nil || before != after || term != leader.leaderSince.Load() {
		t.Fatalf("leader session changed: %d -> %d: %v", before, after, err)
	}
	raw, err := p.Load()
	if err != nil || string(raw) != `{"original":true}` {
		t.Fatalf("failed update persisted: %s %v", raw, err)
	}
	if _, err := p.db.Exec(`DROP TRIGGER delay_blob ON cp_state_blobs; DROP FUNCTION delay_blob()`); err != nil {
		t.Fatal(err)
	}
	if err := p.UpdateContext(captureCPWriteLease(context.Background()), func([]byte) ([]byte, error) { return []byte(`{"retry":true}`), nil }); err != nil {
		t.Fatal(err)
	}
	t.Logf("same_pid=%d same_term=true definite_rollback=true retry_succeeded=true", after)
}

func TestPostgresBlobRequestCancellationKeepsLeaderSession(t *testing.T) {
	d, _, leader, peer := trustDistributionPostgresFixture(t)
	p := d.store.(postgresBlobPersister)
	p.key = "cancel_blob"
	if err := p.Save([]byte(`{"original":true}`)); err != nil {
		t.Fatal(err)
	}
	var pid int
	if err := leader.conn.QueryRowContext(context.Background(), "SELECT pg_backend_pid()").Scan(&pid); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"edit_cancel", "edit_deadline", "sql_cancel"} {
		t.Run(mode, func(t *testing.T) {
			if _, err := p.db.Exec(`CREATE FUNCTION delay_cancel_blob() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.3); RETURN NEW; END $$; CREATE TRIGGER delay_cancel_blob BEFORE UPDATE ON cp_state_blobs FOR EACH ROW EXECUTE FUNCTION delay_cancel_blob()`); err != nil {
				t.Fatal(err)
			}
			defer p.db.Exec(`DROP TRIGGER delay_cancel_blob ON cp_state_blobs; DROP FUNCTION delay_cancel_blob()`)
			timeout := 2 * time.Second
			if mode == "edit_deadline" {
				timeout = 50 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(captureCPWriteLease(context.Background()), timeout)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- p.UpdateContext(ctx, func([]byte) ([]byte, error) {
					switch mode {
					case "edit_cancel":
						cancel()
					case "edit_deadline":
						<-ctx.Done()
					}
					return []byte(`{"changed":true}`), nil
				})
			}()
			if mode == "sql_cancel" {
				observed := false
				for stop := time.Now().Add(time.Second); time.Now().Before(stop); {
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
					cancel()
					<-done
					t.Fatal("did not observe active SQL before cancellation")
				}
			}
			err := <-done
			want := error(context.Canceled)
			if mode == "edit_deadline" {
				want = context.DeadlineExceeded
			}
			if !errors.Is(err, want) || !errors.Is(err, blobstore.ErrWriteNotCommitted) {
				t.Fatalf("cancel not a definite rollback: %v", err)
			}
			leader.tick()
			peer.tick()
			if !leader.IsLeader() || peer.IsLeader() {
				t.Fatal("request cancellation lost leader")
			}
			var after int
			if err := leader.conn.QueryRowContext(context.Background(), "SELECT pg_backend_pid()").Scan(&after); err != nil || after != pid {
				t.Fatalf("session changed: %d %v", after, err)
			}
			if raw, err := p.Load(); err != nil || string(raw) != `{"original":true}` {
				t.Fatalf("cancelled change saved: %s %v", raw, err)
			}
		})
	}
}

// A request that ends while COMMIT is in flight can no longer roll the change
// back. Forwarding that cancellation made lib/pq close the advisory-lock session,
// so a disconnecting client (including a device on the data path) handed
// leadership to a peer. COMMIT is bounded by the SQL budget instead.
func TestPostgresBlobCommitCancellationKeepsLeaderSession(t *testing.T) {
	cases := []struct {
		name  string
		sleep string
		limit time.Duration
		// cancelAt < 0 means: let the request deadline expire instead.
		cancelAt time.Duration
	}{
		{name: "client_cancel_during_commit", sleep: "0.5", limit: 5 * time.Second, cancelAt: 150 * time.Millisecond},
		{name: "request_deadline_during_commit", sleep: "0.4", limit: 80 * time.Millisecond, cancelAt: -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, _, leader, peer := trustDistributionPostgresFixture(t)
			p := d.store.(postgresBlobPersister)
			p.key = "commit_cancel_" + tc.name
			if err := p.Save([]byte(`{"original":true}`)); err != nil {
				t.Fatal(err)
			}
			if _, err := p.db.Exec(`CREATE OR REPLACE FUNCTION delay_blob_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(` + tc.sleep + `); RETURN NEW; END $$;
				DROP TRIGGER IF EXISTS delay_blob_commit ON cp_state_blobs;
				CREATE CONSTRAINT TRIGGER delay_blob_commit AFTER UPDATE ON cp_state_blobs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION delay_blob_commit()`); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { p.db.Exec(`DROP TRIGGER IF EXISTS delay_blob_commit ON cp_state_blobs`) })
			var before int
			if err := leader.conn.QueryRowContext(context.Background(), "SELECT pg_backend_pid()").Scan(&before); err != nil {
				t.Fatal(err)
			}
			term := leader.leaderSince.Load()
			ctx, cancel := context.WithTimeout(captureCPWriteLease(context.Background()), tc.limit)
			defer cancel()
			if tc.cancelAt > 0 {
				time.AfterFunc(tc.cancelAt, cancel)
			}
			err := p.UpdateContext(ctx, func([]byte) ([]byte, error) { return []byte(`{"changed":true}`), nil })
			if ctx.Err() == nil {
				t.Fatal("request context did not end during COMMIT; the case did not exercise the boundary")
			}
			if err != nil {
				t.Fatalf("COMMIT that finished within the SQL budget reported failure: %v", err)
			}
			leader.tick()
			peer.tick()
			var after int
			if err := leader.conn.QueryRowContext(context.Background(), "SELECT pg_backend_pid()").Scan(&after); err != nil {
				t.Fatal(err)
			}
			if !leader.IsLeader() || peer.IsLeader() || before != after || term != leader.leaderSince.Load() {
				t.Fatalf("request end during COMMIT cost leadership: before=%d after=%d", before, after)
			}
			if raw, err := p.Load(); err != nil || string(raw) != `{"changed":true}` {
				t.Fatalf("committed change not durable: %s %v", raw, err)
			}
		})
	}
}

// COMMIT is still bounded: past the budget plus grace, the transport backstop
// fires. The outcome stays unknown (never reclassified as not-committed).
func TestPostgresBlobHungCommitIsBoundedByBudget(t *testing.T) {
	d, _, _, _ := trustDistributionPostgresFixture(t)
	p := d.store.(postgresBlobPersister)
	p.key = "commit_hung"
	if err := p.Save([]byte(`{"original":true}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := p.db.Exec(`CREATE OR REPLACE FUNCTION delay_blob_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(3); RETURN NEW; END $$;
		DROP TRIGGER IF EXISTS delay_blob_commit ON cp_state_blobs;
		CREATE CONSTRAINT TRIGGER delay_blob_commit AFTER UPDATE ON cp_state_blobs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION delay_blob_commit()`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.db.Exec(`DROP TRIGGER IF EXISTS delay_blob_commit ON cp_state_blobs`) })
	ctx, cancel := context.WithTimeout(captureCPWriteLease(context.Background()), 80*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := p.UpdateContext(ctx, func([]byte) ([]byte, error) { return []byte(`{"changed":true}`), nil })
	elapsed := time.Since(started)
	if err == nil || errors.Is(err, blobstore.ErrWriteNotCommitted) {
		t.Fatalf("hung COMMIT outcome was not reported as unknown: %v", err)
	}
	if elapsed > 80*time.Millisecond+cpStatementCancelGrace+time.Second {
		t.Fatalf("COMMIT was not bounded by budget+grace: %v", elapsed)
	}
}

func TestCPStatementBudgetPreservesRequestAndBoundsFallback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	plain := newCPStatementBudget(ctx)
	defer plain.cancel()
	if plain.sqlCtx != ctx || plain.server {
		t.Fatal("pool-only context changed")
	}
	leased := context.WithValue(ctx, cpWriteLeaseKey{}, cpWriteLease{epoch: 1})
	b := newCPStatementBudget(leased)
	defer b.cancel()
	d, _ := ctx.Deadline()
	sqlDeadline, ok := b.sqlCtx.Deadline()
	if !ok || !sqlDeadline.Equal(d.Add(cpStatementCancelGrace)) || b.sqlCtx.Value(cpWriteLeaseKey{}).(cpWriteLease).epoch != 1 {
		t.Fatal("fallback deadline or lease lost")
	}
	cancel()
	if b.sqlCtx.Err() != nil || !errors.Is(b.prepare(nil), context.Canceled) {
		t.Fatal("cancellation reached driver or was ignored by admission")
	}
}

func TestPostgresBlobPreservesStricterServerTimeout(t *testing.T) {
	d, _, leader, _ := trustDistributionPostgresFixture(t)
	p := d.store.(postgresBlobPersister)
	p.key = "strict_timeout"
	if err := p.Save([]byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := leader.conn.ExecContext(context.Background(), `SET statement_timeout = '30ms'`); err != nil {
		t.Fatal(err)
	}
	if _, err := p.db.Exec(`CREATE FUNCTION delay_strict_blob() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.1); RETURN NEW; END $$; CREATE TRIGGER delay_strict_blob BEFORE UPDATE ON cp_state_blobs FOR EACH ROW EXECUTE FUNCTION delay_strict_blob()`); err != nil {
		t.Fatal(err)
	}
	err := p.UpdateContext(captureCPWriteLease(context.Background()), func([]byte) ([]byte, error) { return []byte(`{"changed":true}`), nil })
	var pgerr *pq.Error
	if !errors.As(err, &pgerr) || pgerr.Code != "57014" || !errors.Is(err, blobstore.ErrWriteNotCommitted) {
		t.Fatalf("stricter server timeout ignored: %v", err)
	}
	var setting string
	if err := leader.conn.QueryRowContext(context.Background(), `SHOW statement_timeout`).Scan(&setting); err != nil || setting != "30ms" {
		t.Fatalf("session setting changed: %s %v", setting, err)
	}
	if raw, err := p.Load(); err != nil || string(raw) != "{}" {
		t.Fatalf("timed-out data changed: %s %v", raw, err)
	}
}

// A fast shared write must not pay one extra round trip per statement on the
// leader's advisory-lock session. A statement that starts well after the last
// setting must still be bounded by the remaining total budget.
func TestPostgresCPStatementBudgetSetsTimeoutOnlyWhenStale(t *testing.T) {
	d, _, _, _ := trustDistributionPostgresFixture(t)
	p := d.store.(postgresBlobPersister)
	ctx, cancel := context.WithTimeout(captureCPWriteLease(context.Background()), 3*time.Second)
	defer cancel()
	tx, finish, err := beginCPWriteTransaction(ctx, p.db)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { tx.Rollback(); finish() }()
	b := newCPStatementBudget(ctx)
	defer b.cancel()
	for i := 0; i < 3; i++ {
		if _, err := b.exec(tx, `SELECT 1`); err != nil {
			t.Fatal(err)
		}
	}
	if b.timeoutSets != 1 {
		t.Fatalf("fast statements set the timeout %d times, want 1", b.timeoutSets)
	}
	if _, err := b.exec(tx, `SELECT pg_sleep(0.6)`); err != nil {
		t.Fatal(err)
	}
	var setting string
	if err := b.queryRow(tx, `SELECT current_setting('statement_timeout')`).Scan(&setting); err != nil {
		t.Fatal(err)
	}
	if b.timeoutSets != 2 {
		t.Fatalf("stale setting was not renewed: sets=%d", b.timeoutSets)
	}
	got, err := time.ParseDuration(setting)
	if err != nil {
		t.Fatalf("unexpected setting %q: %v", setting, err)
	}
	if remaining := time.Until(b.deadline); got > remaining+cpStatementTimeoutReuse || got > 2500*time.Millisecond {
		t.Fatalf("renewed timeout %v exceeds the remaining budget %v", got, remaining)
	}
	t.Logf("sets=%d renewed_timeout=%s", b.timeoutSets, setting)
}
