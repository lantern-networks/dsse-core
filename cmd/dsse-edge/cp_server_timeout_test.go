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

func TestPostgresBlobCommitCancellationRemainsConservative(t *testing.T) {
	d, _, leader, peer := trustDistributionPostgresFixture(t)
	p := d.store.(postgresBlobPersister)
	p.key = "commit_timeout"
	if err := p.Save([]byte(`{"original":true}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := p.db.Exec(`CREATE FUNCTION delay_blob_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.3); RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER delay_blob_commit AFTER UPDATE ON cp_state_blobs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION delay_blob_commit()`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(captureCPWriteLease(context.Background()), 80*time.Millisecond)
	defer cancel()
	err := p.UpdateContext(ctx, func([]byte) ([]byte, error) { return []byte(`{"changed":true}`), nil })
	var pgerr *pq.Error
	if !errors.As(err, &pgerr) || pgerr.Code != "57014" || errors.Is(err, blobstore.ErrWriteNotCommitted) {
		t.Fatalf("COMMIT outcome was reclassified: %v", err)
	}
	// COMMIT must retain client cancellation: statement_timeout alone does
	// not bound deferred finalization. Losing the session here is a known
	// remaining availability issue, not permission to commit after timeout.
	leader.tick()
	peer.tick()
	if leader.IsLeader() || !peer.IsLeader() {
		t.Fatal("commit cancellation did not exercise the existing session-loss boundary")
	}
	if raw, err := p.Load(); err != nil || string(raw) != `{"original":true}` {
		t.Fatalf("timed-out commit saved: %s %v", raw, err)
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
