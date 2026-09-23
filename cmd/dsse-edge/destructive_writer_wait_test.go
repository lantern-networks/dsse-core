package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
)

func TestPrunePolicyCanceledSecondGateReleasesFirstWriter(t *testing.T) {
	h, r := newLegalHoldStore(nil), newRetentionOverrideStore(nil)
	r.writeMu.Lock()
	defer r.writeMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	unlock, err := lockPrunePolicy(ctx, retentionConfig{legalHold: h, override: r})
	if unlock != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("canceled second gate: unlock=%v err=%v", unlock != nil, err)
	}
	// Local Set must acquire the first writer gate after the second gate
	// times out; partial acquisition must not leak the earlier exclusion.
	done := make(chan error, 1)
	go func() { done <- h.Set("target", "review", "", true, time.Now()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("partial acquisition leaked local hold lock")
	}
}

func TestPurgeLogPolicyWaitCancellationPreservesFiles(t *testing.T) {
	h := newLegalHoldStore(nil)
	dir := t.TempDir()
	w, err := logs.NewWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	paths := map[string]string{}
	for _, tenant := range []string{"target", "peer"} {
		path := filepath.Join(dir, "tenants", logs.SafeTenantSegment(tenant), "audit.log.jsonl")
		paths[tenant] = path
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("{}\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	h.writeMu.Lock()
	var once sync.Once
	release := func() { once.Do(h.writeMu.Unlock) }
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := purgeTenantLogDirectoryWithHold(ctx, w, "target", h); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("wait error=%v", err)
		}
	case <-time.After(time.Second):
		release()
		<-done
		t.Fatal("file purge waited for policy writer after deadline")
	}
	release()
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil || string(raw) != "{}\n" {
			t.Fatal("canceled purge changed file", err)
		}
	}
	if _, err := purgeTenantLogDirectoryWithHold(context.Background(), w, "target", h); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(paths["target"]); !os.IsNotExist(err) {
		t.Fatal("retry did not remove target", err)
	}
	if raw, err := os.ReadFile(paths["peer"]); err != nil || string(raw) != "{}\n" {
		t.Fatal("retry changed peer", err)
	}
}

// Exercise the actual destructive entry points, including cancellation while
// the second policy gate or chain gate is held. The first gate must be released
// without waiting for the blocker, and no SQL/object mutation may escape.
func TestPostgresDestructiveWriterWaitCancellation(t *testing.T) {
	for _, path := range []string{"prune_hold", "prune_retention", "archive_hold", "archive_retention", "archive_chain", "purge_hold"} {
		for _, mode := range []string{"deadline", "cancel"} {
			t.Run(path+"/"+mode, func(t *testing.T) {
				d, _, leader, peer := trustDistributionPostgresFixture(t)
				p := d.store.(postgresBlobPersister)
				hp, rp := p, p
				hp.key, rp.key = "legal_hold", "retention_override"
				h, r := newLegalHoldStore(hp), newRetentionOverrideStore(rp)
				now := time.Now()
				if err := h.Set("peer", "review", "", true, now); err != nil {
					t.Fatal(err)
				}
				if err := r.Set("audit", 1); err != nil {
					t.Fatal(err)
				}
				if _, err := p.db.Exec(`CREATE TABLE hot_events(tenant_id text,stream text,event_id text,received_at timestamptz,payload bytea); INSERT INTO hot_events VALUES('target','audit','old',now()-interval '3 days','{}'),('peer','audit','old',now()-interval '3 days','{}')`); err != nil {
					t.Fatal(err)
				}
				beforeHold, err := hp.Load()
				if err != nil {
					t.Fatal(err)
				}
				beforeRetention, err := rp.Load()
				if err != nil {
					t.Fatal(err)
				}
				a := &fakeArchive{objs: map[string][]byte{}}
				chain := newAuditChainStore(nil)
				cfg := retentionConfig{legalHold: h, override: r, hotEvents: 24 * time.Hour, archive: a, auditChain: chain}
				var blocker sync.Locker = &h.writeMu
				if path == "prune_retention" || path == "archive_retention" {
					blocker = &r.writeMu
				}
				if path == "archive_chain" {
					blocker = &chain.operationMu
				}
				blocker.Lock()
				var releaseOnce sync.Once
				release := func() { releaseOnce.Do(blocker.Unlock) }
				defer release()
				var pid int
				if err := leader.conn.QueryRowContext(context.Background(), "SELECT pg_backend_pid()").Scan(&pid); err != nil {
					t.Fatal(err)
				}
				term := leader.leaderSince.Load()
				run := func(ctx context.Context) error {
					switch path {
					case "purge_hold":
						_, err := executeTenantPurgeBatch(ctx, p.db, "hot_events", "DELETE FROM hot_events WHERE ctid IN (SELECT ctid FROM hot_events WHERE tenant_id=$1 LIMIT $2)", "target", h)
						return err
					case "prune_hold", "prune_retention":
						deleteHotStreamOlderThan(ctx, p.db, cfg, "target", "audit", now.Add(-24*time.Hour), now)
					default:
						archiveThenPruneStream(ctx, p.db, cfg, "target", "audit", now.Add(-24*time.Hour), now)
					}
					return nil
				}
				timeout := 50 * time.Millisecond
				if mode == "cancel" {
					timeout = 3 * time.Second
				}
				ctx, cancel := context.WithTimeout(context.Background(), timeout)
				defer cancel()
				started, done := make(chan struct{}), make(chan error, 1)
				go func() { close(started); done <- run(ctx) }()
				<-started
				if mode == "cancel" {
					time.Sleep(20 * time.Millisecond)
					cancel()
				}
				returned := false
				select {
				case err := <-done:
					returned = true
					if path == "purge_hold" && err == nil {
						t.Error("canceled purge reported success")
					}
				case <-time.After(500 * time.Millisecond):
					t.Error("destructive operation waited for blocker after cancellation")
				}
				// Check that earlier acquired gates are available BEFORE releasing
				// the later blocker. This catches partial-acquisition lock leaks.
				if returned && (path == "prune_retention" || path == "archive_retention" || path == "archive_chain") {
					checkCtx, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
					if err := h.writeMu.LockContext(checkCtx); err != nil {
						t.Error("hold gate leaked", err)
					} else {
						h.writeMu.Unlock()
					}
					if path == "archive_chain" {
						if err := r.writeMu.LockContext(checkCtx); err != nil {
							t.Error("retention gate leaked", err)
						} else {
							r.writeMu.Unlock()
						}
					}
					stop()
				}
				release()
				if !returned {
					<-done
				}
				count := func(tenant string, want int) {
					t.Helper()
					var n int
					if err := p.db.QueryRow("SELECT count(*) FROM hot_events WHERE tenant_id=$1", tenant).Scan(&n); err != nil || n != want {
						t.Fatalf("%s rows=%d want=%d: %v", tenant, n, want, err)
					}
				}
				count("target", 1)
				count("peer", 1)
				if len(a.objs) != 0 || len(chain.per) != 0 {
					t.Fatal("canceled wait advanced archive")
				}
				afterHold, err := hp.Load()
				if err != nil {
					t.Fatal(err)
				}
				afterRetention, err := rp.Load()
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(beforeHold, afterHold) || !bytes.Equal(beforeRetention, afterRetention) {
					t.Fatal("canceled wait changed policy")
				}
				leader.tick()
				peer.tick()
				var afterPID int
				if err := leader.conn.QueryRowContext(context.Background(), "SELECT pg_backend_pid()").Scan(&afterPID); err != nil || afterPID != pid || term != leader.leaderSince.Load() || !leader.IsLeader() || peer.IsLeader() {
					t.Fatalf("leader/session changed: %v", err)
				}
				// A newly committed hold must still win over the original Store's
				// stale snapshot. After explicit release, retry must actually work.
				if err := newLegalHoldStore(hp).Set("target", "review", "", true, now); err != nil {
					t.Fatal(err)
				}
				_ = run(context.Background())
				count("target", 1)
				if len(a.objs) != 0 {
					t.Fatal("held retry archived data")
				}
				if err := newLegalHoldStore(hp).Set("target", "review", "", false, now); err != nil {
					t.Fatal(err)
				}
				if err := run(context.Background()); err != nil {
					t.Fatal(err)
				}
				count("target", 0)
				count("peer", 1)
				if path == "archive_hold" || path == "archive_retention" || path == "archive_chain" {
					if len(a.objs) != 1 || chain.per["target"].Seq != 1 {
						t.Fatal("archive retry did not advance exactly once")
					}
				}
				t.Logf("returned_before_unlock=%t policy_unchanged=true same_pid=%d fresh_hold_protected=true retry_target=0 peer=1 archive_objects=%d", returned, pid, len(a.objs))
			})
		}
	}
}
