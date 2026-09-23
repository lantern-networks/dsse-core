package main

import (
	"context"
	"errors"
	"github.com/lantern-networks/dsse-core/blobstore"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestFilePurgeOwnerKeepsExclusionThroughCanceledIO(t *testing.T) {
	for _, phase := range []string{"count", "close", "remove", "verify"} {
		t.Run(phase, func(t *testing.T) {
			p := blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "hold.json")}
			h := newLegalHoldStore(p)
			owned, _, err := h.beginErasure(context.Background(), "target", "test")
			if err != nil {
				t.Fatal(err)
			}
			entered, resume := make(chan struct{}), make(chan struct{})
			var once sync.Once
			release := func() { once.Do(func() { close(resume) }) }
			defer release()
			blocked := func(at string) {
				if at == phase {
					close(entered)
					<-resume
				}
			}
			countCalls, removeCalls := 0, 0
			ctx, cancel := context.WithCancel(owned)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := runTenantFilePurge(ctx, h, "target", func(ctx context.Context) (int64, error) {
					return eraseTenantLogFiles(ctx, func() (int64, error) {
						countCalls++
						if countCalls == 1 {
							blocked("count")
							return 1, nil
						}
						blocked("verify")
						return 0, nil
					}, func() error { blocked("close"); return nil }, func() error { removeCalls++; blocked("remove"); return nil })
				})
				done <- err
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("not entered")
			}
			cancel()
			select {
			case err = <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("error=%v", err)
				}
			case <-time.After(300 * time.Millisecond):
				t.Fatal("caller stuck")
			}
			wait, stop := context.WithTimeout(context.Background(), 30*time.Millisecond)
			err = h.writeMu.LockContext(wait)
			stop()
			if err == nil {
				h.writeMu.Unlock()
				t.Fatal("live worker lost exclusion")
			}
			fresh := newLegalHoldStore(p)
			if !fresh.IsHeld("target") {
				t.Fatal("durable marker lost")
			}
			release()
			wait, stop = context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if err = h.writeMu.LockContext(wait); err != nil {
				t.Fatal(err)
			}
			h.writeMu.Unlock()
			if (phase == "count" || phase == "close") && removeCalls != 0 {
				t.Fatal("cancellation allowed later deletion")
			}
			if _, _, err = h.beginErasure(context.Background(), "target", "retry"); !errors.Is(err, errTenantErasureInProgress) {
				t.Fatal("retry bypassed reconciliation", err)
			}
		})
	}
}

func TestFilePurgeCloseFailurePreservesFiles(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "log.jsonl")
	if err := os.WriteFile(file, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("close refused")
	_, err := eraseTenantLogFiles(context.Background(), func() (int64, error) { return 1, nil }, func() error { return failure }, func() error { return os.RemoveAll(root) })
	if !errors.Is(err, failure) {
		t.Fatalf("close failure hidden: %v", err)
	}
	if raw, e := os.ReadFile(file); e != nil || string(raw) != "preserve" {
		t.Fatal("removed after failed close", e)
	}
}

func TestPurgeFootprintUsesOwnerResult(t *testing.T) {
	for _, count := range []int64{0, -1} {
		row := adminTenantFootprintRow{Store: "log_files", Count: count}
		if count < 0 {
			row.Error = "unconfirmed"
		}
		result := countAdminTenantFootprint(context.Background(), "node", "target", nil, nil, nil, nil, nil, nil, nil, adminTenantExtraStores{}, time.Now(), row)
		found := false
		for _, r := range result.Stores {
			if r.Store == "log_files" {
				found = true
				if r != row {
					t.Fatal(r)
				}
			}
		}
		if !found || result.Clean() != (count == 0) {
			t.Fatal("unknown incorrectly reported clean", result)
		}
	}
}

// Losing the SQL guard cannot let the next leader treat still-running file I/O
// as finished. The durable marker, not the connection lifetime, carries that fact.
func TestPostgresFilePurgeOwnerSurvivesLeaderLoss(t *testing.T) {
	d, _, leader, peer := trustDistributionPostgresFixture(t)
	p := d.store.(postgresBlobPersister)
	p.key = "legal_hold"
	h := newLegalHoldStore(p)
	owned, _, err := h.beginErasure(retentionWriteContext(context.Background()), "target", "old")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "target.log")
	if err = os.WriteFile(path, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	entered, resume := make(chan struct{}), make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(resume) }) }
	defer release()
	var pid int
	if err = leader.conn.QueryRowContext(context.Background(), "SELECT pg_backend_pid()").Scan(&pid); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(owned)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := runTenantFilePurge(ctx, h, "target", func(context.Context) (int64, error) { close(entered); <-resume; return 1, os.Remove(path) })
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("not entered")
	}
	cancel()
	select {
	case err = <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("caller stuck")
	}
	if _, err = p.db.Exec("SELECT pg_terminate_backend($1)", pid); err != nil {
		t.Fatal(err)
	}
	peer.tick()
	if !peer.IsLeader() {
		t.Fatal("no successor")
	}
	cpLeaderElectorInstance = peer
	next := newLegalHoldStore(p)
	if _, _, err = next.beginErasure(context.Background(), "target", "new"); !errors.Is(err, errTenantErasureInProgress) {
		t.Fatal("successor bypassed marker", err)
	}
	if err = next.Set("target", "review", "", true, time.Now()); !errors.Is(err, errTenantErasureInProgress) {
		t.Fatal("hold passed running erasure", err)
	}
	release()
	wait, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err = h.writeMu.LockContext(wait); err != nil {
		t.Fatal(err)
	}
	h.writeMu.Unlock()
	leader.release()
	if _, err = os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("late filesystem result not observed", err)
	}
	if !newLegalHoldStore(p).IsHeld("target") {
		t.Fatal("late file result cleared reconciliation marker")
	}
}
