package main

import (
	"context"
	"errors"
	"github.com/lantern-networks/dsse-core/blobstore"
	"strings"
	"testing"
	"time"
)

func TestCPWriterLeaseCaptureHonorsCancellation(t *testing.T) {
	e := &cpLeaderElector{}
	e.isLeader.Store(true)
	e.leaderSince.Store(1)
	old := cpLeaderElectorInstance
	cpLeaderElectorInstance = e
	defer func() { cpLeaderElectorInstance = old }()
	e.mu.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan context.Context, 1)
	go func() { done <- captureCPWriteLease(ctx) }()
	cancel()
	select {
	case got := <-done:
		e.mu.Unlock()
		if lease := got.Value(cpWriteLeaseKey{}).(cpWriteLease); lease.epoch != 0 {
			t.Fatal("cancelled capture authorized a term")
		}
	case <-time.After(300 * time.Millisecond):
		e.mu.Unlock()
		<-done
		t.Fatal("cancelled capture waited for busy writer")
	}
}

func TestCPWriterTransactionWaitHonorsDeadline(t *testing.T) {
	e := &cpLeaderElector{}
	e.isLeader.Store(true)
	e.leaderSince.Store(1)
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), cpWriteLeaseKey{}, cpWriteLease{elector: e, epoch: 1}), 20*time.Millisecond)
	defer cancel()
	e.mu.Lock()
	done := make(chan error, 1)
	go func() { _, finish, err := beginCPWriteTransaction(ctx, nil); finish(); done <- err }()
	select {
	case err := <-done:
		e.mu.Unlock()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("wrong refusal: %v", err)
		}
	case <-time.After(300 * time.Millisecond):
		e.mu.Unlock()
		<-done
		t.Fatal("expired write waited for busy writer")
	}
}

func TestCPWriterCaptureDoesNotRebindExistingTerm(t *testing.T) {
	e := &cpLeaderElector{}
	e.isLeader.Store(true)
	e.leaderSince.Store(2)
	old := cpLeaderElectorInstance
	cpLeaderElectorInstance = e
	defer func() { cpLeaderElectorInstance = old }()
	ctx := context.WithValue(context.Background(), cpWriteLeaseKey{}, cpWriteLease{elector: e, epoch: 1})
	got := captureCPWriteLease(ctx)
	if got.Value(cpWriteLeaseKey{}).(cpWriteLease).epoch != 1 {
		t.Fatal("recaptured request moved into a new term")
	}
	_, finish, err := beginCPWriteTransaction(got, nil)
	finish()
	if err == nil {
		t.Fatal("old term admitted")
	}
}

func TestPostgresCPWriterWaitLeavesActiveSessionHealthy(t *testing.T) {
	d, _, a, b := trustDistributionPostgresFixture(t)
	p := d.store.(postgresBlobPersister)
	p.key = "writer_wait_probe"
	lease := captureCPWriteLease(context.Background())
	tx, finish, err := beginCPWriteTransaction(lease, p.db)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { tx.Rollback(); finish() }()
	if _, err := tx.Exec(`INSERT INTO cp_state_blobs(store_key,payload) VALUES ('writer_wait_probe','{"original":true}')`); err != nil {
		t.Fatal(err)
	}
	var pidBefore int
	if err := tx.QueryRow("SELECT pg_backend_pid()").Scan(&pidBefore); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(lease, 30*time.Millisecond)
	defer cancel()
	changed := false
	done := make(chan error, 1)
	go func() {
		done <- p.UpdateContext(ctx, func([]byte) ([]byte, error) { changed = true; return []byte(`{}`), nil })
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, blobstore.ErrWriteNotCommitted) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		tx.Rollback()
		finish()
		finish = func() {}
		<-done
		t.Fatal("deadline waited for active SQL transaction")
	}
	if changed {
		t.Fatal("timed-out writer ran edit")
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	finish()
	finish = func() {}
	a.tick()
	b.tick()
	if !a.IsLeader() || b.IsLeader() {
		t.Fatal("waiting request discarded leader session")
	}
	var pidAfter int
	if err := a.conn.QueryRowContext(context.Background(), "SELECT pg_backend_pid()").Scan(&pidAfter); err != nil || pidBefore != pidAfter {
		t.Fatal("session changed", err)
	}
	if err := p.UpdateContext(lease, func([]byte) ([]byte, error) { return []byte(`{"recovered":true}`), nil }); err != nil {
		t.Fatal(err)
	}
	raw, err := p.Load()
	if err != nil || !strings.Contains(string(raw), "recovered") {
		t.Fatal("fresh write failed", err)
	}
}

func TestCPWriterWaitHasBoundWithoutCallerDeadline(t *testing.T) {
	e := &cpLeaderElector{}
	e.mu.Lock()
	ctx := context.WithValue(context.Background(), cpWriteLeaseKey{}, cpWriteLease{elector: e, epoch: 1})
	done := make(chan error, 1)
	go func() { _, finish, err := beginCPWriteTransaction(ctx, nil); finish(); done <- err }()
	select {
	case err := <-done:
		e.mu.Unlock()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(cpStateBlobDBTimeout + time.Second):
		e.mu.Unlock()
		<-done
		t.Fatal("writer wait exceeded its budget")
	}
}
func TestCPWriterCapturesBusyTermWithoutWaiting(t *testing.T) {
	e := &cpLeaderElector{}
	e.isLeader.Store(true)
	e.leaderSince.Store(1)
	old := cpLeaderElectorInstance
	cpLeaderElectorInstance = e
	defer func() { cpLeaderElectorInstance = old }()
	e.mu.Lock()
	done := make(chan context.Context, 1)
	go func() { done <- captureCPWriteLease(context.Background()) }()
	select {
	case ctx := <-done:
		e.leaderSince.Store(2)
		e.mu.Unlock()
		if ctx.Value(cpWriteLeaseKey{}).(cpWriteLease).epoch != 1 {
			t.Fatal("busy term not captured")
		}
		_, finish, err := beginCPWriteTransaction(ctx, nil)
		finish()
		if err == nil {
			t.Fatal("request rebound to next term")
		}
	case <-time.After(300 * time.Millisecond):
		e.mu.Unlock()
		<-done
		t.Fatal("lease capture queued behind writer")
	}
}
