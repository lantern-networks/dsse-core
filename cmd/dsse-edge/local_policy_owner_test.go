package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
)

// The timed-out caller must leave, but its file writer must retain exclusion
// until Save really returns. A late successful Save is not a confirmed request.
func TestLocalPolicyOwnerDeadlineKeepsExclusionAndPending(t *testing.T) {
	for _, kind := range []string{"hold", "retention"} {
		t.Run(kind, func(t *testing.T) {
			p := &localPolicySaveBlocker{FilePersister: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "policy.json")}, entered: make(chan struct{}), resume: make(chan struct{})}
			h, r := newLegalHoldStore(p), newRetentionOverrideStore(p)
			mu := &h.writeMu
			set := func(ctx context.Context) error { return h.SetContext(ctx, "target", "review", "", true, time.Now()) }
			pending := func() bool { return h.Pending("target") }
			if kind == "retention" {
				mu = &r.writeMu
				set = func(ctx context.Context) error { return r.SetContext(ctx, "audit", 0) }
				pending = func() bool { return len(r.PendingForever()) == 1 }
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- set(ctx) }()
			<-p.entered
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Errorf("owner error=%v", err)
				}
			case <-time.After(300 * time.Millisecond):
				close(p.resume)
				<-done
				t.Fatal("request owner remained blocked in file Save after cancellation")
			}
			if !pending() {
				t.Error("unconfirmed protection not retained")
			}
			wait, stop := context.WithTimeout(context.Background(), 30*time.Millisecond)
			err := mu.LockContext(wait)
			stop()
			if err == nil {
				mu.Unlock()
				t.Error("exclusion released before Save completed")
			}
			if raw, err := p.Load(); err != nil || len(raw) != 0 {
				t.Errorf("unexpected saved state: %q, %v", raw, err)
			}
			close(p.resume)
			wait, stop = context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if err := mu.LockContext(wait); err != nil {
				t.Fatal(err)
			}
			mu.Unlock()
			if !pending() {
				t.Fatal("late Save falsely confirmed timed-out request")
			}
			if kind == "hold" && !newLegalHoldStore(p).IsHeld("target") {
				t.Fatal("late hold not persisted")
			}
			if kind == "retention" {
				if d, ok := newRetentionOverrideStore(p).Get("audit"); !ok || d != 0 {
					t.Fatal("late forever not persisted")
				}
			}
			if err := set(context.Background()); err != nil {
				t.Fatal(err)
			}
			if pending() {
				t.Fatal("explicit retry did not confirm protection")
			}
		})
	}
}

func TestLocalPolicyOwnerDefaultBudget(t *testing.T) {
	p := &localPolicySaveBlocker{FilePersister: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "holds.json")}, entered: make(chan struct{}), resume: make(chan struct{})}
	h := newLegalHoldStore(p)
	done := make(chan error, 1)
	started := time.Now()
	go func() { done <- h.Set("target", "review", "", true, time.Now()) }()
	<-p.entered
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("error=%v", err)
		}
		if time.Since(started) < cpStateBlobDBTimeout {
			t.Error("default budget ended early")
		}
	case <-time.After(cpStateBlobDBTimeout + time.Second):
		close(p.resume)
		<-done
		t.Fatal("default request budget did not release caller")
	}
	close(p.resume)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := h.writeMu.LockContext(ctx); err != nil {
		t.Fatal(err)
	}
	h.writeMu.Unlock()
	if !h.Pending("target") || !newLegalHoldStore(p).IsHeld("target") {
		t.Fatal("late result was not both saved and unconfirmed")
	}
}
