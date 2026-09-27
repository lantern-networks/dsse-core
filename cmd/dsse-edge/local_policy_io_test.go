package main

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
)

type localPolicySaveBlocker struct {
	blobstore.FilePersister
	entered, resume chan struct{}
	once            sync.Once
}

func (p *localPolicySaveBlocker) Save(raw []byte) error {
	p.once.Do(func() { close(p.entered); <-p.resume })
	return p.FilePersister.Save(raw)
}

// A slow local save must not hide the confirmed state or prevent a queued
// preservation request from returning on its own deadline. The older save must
// not erase the newer process-local intent when it eventually completes.
func TestLocalPolicySaveAllowsStatusAndCanceledPreservation(t *testing.T) {
	for _, kind := range []string{"hold", "retention", "erasure"} {
		t.Run(kind, func(t *testing.T) {
			p := &localPolicySaveBlocker{FilePersister: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "policy.json")}, entered: make(chan struct{}), resume: make(chan struct{})}
			h, r := newLegalHoldStore(p), newRetentionOverrideStore(p)
			first := make(chan error, 1)
			go func() {
				if kind == "retention" {
					first <- r.Set("audit", 1)
					return
				}
				if kind == "erasure" {
					_, _, err := h.beginErasure(context.Background(), "other", "node")
					first <- err
					return
				}
				first <- h.Set("target", "review", "", false, time.Now())
			}()
			<-p.entered
			var once sync.Once
			release := func() { once.Do(func() { close(p.resume) }) }
			defer release()
			status := make(chan error, 1)
			go func() {
				if kind == "retention" {
					status <- r.Health()
				} else {
					status <- h.Health()
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			next := make(chan error, 1)
			go func() {
				if kind == "retention" {
					next <- r.SetContext(ctx, "audit", 0)
				} else {
					next <- h.SetContext(ctx, "target", "review", "", true, time.Now())
				}
			}()
			for label, ch := range map[string]<-chan error{"status": status, "queued": next} {
				select {
				case err := <-ch:
					if label == "queued" && !errors.Is(err, context.DeadlineExceeded) {
						t.Errorf("queued error=%v", err)
					}
					if label == "status" && err != nil {
						t.Error(err)
					}
				case <-time.After(300 * time.Millisecond):
					t.Errorf("%s blocked behind local file I/O", label)
					release()
					<-ch
				}
			}
			release()
			if err := <-first; err != nil {
				t.Fatal(err)
			}
			if kind == "retention" {
				if d, _ := r.Get("audit"); d != 0 || len(r.PendingForever()) != 1 {
					t.Fatal("older save cleared newer forever intent")
				}
				if d, _ := newRetentionOverrideStore(p).Get("audit"); d != 1 {
					t.Fatal("unconfirmed intent falsely durable")
				}
				if err := r.Set("audit", 0); err != nil {
					t.Fatal(err)
				}
				if d, _ := newRetentionOverrideStore(p).Get("audit"); d != 0 || len(r.PendingForever()) != 0 {
					t.Fatal("retry failed")
				}
			} else {
				if !h.Pending("target") || !h.IsHeld("target") {
					t.Fatal("older save cleared newer hold intent")
				}
				if newLegalHoldStore(p).IsHeld("target") {
					t.Fatal("unconfirmed intent falsely durable")
				}
				if err := h.Set("target", "review", "", true, time.Now()); err != nil {
					t.Fatal(err)
				}
				if !newLegalHoldStore(p).IsHeld("target") || h.Pending("target") {
					t.Fatal("retry failed")
				}
			}
		})
	}
}

func TestLocalPrunePolicyDoesNotBlockCanceledPreservation(t *testing.T) {
	for _, kind := range []string{"hold", "retention"} {
		t.Run(kind, func(t *testing.T) {
			h, r := newLegalHoldStore(nil), newRetentionOverrideStore(nil)
			unlock, err := lockPrunePolicy(context.Background(), retentionConfig{legalHold: h, override: r})
			if err != nil {
				t.Fatal(err)
			}
			var once sync.Once
			release := func() { once.Do(unlock) }
			defer release()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				if kind == "hold" {
					done <- h.SetContext(ctx, "target", "review", "", true, time.Now())
				} else {
					done <- r.SetContext(ctx, "audit", 0)
				}
			}()
			select {
			case err := <-done:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Errorf("wait error=%v", err)
				}
			case <-time.After(300 * time.Millisecond):
				t.Error("preservation cannot return while destructive operation owns policy")
				release()
				<-done
			}
			release()
			if kind == "hold" && !h.Pending("target") {
				t.Fatal("missing pending hold")
			}
			if kind == "retention" && len(r.PendingForever()) != 1 {
				t.Fatal("missing pending forever")
			}
		})
	}
}
