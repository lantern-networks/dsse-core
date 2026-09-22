package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type blockedPolicyWriter struct {
	transactionalCAFixture
	entered chan struct{}
	resume  chan struct{}
	once    sync.Once
}

func (p *blockedPolicyWriter) UpdateContext(ctx context.Context, edit func([]byte) ([]byte, error)) error {
	p.once.Do(func() { close(p.entered); <-p.resume })
	return p.transactionalCAFixture.UpdateContext(ctx, edit)
}

// A queued preservation request must return on cancellation, without allowing
// the older relaxing writer's eventual success to clear its pending protection.
func TestPolicyWriterWaitCancellationPreservesNewerIntent(t *testing.T) {
	for _, kind := range []string{"hold", "retention"} {
		t.Run(kind, func(t *testing.T) {
			p := &blockedPolicyWriter{entered: make(chan struct{}), resume: make(chan struct{})}
			h, r := newLegalHoldStore(p), newRetentionOverrideStore(p)
			update := func(ctx context.Context, protect bool) error {
				if kind == "hold" {
					return h.SetContext(ctx, "target", "review", "", protect, time.Now())
				}
				days := 1
				if protect {
					days = 0
				}
				return r.SetContext(ctx, "audit", days)
			}
			first := make(chan error, 1)
			go func() { first <- update(context.Background(), false) }()
			<-p.entered
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			next := make(chan error, 1)
			go func() { next <- update(ctx, true) }()
			returned := false
			select {
			case err := <-next:
				returned = true
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Errorf("queued request error=%v", err)
				}
			case <-time.After(300 * time.Millisecond):
				t.Error("queued policy writer ignored deadline")
			}
			close(p.resume)
			if err := <-first; err != nil {
				t.Fatal(err)
			}
			if !returned {
				<-next
			}
			if kind == "hold" {
				if !h.Pending("target") || !h.IsHeld("target") {
					t.Fatal("newer pending hold lost")
				}
				if newLegalHoldStore(p).IsHeld("target") {
					t.Fatal("pending falsely durable")
				}
			} else {
				if len(r.PendingForever()) != 1 {
					t.Fatal("newer pending forever lost")
				}
				if d, _ := r.Get("audit"); d != 0 {
					t.Fatal("pending protection lost")
				}
				if d, _ := newRetentionOverrideStore(p).Get("audit"); d != 1 {
					t.Fatal("pending falsely durable")
				}
			}
			if err := update(context.Background(), true); err != nil {
				t.Fatal(err)
			}
			if kind == "hold" {
				if h.Pending("target") || !newLegalHoldStore(p).IsHeld("target") {
					t.Fatal("hold retry not durable")
				}
			} else {
				if len(r.PendingForever()) != 0 {
					t.Fatal("pending not cleared by retry")
				}
				if d, _ := newRetentionOverrideStore(p).Get("audit"); d != 0 {
					t.Fatal("forever retry not durable")
				}
			}
		})
	}
}

func TestPolicyHealthWaitCancellationDoesNotChangeConfirmedState(t *testing.T) {
	for _, kind := range []string{"hold", "retention"} {
		t.Run(kind, func(t *testing.T) {
			p := &transactionalCAFixture{}
			h, r := newLegalHoldStore(p), newRetentionOverrideStore(p)
			var mu *cpWriterMutex
			var health func(context.Context) error
			if kind == "hold" {
				if err := h.Set("peer", "review", "", true, time.Now()); err != nil {
					t.Fatal(err)
				}
				mu = &h.writeMu
				health = h.HealthContext
			} else {
				if err := r.Set("audit", 1); err != nil {
					t.Fatal(err)
				}
				mu = &r.writeMu
				health = r.HealthContext
			}
			mu.Lock()
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			done := make(chan error, 1)
			go func() { done <- health(ctx) }()
			returned := false
			select {
			case err := <-done:
				returned = true
				if !errors.Is(err, context.Canceled) {
					t.Errorf("health error=%v", err)
				}
			case <-time.After(300 * time.Millisecond):
				t.Error("health ignored cancellation")
			}
			mu.Unlock()
			if !returned {
				<-done
			}
			if err := health(context.Background()); err != nil {
				t.Fatal(err)
			}
			if kind == "hold" {
				if !h.IsHeld("peer") || h.Pending("peer") {
					t.Fatal("hold state changed")
				}
			} else {
				if d, _ := r.Get("audit"); d != 1 || len(r.PendingForever()) != 0 {
					t.Fatal("retention state changed")
				}
			}
		})
	}
}

func TestPostgresPolicyWaitPreservationStopsLaterPrune(t *testing.T) {
	d, _, leader, peer := trustDistributionPostgresFixture(t)
	hp := d.store.(postgresBlobPersister)
	hp.key = "legal_hold"
	rp := hp
	rp.key = "retention_override"
	if err := hp.Save([]byte(`[]`)); err != nil {
		t.Fatal(err)
	}
	if err := rp.Save([]byte(`{"audit":1}`)); err != nil {
		t.Fatal(err)
	}
	h, r := newLegalHoldStore(hp), newRetentionOverrideStore(rp)
	if _, err := hp.db.Exec(`CREATE TABLE hot_events(tenant_id text,stream text,received_at timestamptz); INSERT INTO hot_events VALUES('target','access',now()-interval '10 days'),('free','audit',now()-interval '10 days')`); err != nil {
		t.Fatal(err)
	}
	var pid int
	if err := leader.conn.QueryRowContext(context.Background(), `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	term := leader.leaderSince.Load()
	// Model the shared policy locks held by an archive without blocking the
	// session: failure must happen at the local queue, before any SQL begins.
	h.writeMu.Lock()
	r.writeMu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	hd, rd := make(chan error, 1), make(chan error, 1)
	go func() { hd <- h.SetContext(ctx, "target", "review", "", true, time.Now()) }()
	go func() { rd <- r.SetContext(ctx, "audit", 0) }()
	for _, done := range []chan error{hd, rd} {
		select {
		case err := <-done:
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("wait error=%v", err)
			}
		case <-time.After(time.Second):
			h.writeMu.Unlock()
			r.writeMu.Unlock()
			cancel()
			t.Fatal("policy wait did not return")
		}
	}
	cancel()
	h.writeMu.Unlock()
	r.writeMu.Unlock()
	cfg := retentionConfig{hotEvents: time.Hour, legalHold: h, override: r}
	now := time.Now()
	prune := func() {
		deleteHotStreamOlderThan(context.Background(), hp.db, cfg, "target", "access", now.Add(-time.Hour), now)
		deleteHotStreamOlderThan(context.Background(), hp.db, cfg, "free", "audit", now.Add(-time.Hour), now)
	}
	prune()
	var count int
	if err := hp.db.QueryRow(`SELECT count(*) FROM hot_events`).Scan(&count); err != nil || count != 2 {
		t.Fatal("pending preservation bypassed", count, err)
	}
	if newLegalHoldStore(hp).IsHeld("target") {
		t.Fatal("hold falsely durable")
	}
	if days, _ := newRetentionOverrideStore(rp).Get("audit"); days != 1 {
		t.Fatal("retention falsely durable")
	}
	if err := h.Set("target", "review", "", false, now); err != nil {
		t.Fatal(err)
	}
	if err := r.Set("audit", 1); err != nil {
		t.Fatal(err)
	}
	prune()
	if err := hp.db.QueryRow(`SELECT count(*) FROM hot_events`).Scan(&count); err != nil || count != 0 {
		t.Fatal("explicit relaxation not applied", count, err)
	}
	leader.tick()
	peer.tick()
	var after int
	if err := leader.conn.QueryRowContext(context.Background(), `SELECT pg_backend_pid()`).Scan(&after); err != nil || after != pid || leader.leaderSince.Load() != term || !leader.IsLeader() || peer.IsLeader() {
		t.Fatal("leader changed", err)
	}
}
