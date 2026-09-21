package main

import (
	"context"
	"github.com/lantern-networks/dsse-core/archive"
	"io"
	"testing"
	"time"
)

// The caller selected a cutoff before a concurrent administrator committed a
// protection. The destructive boundary must use the new committed policy.
func TestPostgresArchiveRechecksRetentionAtDeleteBoundary(t *testing.T) {
	d, _, _, _ := trustDistributionPostgresFixture(t)
	p := d.store.(postgresBlobPersister)
	if _, err := p.db.Exec(`CREATE TABLE hot_events(tenant_id text,stream text,event_id text,received_at timestamptz,payload bytea)`); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"hold", "forever", "longer"} {
		t.Run(kind, func(t *testing.T) {
			hp, rp := p, p
			hp.key = "hold_" + kind
			rp.key = "ret_" + kind
			h, r := newLegalHoldStore(hp), newRetentionOverrideStore(rp)
			now := time.Now()
			cfg := retentionConfig{legalHold: h, override: r, hotEvents: 24 * time.Hour, archive: &fakeArchive{objs: map[string][]byte{}}}
			staleCutoff := now.Add(-cfg.retentionForStream("audit"))
			if _, err := p.db.Exec(`INSERT INTO hot_events VALUES($1,'audit','old',$2,$3)`, kind, now.Add(-10*24*time.Hour), []byte(`{}`)); err != nil {
				t.Fatal(err)
			}
			if kind == "hold" {
				if err := newLegalHoldStore(hp).Set(kind, "review", "", true, now); err != nil {
					t.Fatal(err)
				}
			} else {
				days := 0
				if kind == "longer" {
					days = 30
				}
				if err := newRetentionOverrideStore(rp).Set("audit", days); err != nil {
					t.Fatal(err)
				}
			}
			archiveThenPruneStream(context.Background(), p.db, cfg, kind, "audit", staleCutoff, now)
			var n int
			if err := p.db.QueryRow(`SELECT count(*) FROM hot_events WHERE tenant_id=$1`, kind).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n != 1 || len(cfg.archive.(*fakeArchive).objs) != 0 {
				t.Fatal("committed protection ignored by in-flight archive/delete")
			}
			deleteHotStreamOlderThan(context.Background(), p.db, cfg, kind, "audit", staleCutoff, now)
			if err := p.db.QueryRow(`SELECT count(*) FROM hot_events WHERE tenant_id=$1`, kind).Scan(&n); err != nil || n != 1 {
				t.Fatal("delete-only ignored changed policy", n, err)
			}
		})
	}
}

func TestPostgresDeleteOnlyPrunerProtectsHeldOutboxesAndOldTerms(t *testing.T) {
	d, _, leader, peer := trustDistributionPostgresFixture(t)
	p := d.store.(postgresBlobPersister)
	p.key = "legal_hold"
	h := newLegalHoldStore(p)
	for _, sql := range []string{`CREATE TABLE hot_events(tenant_id text,stream text,received_at timestamptz)`, `CREATE TABLE admin_audit_outbox(tenant_id text,status text,updated_at timestamptz)`, `CREATE TABLE domain_event_outbox(tenant_id text,status text,updated_at timestamptz)`} {
		if _, err := p.db.Exec(sql); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	old := now.Add(-10 * 24 * time.Hour)
	if err := h.Set("held", "review", "", true, now); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"held", "free"} {
		if _, err := p.db.Exec(`INSERT INTO hot_events VALUES($1,'audit',$2)`, tenant, old); err != nil {
			t.Fatal(err)
		}
		for _, table := range []string{"admin_audit_outbox", "domain_event_outbox"} {
			for _, status := range []string{"published", "dead", "pending", "publishing"} {
				if _, err := p.db.Exec("INSERT INTO "+table+" VALUES($1,$2,$3)", tenant, status, old); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	cfg := retentionConfig{hotEvents: time.Hour, outboxPublished: time.Hour, outboxDead: time.Hour, legalHold: h}
	stale := retentionWriteContext(context.Background())
	leader.release()
	peer.tick()
	peer.release()
	leader.tick()
	runRetentionPrune(stale, p.db, cfg)
	assertCount := func(table, tenant string, want int) {
		t.Helper()
		var n int
		if err := p.db.QueryRow("SELECT count(*) FROM "+table+" WHERE tenant_id=$1", tenant).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != want {
			t.Fatalf("%s/%s count=%d want=%d", table, tenant, n, want)
		}
	}
	for _, tenant := range []string{"held", "free"} {
		assertCount("hot_events", tenant, 1)
		assertCount("admin_audit_outbox", tenant, 4)
		assertCount("domain_event_outbox", tenant, 4)
	}
	runRetentionPrune(context.Background(), p.db, cfg)
	assertCount("hot_events", "held", 1)
	assertCount("hot_events", "free", 0)
	for _, table := range []string{"admin_audit_outbox", "domain_event_outbox"} {
		assertCount(table, "held", 4)
		assertCount(table, "free", 2)
	}
	if err := h.Set("held", "review", "", false, now); err != nil {
		t.Fatal(err)
	}
	runRetentionPrune(context.Background(), p.db, cfg)
	assertCount("hot_events", "held", 0)
	for _, table := range []string{"admin_audit_outbox", "domain_event_outbox"} {
		assertCount(table, "held", 2)
	}
}

type blockingPruneArchive struct {
	fakeArchive
	entered chan struct{}
	release chan struct{}
}

func (a *blockingPruneArchive) Put(ctx context.Context, key string, r io.Reader, size int64, opts archive.PutOptions) (archive.PutResult, error) {
	close(a.entered)
	select {
	case <-ctx.Done():
		return archive.PutResult{}, ctx.Err()
	case <-a.release:
		return a.fakeArchive.Put(ctx, key, r, size, opts)
	}
}
func TestPostgresPrunePolicyWriterWaitsForCommit(t *testing.T) {
	d, _, _, _ := trustDistributionPostgresFixture(t)
	p := d.store.(postgresBlobPersister)
	p.key = "legal_hold"
	if _, err := p.db.Exec(`CREATE TABLE hot_events(tenant_id text,stream text,event_id text,received_at timestamptz,payload bytea); INSERT INTO hot_events VALUES('held','audit','old',now()-interval '10 days','{}')`); err != nil {
		t.Fatal(err)
	}
	h := newLegalHoldStore(p)
	// Materialize a declared empty row, rather than a hold.
	if err := h.Set("held", "review", "", false, time.Now()); err != nil {
		t.Fatal(err)
	}
	arc := &blockingPruneArchive{fakeArchive: fakeArchive{objs: map[string][]byte{}}, entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		archiveThenPruneStream(context.Background(), p.db, retentionConfig{legalHold: h, archive: arc}, "held", "audit", time.Now().Add(-time.Hour), time.Now())
	}()
	select {
	case <-arc.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("archive never reached PUT")
	}
	// No process-local elector mutex: this independently admitted writer must be
	// serialized by the PostgreSQL policy row, not just a Go lock.
	writer := make(chan error, 1)
	go func() {
		writer <- p.Update(func([]byte) ([]byte, error) { return []byte(`[{"tenant_id":"held","held_since":"review"}]`), nil })
	}()
	select {
	case err := <-writer:
		close(arc.release)
		<-done
		t.Fatalf("policy committed before deletion transaction ended: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(arc.release)
	<-done
	if err := <-writer; err != nil {
		t.Fatal(err)
	}
	if !newLegalHoldStore(p).IsHeld("held") {
		t.Fatal("queued hold lost")
	}
	var n int
	if err := p.db.QueryRow(`SELECT count(*) FROM hot_events`).Scan(&n); err != nil || n != 0 {
		t.Fatal("ordered deletion failed", n, err)
	}
}
func TestPostgresArchiveTimeoutReleasesCPWriter(t *testing.T) {
	d, _, _, _ := trustDistributionPostgresFixture(t)
	p := d.store.(postgresBlobPersister)
	p.key = "audit_chain"
	if _, err := p.db.Exec(`CREATE TABLE hot_events(tenant_id text,stream text,event_id text,received_at timestamptz,payload bytea); INSERT INTO hot_events VALUES('held','audit','old',now()-interval '10 days','{}')`); err != nil {
		t.Fatal(err)
	}
	arc := &blockingPruneArchive{fakeArchive: fakeArchive{objs: map[string][]byte{}}, entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	started := time.Now()
	go func() {
		defer close(done)
		archiveThenPruneStream(context.Background(), p.db, retentionConfig{archive: arc, auditChain: newAuditChainStore(p)}, "held", "audit", time.Now().Add(-time.Hour), time.Now())
	}()
	select {
	case <-arc.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("archive never reached PUT")
	}
	select {
	case <-done:
	case <-time.After(cpStateBlobDBTimeout + 3*time.Second):
		close(arc.release)
		<-done
		t.Fatal("unbounded archive PUT held CP writer")
	}
	if time.Since(started) < cpStateBlobDBTimeout/2 {
		t.Fatal("test did not wait for configured timeout")
	}
	// The original elector session may have been discarded by database/sql on
	// cancellation. A tick must recover it; an ordinary write must work again.
	cpLeaderElectorInstance.tick()
	q := p
	q.key = "after_archive_timeout"
	if err := q.UpdateContext(retentionWriteContext(context.Background()), func([]byte) ([]byte, error) { return []byte(`{}`), nil }); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := p.db.QueryRow(`SELECT count(*) FROM hot_events`).Scan(&n); err != nil || n != 1 {
		t.Fatal("timed-out archive erased hot data", n, err)
	}
}

func TestPostgresPrunePolicyCorruptionKeepsHotRows(t *testing.T) {
	d, _, _, _ := trustDistributionPostgresFixture(t)
	p := d.store.(postgresBlobPersister)
	if _, err := p.db.Exec(`CREATE TABLE hot_events(tenant_id text,stream text,received_at timestamptz); INSERT INTO hot_events VALUES('protected','audit',now()-interval '10 days')`); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"hold", "retention"} {
		p.key = kind
		h := newLegalHoldStore(nil)
		r := newRetentionOverrideStore(nil)
		if kind == "hold" {
			h = newLegalHoldStore(p)
			if err := h.Set("protected", "review", "", false, time.Now()); err != nil {
				t.Fatal(err)
			}
		} else {
			r = newRetentionOverrideStore(p)
			if err := r.Set("audit", 1); err != nil {
				t.Fatal(err)
			}
		}
		for _, bad := range []string{"null", "broken", "missing"} {
			if bad == "missing" {
				if _, err := p.db.Exec(`DELETE FROM cp_state_blobs WHERE store_key=$1`, p.key); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := p.Save([]byte(bad)); err != nil {
					t.Fatal(err)
				}
			}
			deleteHotStreamOlderThan(context.Background(), p.db, retentionConfig{legalHold: h, override: r, hotEvents: time.Hour}, "protected", "audit", time.Now().Add(-time.Hour), time.Now())
			var n int
			if err := p.db.QueryRow(`SELECT count(*) FROM hot_events`).Scan(&n); err != nil || n != 1 {
				t.Fatal("invalid policy allowed deletion", kind, bad, n, err)
			}
		}
	}
}
