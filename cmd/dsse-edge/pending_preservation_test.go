package main

import (
	"bytes"
	"context"
	"github.com/lantern-networks/dsse-core/blobstore"
	"testing"
	"time"
)

func TestPendingPreservationSurvivesRefreshAndUnrelatedSave(t *testing.T) {
	for _, shared := range []bool{false, true} {
		name := "file-contract"
		if shared {
			name = "shared-contract"
		}
		t.Run(name, func(t *testing.T) {
			var hp, rp blobstore.Persister
			var fail func(bool)
			if shared {
				h, r := &transactionalCAFixture{}, &transactionalCAFixture{}
				hp, rp = h, r
				fail = func(v bool) { h.failCommit = v; r.failCommit = v }
			} else {
				h, r := &holdOutcomePersister{}, &holdOutcomePersister{}
				hp, rp = h, r
				fail = func(v bool) { h.fail = v; r.fail = v }
			}
			h, r := newLegalHoldStore(hp), newRetentionOverrideStore(rp)
			now := time.Now()
			if err := h.Set("peer", "review", "", true, now); err != nil {
				t.Fatal(err)
			}
			if err := r.Set("audit", 1); err != nil {
				t.Fatal(err)
			}
			beforeH, _ := hp.Load()
			beforeR, _ := rp.Load()
			fail(true)
			if h.Set("target", "review", "", true, now) == nil || r.Set("audit", 0) == nil {
				t.Fatal("failed save acknowledged")
			}
			if h.Health() != nil || r.Health() != nil {
				t.Fatal("healthy durable state unavailable")
			}
			if !h.IsHeld("target") {
				t.Fatal("unsaved hold lost on refresh")
			}
			if d, ok := r.Get("audit"); !ok || d != 0 {
				t.Fatal("unsaved forever lost on refresh")
			}
			afterH, _ := hp.Load()
			afterR, _ := rp.Load()
			if !bytes.Equal(beforeH, afterH) || !bytes.Equal(beforeR, afterR) {
				t.Fatal("failed write changed storage")
			}
			if newLegalHoldStore(hp).IsHeld("target") {
				t.Fatal("local intent falsely durable")
			}
			if d, _ := newRetentionOverrideStore(rp).Get("audit"); d != 1 {
				t.Fatal("forever falsely durable")
			}
			if h.Set("target", "review", "", false, now) == nil || r.Set("audit", 1) == nil {
				t.Fatal("failed relaxation acknowledged")
			}
			if !h.IsHeld("target") {
				t.Fatal("failed release lost pending hold")
			}
			if d, _ := r.Get("audit"); d != 0 {
				t.Fatal("failed reduction lost pending forever")
			}
			fail(false)
			if h.Set("other", "review", "", true, now) != nil || r.Set("access", 30) != nil {
				t.Fatal("unrelated save failed")
			}
			if !h.IsHeld("target") {
				t.Fatal("unrelated save cleared pending hold")
			}
			if d, _ := r.Get("audit"); d != 0 {
				t.Fatal("unrelated save cleared pending forever")
			}
			if newLegalHoldStore(hp).IsHeld("target") {
				t.Fatal("unrelated save persisted pending hold")
			}
			if d, _ := newRetentionOverrideStore(rp).Get("audit"); d != 1 {
				t.Fatal("unrelated save persisted pending forever")
			}
			if h.Set("target", "review", "", true, now) != nil || r.Set("audit", 0) != nil {
				t.Fatal("retry failed")
			}
			if !newLegalHoldStore(hp).IsHeld("target") {
				t.Fatal("retry not durable")
			}
			if d, _ := newRetentionOverrideStore(rp).Get("audit"); d != 0 {
				t.Fatal("forever retry not durable")
			}
			if h.Set("target", "review", "", false, now) != nil || r.Set("audit", 1) != nil {
				t.Fatal("release failed")
			}
			if h.IsHeld("target") || !h.IsHeld("peer") {
				t.Fatal("release/peer mismatch")
			}
			if d, _ := r.Get("audit"); d != 1 {
				t.Fatal("release did not clear pending")
			}
		})
	}
}

func TestPostgresPendingPreservationStopsDestructiveBoundary(t *testing.T) {
	d, _, _, _ := trustDistributionPostgresFixture(t)
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
	for _, q := range []string{`CREATE TABLE hot_events(tenant_id text,stream text,received_at timestamptz)`, `CREATE TABLE admin_audit_outbox(tenant_id text,status text,updated_at timestamptz)`, `CREATE TABLE domain_event_outbox(tenant_id text,status text,updated_at timestamptz)`, `INSERT INTO hot_events VALUES('target','audit',now()-interval '10 days'),('target','access',now()-interval '10 days'),('free','audit',now()-interval '10 days'),('free','access',now()-interval '10 days')`, `INSERT INTO admin_audit_outbox VALUES('target','published',now()-interval '10 days'),('free','published',now()-interval '10 days')`, `INSERT INTO domain_event_outbox SELECT * FROM admin_audit_outbox`, `CREATE FUNCTION refuse_preservation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected save refusal'; END $$; CREATE TRIGGER refuse_preservation BEFORE UPDATE ON cp_state_blobs FOR EACH ROW EXECUTE FUNCTION refuse_preservation()`} {
		if _, err := hp.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	cfg := retentionConfig{hotEvents: time.Hour, outboxPublished: time.Hour, legalHold: h, override: r}
	if h.Set("target", "review", "", true, now) == nil || r.Set("audit", 0) == nil {
		t.Fatal("save refusal missing")
	}
	// Trigger only rejects UPDATE; a sweep reading durable rows would still delete.
	if h.Health() != nil || r.Health() != nil {
		t.Fatal("refresh failed")
	}
	result := purgeAdminTenantData(context.Background(), "test", "target", nil, nil, nil, nil, nil, nil, "", nil, nil, adminTenantExtraStores{}, h, now)
	if result.Complete || len(result.Erased) != 0 || len(result.Failures) != 1 || result.Failures[0] != "legal_hold: tenant is held" {
		t.Fatal("pending hold bypassed purge guard", result)
	}
	stale := now.Add(-time.Hour)
	deleteHotStreamOlderThan(context.Background(), hp.db, cfg, "target", "access", stale, now)
	deleteHotStreamOlderThan(context.Background(), hp.db, cfg, "free", "audit", stale, now)
	runRetentionPrune(context.Background(), hp.db, cfg)
	count := func(table, tenant string, want int) {
		t.Helper()
		var n int
		if err := hp.db.QueryRow("SELECT count(*) FROM "+table+" WHERE tenant_id=$1", tenant).Scan(&n); err != nil || n != want {
			t.Fatalf("%s/%s=%d want=%d err=%v", table, tenant, n, want, err)
		}
	}
	count("hot_events", "target", 2)
	count("hot_events", "free", 1)
	for _, table := range []string{"admin_audit_outbox", "domain_event_outbox"} {
		count(table, "target", 1)
		count(table, "free", 0)
	}
	if _, err := hp.db.Exec(`DROP TRIGGER refuse_preservation ON cp_state_blobs; DROP FUNCTION refuse_preservation()`); err != nil {
		t.Fatal(err)
	}
	if h.Set("target", "review", "", false, now) != nil || r.Set("audit", 1) != nil {
		t.Fatal("explicit successful relaxation failed")
	}
	runRetentionPrune(context.Background(), hp.db, cfg)
	count("hot_events", "target", 0)
	count("hot_events", "free", 0)
	for _, table := range []string{"admin_audit_outbox", "domain_event_outbox"} {
		count(table, "target", 0)
	}
}
