package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/policyrule"
)

type purgeHoldInterleave struct {
	raw       []byte
	afterSave func()
}

func (p *purgeHoldInterleave) Load() ([]byte, error) { return p.raw, nil }
func (p *purgeHoldInterleave) Save(b []byte) error {
	p.raw = append([]byte(nil), b...)
	if p.afterSave != nil {
		f := p.afterSave
		p.afterSave = nil
		f()
	}
	return nil
}

func TestPostgresTenantPurgeRechecksHoldAfterEarlierStore(t *testing.T) {
	d, _, _, _ := trustDistributionPostgresFixture(t)
	hp := d.store.(postgresBlobPersister)
	hp.key = "legal_hold"
	if err := hp.Save([]byte(`[]`)); err != nil {
		t.Fatal(err)
	}
	holds, peer := newLegalHoldStore(hp), newLegalHoldStore(hp)
	for _, table := range []string{"hot_events", "admin_audit_outbox", "domain_event_outbox", "admin_tenant_model_deletions", "admin_tenant_model_purge_orders"} {
		if _, err := hp.db.Exec("CREATE TABLE " + table + "(tenant_id text); INSERT INTO " + table + " VALUES('target'),('peer')"); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	writer, err := logs.NewWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	logpath := filepath.Join(dir, "tenants", logs.SafeTenantSegment("target"), "audit.log.jsonl")
	if err := os.MkdirAll(filepath.Dir(logpath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logpath, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	p := &purgeHoldInterleave{}
	rules := policyrule.NewStore()
	if err := rules.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if _, err := rules.Upsert(policyrule.Rule{ID: "rule", TenantID: "target", Plane: policyrule.PlaneEgress, Priority: 100, Source: []string{"*"}, Destination: []string{"*"}, ServiceID: "builtin-svc-https", Action: policyrule.Action{Access: "deny", Inspection: "inspect"}, Status: "active"}); err != nil {
		t.Fatal(err)
	}
	// Commit a concurrent administrator's hold after the entry guard, during an
	// earlier store's deletion. No wall-clock race or production hook is needed.
	p.afterSave = func() {
		if err := peer.Set("target", "review", "", true, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	result := purgeAdminTenantData(context.Background(), "test", "target", hp.db, writer, nil, nil, rules, nil, "", nil, nil, adminTenantExtraStores{}, holds, time.Now())
	if result.Complete || len(result.Failures) == 0 {
		t.Error("partial purge claimed success")
	}
	if _, err := os.Stat(logpath); err != nil {
		t.Error("hold committed before file deletion but file was erased", err)
	}
	for _, table := range []string{"hot_events", "admin_audit_outbox", "domain_event_outbox", "admin_tenant_model_deletions", "admin_tenant_model_purge_orders"} {
		for _, tenant := range []string{"target", "peer"} {
			var n int
			if err := hp.db.QueryRow("SELECT count(*) FROM "+table+" WHERE tenant_id=$1", tenant).Scan(&n); err != nil || n != 1 {
				t.Errorf("%s/%s count=%d err=%v", table, tenant, n, err)
			}
		}
	}
	if err := peer.Set("target", "review", "", false, time.Now()); err != nil {
		t.Fatal(err)
	}
	purgeAdminTenantData(context.Background(), "test", "target", hp.db, writer, nil, nil, rules, nil, "", nil, nil, adminTenantExtraStores{}, holds, time.Now())
	if _, err := os.Stat(logpath); !os.IsNotExist(err) {
		t.Error("released file not erased", err)
	}
	for _, table := range []string{"hot_events", "admin_audit_outbox", "domain_event_outbox"} {
		var n int
		if err := hp.db.QueryRow("SELECT count(*) FROM " + table + " WHERE tenant_id='target'").Scan(&n); err != nil || n != 0 {
			t.Errorf("released %s count=%d err=%v", table, n, err)
		}
	}
}

func TestPostgresPurgeHoldGuardKeepsWriterOutsideDeletion(t *testing.T) {
	d, _, a, b := trustDistributionPostgresFixture(t)
	hp := d.store.(postgresBlobPersister)
	hp.key = "legal_hold"
	if err := hp.Save([]byte(`[]`)); err != nil {
		t.Fatal(err)
	}
	holds := newLegalHoldStore(hp)
	ctx := retentionWriteContext(context.Background())
	tx, finish, err := beginTenantPurgeHoldGuard(ctx, holds, hp.db, "target")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { finish() }()
	// A different SQL connection bypasses the process elector mutex, proving
	// the authoritative row lock (not only the Go mutex) excludes the writer.
	waitCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	_, err = hp.db.ExecContext(waitCtx, `UPDATE cp_state_blobs SET payload=$1 WHERE store_key=$2`, []byte(`[{"tenant_id":"target"}]`), hp.key)
	cancel()
	if err == nil {
		t.Fatal("hold writer passed an active deletion guard")
	}
	if tx == nil {
		t.Fatal("same-pool deletion must share policy transaction")
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	finish()
	finish = func() {}
	if err := newLegalHoldStore(hp).Set("target", "peer", "", true, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, release, err := beginTenantPurgeHoldGuard(retentionWriteContext(context.Background()), holds, hp.db, "target"); err == nil {
		release()
		t.Fatal("committed hold bypassed")
	}
	if err := newLegalHoldStore(hp).Set("target", "peer", "", false, time.Now()); err != nil {
		t.Fatal(err)
	}
	old := captureCPWriteLease(context.Background())
	a.release()
	b.tick()
	b.release()
	a.tick()
	if _, release, err := beginTenantPurgeHoldGuard(old, holds, hp.db, "target"); err == nil {
		release()
		t.Fatal("old term admitted")
	}
}

func TestPurgeLocalHoldGuardKeepsFailedProtectionAndCancellation(t *testing.T) {
	p := &holdOutcomePersister{}
	holds := newLegalHoldStore(p)
	p.fail = true
	if holds.Set("target", "review", "", true, time.Now()) == nil {
		t.Fatal("expected refusal")
	}
	if _, done, err := beginTenantPurgeHoldGuard(context.Background(), holds, nil, "target"); err == nil {
		done()
		t.Fatal("pending hold ignored")
	}
	p.fail = false
	if err := holds.Set("target", "review", "", false, time.Now()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, done, err := beginTenantPurgeHoldGuard(ctx, holds, nil, "target"); err == nil {
		done()
		t.Fatal("cancelled deletion allowed")
	}
	_, done, err := beginTenantPurgeHoldGuard(context.Background(), holds, nil, "target")
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan error, 1)
	go func() { ch <- holds.Set("target", "review", "", true, time.Now()) }()
	select {
	case <-ch:
		done()
		t.Fatal("local hold writer passed deletion guard")
	case <-time.After(30 * time.Millisecond):
	}
	done()
	select {
	case err := <-ch:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("writer did not resume")
	}
}
