package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
)

func TestTenantErasureFenceFileReloadAndOwner(t *testing.T) {
	p := blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "holds.json")}
	h := newLegalHoldStore(p)
	if err := h.Set("peer", "review", "keep", true, time.Now()); err != nil {
		t.Fatal(err)
	}
	ctx, finish, err := h.beginErasure(context.Background(), "target", "node-a")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := p.Load()
	if err != nil {
		t.Fatal(err)
	}
	var legacy []legalHoldRecord
	if json.Unmarshal(raw, &legacy) == nil {
		t.Fatal("old reader can silently drop marker")
	}
	reloaded := newLegalHoldStore(p) // Durable reload, not an OS process restart.
	if !reloaded.IsHeld("target") || !reloaded.IsHeld("peer") {
		t.Fatal("reload did not retain protection")
	}
	for _, active := range []bool{true, false} {
		if !errors.Is(reloaded.Set("target", "review", "", active, time.Now()), errTenantErasureInProgress) {
			t.Fatal("reload accepted target mutation")
		}
	}
	if _, _, _, err := reloaded.adminStatus(context.Background(), "target"); !errors.Is(err, errTenantErasureInProgress) {
		t.Fatal("erasure represented as accepted hold", err)
	}
	if _, done, err := beginTenantPurgeHoldGuard(context.Background(), h, nil, "target"); err == nil {
		done()
		t.Fatal("unowned erasure admitted")
	}
	if _, done, err := beginTenantPurgeHoldGuard(ctx, h, nil, "target"); err != nil {
		t.Fatal(err)
	} else {
		done()
	}
	if err := finish(); err != nil {
		t.Fatal(err)
	}
	final := newLegalHoldStore(p)
	if final.IsHeld("target") || !final.IsHeld("peer") {
		t.Fatal("completion changed peer or left fence")
	}
	raw, err = p.Load()
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(raw, &legacy) == nil {
		t.Fatal("completion reverted to old format")
	}
	if err := final.Set("target", "review", "", true, time.Now()); err != nil {
		t.Fatal(err)
	}
	// Hold committed first wins and no erasure marker is saved.
	before, _ := p.Load()
	if _, _, err := final.beginErasure(context.Background(), "target", "node"); err == nil {
		t.Fatal("accepted hold bypassed")
	}
	after, _ := p.Load()
	if !bytes.Equal(before, after) {
		t.Fatal("rejected start changed state")
	}
}

func TestTenantErasureFenceFailedSaveAndCompletion(t *testing.T) {
	p := &holdOutcomePersister{}
	h := newLegalHoldStore(p)
	p.fail = true
	if _, _, err := h.beginErasure(context.Background(), "target", "node"); err == nil {
		t.Fatal("failed acquisition accepted")
	}
	if len(p.data) != 0 {
		t.Fatal("failed acquisition persisted")
	}
	p.fail = false
	ctx, cancel := context.WithCancel(context.Background())
	_, finish, err := h.beginErasure(ctx, "target", "node")
	if err != nil {
		t.Fatal(err)
	}
	saved := bytes.Clone(p.data)
	cancel()
	p.fail = true
	if err := finish(); err == nil {
		t.Fatal("failed completion accepted")
	}
	if !h.IsHeld("target") || !newLegalHoldStore(p).IsHeld("target") || !bytes.Equal(saved, p.data) {
		t.Fatal("failed completion lost marker")
	}
	if _, _, err := h.beginErasure(context.Background(), "target", "retry"); err == nil {
		t.Fatal("unresolved erasure retried")
	}
	p.fail = false
	if err := finish(); err != nil {
		t.Fatal("bounded completion should outlive request cancellation", err)
	}
	if h.IsHeld("target") {
		t.Fatal("completed marker retained")
	}
}

func TestPostgresTenantErasureFenceSurvivesSessionLoss(t *testing.T) {
	d, _, a, b := trustDistributionPostgresFixture(t)
	hp := d.store.(postgresBlobPersister)
	hp.key = "legal_hold"
	h := newLegalHoldStore(hp)
	if err := h.Set("peer", "review", "keep", true, time.Now()); err != nil {
		t.Fatal(err)
	}
	_, finish, err := h.beginErasure(retentionWriteContext(context.Background()), "target", "node-a")
	if err != nil {
		t.Fatal(err)
	}
	before, err := hp.Load()
	if err != nil {
		t.Fatal(err)
	}
	// An independent resource transaction can finish after the CP session dies.
	if _, err := hp.db.Exec("CREATE TABLE independent_resource(tenant_id text); INSERT INTO independent_resource VALUES('target'),('peer')"); err != nil {
		t.Fatal(err)
	}
	resource, err := hp.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer resource.Rollback()
	if _, err := resource.Exec("DELETE FROM independent_resource WHERE tenant_id='target'"); err != nil {
		t.Fatal(err)
	}
	var pid int
	if err := a.conn.QueryRowContext(context.Background(), "SELECT pg_backend_pid()").Scan(&pid); err != nil {
		t.Fatal(err)
	}
	if _, err := hp.db.Exec("SELECT pg_terminate_backend($1)", pid); err != nil {
		t.Fatal(err)
	}
	a.release()
	b.tick()
	if !b.IsLeader() {
		t.Fatal("peer did not take leadership")
	}
	cpLeaderElectorInstance = b
	peer := newLegalHoldStore(hp)
	if err := peer.Set("target", "review", "", true, time.Now()); !errors.Is(err, errTenantErasureInProgress) {
		t.Fatal("new leader accepted hold while resource work remained", err)
	}
	if peer.Pending("target") {
		t.Fatal("known refusal misreported as unconfirmed write")
	}
	if err := resource.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := finish(); err == nil {
		t.Fatal("old leader cleared fence")
	}
	after, err := hp.Load()
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("session loss changed fence", err)
	}
	if !newLegalHoldStore(hp).IsHeld("target") {
		t.Fatal("fresh reader lost fence")
	}
	if err := peer.Set("unrelated", "review", "", true, time.Now()); err != nil {
		t.Fatal(err)
	}
	current := newLegalHoldStore(hp)
	if !current.IsHeld("target") || !current.IsHeld("peer") || !current.IsHeld("unrelated") {
		t.Fatal("peer update discarded protection")
	}
	// Automatic retry must remain stopped; recovery requires evidence that all
	// old external work has ended, not just SQL leadership or a timer.
	if _, _, err := current.beginErasure(context.Background(), "target", "node-b"); err == nil {
		t.Fatal("takeover resumed unresolved purge")
	}
}

func TestTenantErasureFenceHTTPRefusalAndAudit(t *testing.T) {
	p := &holdOutcomePersister{}
	h := newLegalHoldStore(p)
	tenant := testEvaluator().PolicyBundle.TenantID
	_, finish, err := h.beginErasure(context.Background(), tenant, "test")
	if err != nil {
		t.Fatal(err)
	}
	saved := bytes.Clone(p.data)
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, Registry: connector.NewRegistry(), LegalHold: h})
	for _, method := range []string{"GET", "POST"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(method, "/admin/legal-hold", strings.NewReader(`{"active":true}`)))
		want := http.StatusServiceUnavailable
		if method == "POST" {
			want = http.StatusInternalServerError
		}
		if rec.Code != want {
			t.Fatalf("%s status=%d body=%s", method, rec.Code, rec.Body.String())
		}
	}
	if !bytes.Equal(saved, p.data) {
		t.Fatal("refused request changed marker")
	}
	rows, err := writer.ReadJSONL("audit.log.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range rows {
		if r["event_type"] == "admin_config_change" && r["target_id"] == "/admin/legal-hold" {
			n++
			if r["result"] != "error" {
				t.Fatal("refusal logged as success", r)
			}
		}
	}
	if n != 1 {
		t.Fatalf("refusal audit count=%d", n)
	}
	if err := finish(); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("POST", "/admin/legal-hold", strings.NewReader(`{"active":true}`)))
	if rec.Code != 200 {
		t.Fatal("post-completion hold failed", rec.Code)
	}
}

func TestTenantErasureFenceInvalidSnapshotFailsClosed(t *testing.T) {
	for _, raw := range []string{`{"version":4,"holds":[],"erasures":{}}`, `{"version":2,"holds":[]}`, `{"version":2,"holds":[],"erasures":{"target":{"id":"bad","node":"n","started_at":"2026-09-23T00:00:00Z"}}}`} {
		p := blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "holds.json")}
		if err := os.WriteFile(p.Path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		h := newLegalHoldStore(p)
		if h.Health() == nil || !h.IsHeld("target") {
			t.Fatal("unknown marker accepted")
		}
		if _, _, err := h.beginErasure(context.Background(), "target", "node"); err == nil {
			t.Fatal("corrupt state overwritten")
		}
		saved, err := p.Load()
		if err != nil || string(saved) != raw {
			t.Fatal("corrupt original changed", err)
		}
	}
}

func TestTenantErasureFencePartialFailureRecoveryRetry(t *testing.T) {
	// A canceled whole-purge preserves files and the durable marker; a retry
	// remains stopped until offline reconciliation clears only that operation.
	p := blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "holds.json")}
	h := newLegalHoldStore(p)
	if err := h.Set("peer", "review", "keep", true, time.Now()); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writer, err := logs.NewWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	path := filepath.Join(dir, "tenants", logs.SafeTenantSegment("target"), "audit.log.jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// Save the marker, then cancel before the first resource step. The context
	// remains valid for acquisition, so this is not merely an entry rejection.
	wrapped := &cancelAfterFenceSave{Persister: p}
	h.persister = wrapped
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wrapped.cancel = cancel
	result := purgeAdminTenantData(ctx, "node", "target", nil, writer, nil, nil, nil, nil, "", nil, nil, adminTenantExtraStores{}, h, time.Now())
	if result.Complete || len(result.Failures) == 0 {
		t.Fatal("partial purge reported success")
	}
	raw, err := p.Load()
	if err != nil {
		t.Fatal(err)
	}
	restored := newLegalHoldStore(p)
	if !restored.IsHeld("target") {
		t.Fatal("partial failure lost marker")
	}
	retry := purgeAdminTenantData(context.Background(), "node", "target", nil, writer, nil, nil, nil, nil, "", nil, nil, adminTenantExtraStores{}, restored, time.Now())
	if retry.Complete || len(retry.Erased) != 0 {
		t.Fatal("unreconciled retry proceeded")
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "{}\n" {
		t.Fatal("file changed before recovery", err)
	}
	// Sole owner has returned, no outstanding work remains: offline file-store
	// procedure retains the original version, peer hold and every other marker.
	snapshot, err := decodeHoldSnapshot(raw, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := snapshot.Erasures["target"]; !ok {
		t.Fatal("recovery has no expected operation")
	}
	delete(snapshot.Erasures, "target")
	recovered, err := encodeHoldSnapshot(snapshot.held(), snapshot.Erasures, snapshot.Version)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Save(recovered); err != nil {
		t.Fatal(err)
	}
	restarted := newLegalHoldStore(p)
	retry = purgeAdminTenantData(context.Background(), "node", "target", nil, writer, nil, nil, nil, nil, "", nil, nil, adminTenantExtraStores{}, restarted, time.Now())
	if !retry.Complete || len(retry.Failures) != 0 {
		t.Fatalf("reconciled retry failed: %+v", retry)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("retry left file", err)
	}
	if !newLegalHoldStore(p).IsHeld("peer") {
		t.Fatal("recovery removed peer hold")
	}
}

type cancelAfterFenceSave struct {
	blobstore.Persister
	cancel context.CancelFunc
}

func (p *cancelAfterFenceSave) Save(raw []byte) error {
	if err := p.Persister.Save(raw); err != nil {
		return err
	}
	if p.cancel != nil {
		p.cancel()
		p.cancel = nil
	}
	return nil
}

func TestPostgresTenantErasureDocumentedRecoveryCAS(t *testing.T) {
	d, _, _, _ := trustDistributionPostgresFixture(t)
	hp := d.store.(postgresBlobPersister)
	hp.key = "legal_hold"
	h := newLegalHoldStore(hp)
	if err := h.Set("peer", "review", "keep", true, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.beginErasure(context.Background(), "target", "node"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.beginErasure(context.Background(), "other-operation", "node"); err != nil {
		t.Fatal(err)
	}
	raw, err := hp.Load()
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := decodeHoldSnapshot(raw, true)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := os.ReadFile("../../docs/tenant-erasure-recovery.md")
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.Split(strings.Split(string(doc), "-- tenant-erasure-recovery-cas-begin\n")[1], "\n-- tenant-erasure-recovery-cas-end")[0]
	sql = strings.NewReplacer(":'expected_hex'", "$1", ":'tenant'", "$2", ":'operation_id'", "$3").Replace(sql)
	run := func(expected []byte, id string, want int64) {
		t.Helper()
		res, err := hp.db.Exec(sql, fmt.Sprintf("%x", expected), "target", id)
		if err != nil {
			t.Fatal(err)
		}
		n, err := res.RowsAffected()
		if err != nil || n != want {
			t.Fatalf("recovery affected=%d want=%d err=%v", n, want, err)
		}
	}
	run(raw, "wrong-operation", 0)
	if err := h.Set("new-peer", "review", "keep", true, time.Now()); err != nil {
		t.Fatal(err)
	}
	run(raw, snapshot.Erasures["target"].ID, 0) // Whole-snapshot CAS protects concurrent changes.
	latest, err := hp.Load()
	if err != nil {
		t.Fatal(err)
	}
	run(latest, snapshot.Erasures["target"].ID, 1)
	final := newLegalHoldStore(hp)
	if final.IsHeld("target") || !final.IsHeld("other-operation") || !final.IsHeld("peer") || !final.IsHeld("new-peer") {
		t.Fatal("recovery lost peer state or did not clear target")
	}
	if _, finish, err := final.beginErasure(context.Background(), "target", "retry"); err != nil {
		t.Fatal(err)
	} else if err := finish(); err != nil {
		t.Fatal(err)
	}
}
