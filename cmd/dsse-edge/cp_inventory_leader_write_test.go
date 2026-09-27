package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPostgresInventoryRequestsCannotOutliveLeadership(t *testing.T) {
	for _, kind := range []string{"enroll", "assign", "create_group", "rename_group"} {
		t.Run(kind, func(t *testing.T) {
			a, b := postgresFailureElectors(t)
			db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), "../../migrations", true)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			p := postgresBlobPersister{db: db, key: "test_inventory_request"}
			db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
			defer db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
			l := enrolledinventory.NewLedger()
			if err := l.SetPersisterChecked(p); err != nil {
				t.Fatal(err)
			}
			if _, err := l.Enroll("target-device", "tenant_lab_001", "", "now"); err != nil {
				t.Fatal(err)
			}
			g, err := l.CreateGroup("Initial", "tenant_lab_001", "", "", "now")
			if err != nil {
				t.Fatal(err)
			}
			old := cpLeaderElectorInstance
			cpLeaderElectorInstance = a
			defer func() { cpLeaderElectorInstance = old }()
			a.tick()
			auth := newAdminAuthStore()
			auth.UpsertPrincipal(adminPrincipal{ID: "review", TenantID: "tenant_lab_001", Roles: []string{"admin"}, Status: "active"})
			auth.UpsertSession(adminSession{ID: "inventory-session", TenantID: "tenant_lab_001", AdminPrincipalID: "review", Roles: []string{"admin"}, Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "inventory-csrf"}})
			h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: auth, EnrolledLedger: l})
			method, path, raw := "POST", "/admin/enrolled-devices", `{"identity":"target-device","note":"stale"}`
			switch kind {
			case "assign":
				path = "/admin/enrolled-devices/target-device/group"
				raw = `{"group":"Stale"}`
			case "create_group":
				path = "/admin/device-groups"
				raw = `{"name":"Stale"}`
			case "rename_group":
				method = "PATCH"
				path = "/admin/device-groups/" + g.ID
				raw = `{"name":"Stale"}`
			}
			body := &pausedSeatBody{Reader: strings.NewReader(raw), entered: make(chan struct{}), resume: make(chan struct{})}
			req := httptest.NewRequest(method, path, body)
			req.AddCookie(&http.Cookie{Name: "admin_session", Value: "inventory-session"})
			req.Header.Set("X-CSRF-Token", "inventory-csrf")
			rec := httptest.NewRecorder()
			done := make(chan struct{})
			go func() { defer close(done); h.ServeHTTP(rec, req) }()
			select {
			case <-body.entered:
			case <-done:
				t.Fatalf("body not reached: %d", rec.Code)
			case <-time.After(5 * time.Second):
				t.Fatal("body timeout")
			}
			a.release()
			b.tick()
			if !b.IsLeader() {
				close(body.resume)
				<-done
				t.Fatal("peer election")
			}
			peer := enrolledinventory.NewLedger()
			if err := peer.SetPersisterChecked(p); err != nil {
				t.Fatal(err)
			}
			if _, err := peer.Enroll("foreign-device", "tenant_other", "peer", "now"); err != nil {
				t.Fatal(err)
			}
			if _, _, err := peer.SetGroup("target-device", "Peer", "now"); err != nil {
				t.Fatal(err)
			}
			before, err := p.Load()
			if err != nil {
				t.Fatal(err)
			}
			generation := l.ConfigGeneration()
			close(body.resume)
			<-done
			after, err := p.Load()
			if err != nil {
				t.Fatal(err)
			}
			if rec.Code != 503 || !bytes.Equal(before, after) || l.ConfigGeneration() != generation {
				t.Fatalf("stale %s: status=%d saved_unchanged=%v generation_unchanged=%v", kind, rec.Code, bytes.Equal(before, after), l.ConfigGeneration() == generation)
			}
		})
	}
}

func TestPostgresInventoryLifecycleUsesLatestRow(t *testing.T) {
	a, b := postgresFailureElectors(t)
	db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), "../../migrations", true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p := postgresBlobPersister{db: db, key: "test_inventory_lifecycle"}
	db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
	defer db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
	l := enrolledinventory.NewLedger()
	if err := l.SetPersisterChecked(p); err != nil {
		t.Fatal(err)
	}
	old := cpLeaderElectorInstance
	cpLeaderElectorInstance = a
	defer func() { cpLeaderElectorInstance = old }()
	a.tick()
	ctx := captureCPWriteLease(context.Background())
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := l.EnrollGroupForTenantContext(ctx, "target", "tenant_a", "tenant_a", "Pilot", "", now, false); err != nil {
		t.Fatal(err)
	}
	g, err := l.CreateGroupContext(ctx, "Pilot", "tenant_a", "", "high", now)
	if err != nil {
		t.Fatal(err)
	}
	peer := enrolledinventory.NewLedger()
	if err := peer.SetPersisterChecked(p); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.EnrollGroup("foreign", "tenant_b", "Pilot", "", now); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.EnrollGroup("new-member", "tenant_a", "Pilot", "", now); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.CreateGroup("Pilot", "tenant_b", "", "critical", now); err != nil {
		t.Fatal(err)
	}
	if _, err := l.EnrollGroupForTenantContext(ctx, "foreign", "tenant_a", "tenant_a", "", "", now, false); !errors.Is(err, enrolledinventory.ErrIdentityOwnedByAnotherTenant) {
		t.Fatalf("latest owner: %v", err)
	}
	name := "Renamed"
	if _, n, err := l.UpdateGroupContext(ctx, g.ID, "tenant_a", &name, nil, nil, now); err != nil || n != 2 {
		t.Fatalf("rename cascade n=%d err=%v", n, err)
	}
	if e, _ := l.EntryFor("foreign"); e.Group != "Pilot" {
		t.Fatal("foreign assignment changed")
	}
	if _, _, err := l.DeleteGroupContext(ctx, g.ID, "tenant_a", false); !errors.Is(err, enrolledinventory.ErrGroupAssigned) {
		t.Fatalf("assigned deletion: %v", err)
	}
	// A peer-created member still protects the group even when this cache lacks it.
	if _, _, err := l.SetGroupContext(ctx, "target", "tenant_a", "", now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := l.SetGroupContext(ctx, "new-member", "tenant_a", "", now); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.ReloadFromStore(); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.EnrollGroup("late-member", "tenant_a", "Renamed", "", now); err != nil {
		t.Fatal(err)
	}
	before, _ := p.Load()
	if _, _, err := l.DeleteGroupContext(ctx, g.ID, "tenant_a", false); !errors.Is(err, enrolledinventory.ErrGroupAssigned) {
		t.Fatal(err)
	}
	after, _ := p.Load()
	if !bytes.Equal(before, after) {
		t.Fatal("refused delete wrote")
	}
	if _, _, err := l.SetGroupContext(ctx, "late-member", "tenant_a", "", now); err != nil {
		t.Fatal(err)
	}
	if ok, _, err := l.DeleteGroupContext(ctx, g.ID, "tenant_a", false); !ok || err != nil {
		t.Fatalf("delete %v %v", ok, err)
	}
	if _, _, err := l.SetKindContext(ctx, "target", "tenant_a", enrolledinventory.KindService, now); err != nil {
		t.Fatal(err)
	}
	if err := l.RecordReportedMachineContext(ctx, "target", "tenant_a", "machine-one", now); err != nil {
		t.Fatal(err)
	}
	tomb, err := l.RemoveCheckedContext(ctx, "target", "tenant_a", now)
	if err != nil || tomb.RemovedAt == "" || tomb.Enabled {
		t.Fatalf("tombstone %+v %v", tomb, err)
	}
	if _, err := l.EnrollGroupForTenantContext(ctx, "target", "tenant_a", "tenant_a", "", "", now, false); !errors.Is(err, enrolledinventory.ErrIdentityRemoved) {
		t.Fatal(err)
	}
	restored, previous, err := l.AllowReenrolmentContext(ctx, "target", "tenant_a", now)
	if err != nil || previous.RemovedAt == "" || restored.RemovedAt != "" || restored.ReenrolmentNonce != previous.ReenrolmentNonce+1 {
		t.Fatalf("rearm before=%+v after=%+v err=%v", previous, restored, err)
	}
	// Even a stale cached owner is not authority to mutate a newly transferred row.
	raw, _ := p.Load()
	var snap map[string]json.RawMessage
	json.Unmarshal(raw, &snap)
	var entries map[string]enrolledinventory.Entry
	json.Unmarshal(snap["entries"], &entries)
	e := entries["target"]
	e.TenantID = "tenant_b"
	entries["target"] = e
	snap["entries"], _ = json.Marshal(entries)
	raw, _ = json.Marshal(snap)
	if err := p.Save(raw); err != nil {
		t.Fatal(err)
	}
	if _, err := l.RemoveCheckedContext(ctx, "target", "tenant_a", now); !errors.Is(err, enrolledinventory.ErrIdentityNotFound) {
		t.Fatal("latest tenant removal", err)
	}
	a.release()
	b.tick()
	if !b.IsLeader() {
		t.Fatal("peer")
	}
	before, _ = p.Load()
	generation := l.ConfigGeneration()
	calls := []func() error{
		func() error {
			_, e := l.EnrollGroupForTenantContext(ctx, "new", "tenant_a", "tenant_a", "", "", now, false)
			return e
		},
		func() error { _, _, e := l.AllowReenrolmentContext(ctx, "target", "tenant_b", now); return e },
		func() error { _, _, e := l.SetGroupContext(ctx, "target", "tenant_b", "other", now); return e },
		func() error {
			_, _, e := l.SetKindContext(ctx, "target", "tenant_b", enrolledinventory.KindEndpoint, now)
			return e
		},
		func() error { _, e := l.RemoveCheckedContext(ctx, "target", "tenant_b", now); return e },
		func() error { return l.RecordReportedMachineContext(ctx, "target", "tenant_b", "new-machine", now) },
		func() error { _, e := l.CreateGroupContext(ctx, "Denied", "tenant_b", "", "", now); return e },
		func() error { _, _, e := l.UpdateGroupContext(ctx, g.ID, "tenant_b", &name, nil, nil, now); return e },
		func() error { _, _, e := l.DeleteGroupContext(ctx, g.ID, "tenant_b", true); return e },
	}
	for i, call := range calls {
		if e := call(); !errors.Is(e, enrolledinventory.ErrInventorySave) {
			t.Fatalf("stale method %d: %v", i, e)
		}
	}
	after, _ = p.Load()
	if !bytes.Equal(before, after) || l.ConfigGeneration() != generation {
		t.Fatal("stale methods modified state")
	}
	reloaded := enrolledinventory.NewLedger()
	if err := reloaded.SetPersisterChecked(p); err != nil {
		t.Fatal(err)
	}
	if e, ok := reloaded.EntryFor("foreign"); !ok || e.Group != "Pilot" || e.TenantID != "tenant_b" {
		t.Fatalf("lost foreign: %+v", e)
	}
}
