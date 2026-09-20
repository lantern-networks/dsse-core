package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/vlan"
)

func TestPostgresNetworkSharedPeerAndAcceptedTerm(t *testing.T) {
	a, b := postgresFailureElectors(t)
	db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), "../../migrations", true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p := postgresBlobPersister{db: db, key: "vlan_objects"}
	saved, err := p.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if saved != nil {
			p.Save(saved)
		} else {
			db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
		}
	}()
	x, y := vlan.NewStore(), vlan.NewStore()
	for _, s := range []*vlan.Store{x, y} {
		if e := s.SetPersister(p); e != nil {
			t.Fatal(e)
		}
	}
	for id, s := range map[string]*vlan.Store{"first": x, "foreign": y} {
		if _, e := s.UpsertObject(model.VLANObject{ID: id, TenantID: id, Class: "server", CIDRs: []string{"10.1.0.0/24"}}); e != nil {
			t.Fatal(e)
		}
		if _, e := s.UpsertPolicy(model.VLANBoundaryPolicy{ID: id, TenantID: id, SourceClass: "server", DestClass: "server", Mode: "observe"}); e != nil {
			t.Fatal(e)
		}
	}
	if e := x.RefreshShared(); e != nil || len(x.ListObjects()) != 2 || len(x.ListPolicies()) != 2 {
		t.Fatalf("peer lost: %v", e)
	}
	tenant := testEvaluator().PolicyBundle.TenantID
	now := time.Now()
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "network-admin", TenantID: tenant, Roles: []string{"admin", "super_admin"}, Status: "active"})
	auth.UpsertSession(adminSession{ID: "network-session", TenantID: tenant, AdminPrincipalID: "network-admin", Roles: []string{"admin", "super_admin"}, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "network-csrf"}})
	w, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	oldDB, oldE := cpStateBlobDB, cpLeaderElectorInstance
	cpStateBlobDB = db
	defer func() { cpStateBlobDB, cpLeaderElectorInstance = oldDB, oldE }()
	config := serverConfig{Evaluator: testEvaluator(), Writer: w, AdminAuth: auth, OperatorTenantID: tenant, VLANObjectStorePath: "postgres"}
	h := newServerWithConfig(config)
	cpLeaderElectorInstance = a
	a.tick()
	request := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.AddCookie(&http.Cookie{Name: "admin_session", Value: "network-session"})
		r.Header.Set("X-CSRF-Token", "network-csrf")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, r)
		return rr
	}
	for _, c := range []struct{ path, body string }{
		{"/admin/vlan-objects", `{"id":"current","class":"server","cidrs":["10.2.0.0/24"]}`},
		{"/admin/vlan-boundary-policies", `{"id":"current","source_class":"server","dest_class":"server","mode":"observe"}`},
	} {
		before, e := p.Load()
		if e != nil {
			t.Fatal(e)
		}
		body := &pausedSeatBody{Reader: strings.NewReader(c.body), entered: make(chan struct{}), resume: make(chan struct{})}
		r := httptest.NewRequest("POST", c.path, body)
		r.AddCookie(&http.Cookie{Name: "admin_session", Value: "network-session"})
		r.Header.Set("X-CSRF-Token", "network-csrf")
		rr := httptest.NewRecorder()
		done := make(chan struct{})
		go func() { defer close(done); h.ServeHTTP(rr, r) }()
		select {
		case <-body.entered:
		case <-done:
			t.Fatalf("body unread %d", rr.Code)
		case <-time.After(5 * time.Second):
			t.Fatal("body timeout")
		}
		a.release()
		b.tick()
		if !b.IsLeader() {
			t.Fatal("peer election failed")
		}
		b.release()
		a.tick()
		if !a.IsLeader() {
			t.Fatal("reacquire failed")
		}
		close(body.resume)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("response timeout")
		}
		after, e := p.Load()
		if e != nil {
			t.Fatal(e)
		}
		if rr.Code != 503 || !bytes.Equal(before, after) {
			t.Fatalf("old term accepted: %d %s", rr.Code, rr.Body)
		}
		if rr := request("POST", c.path, c.body); rr.Code != 200 {
			t.Fatalf("fresh %d %s", rr.Code, rr.Body)
		}
	}
	// Deletion and tenant purge must check the same admitted term, even if the cache is stale.
	stale := captureCPWriteLease(context.Background())
	a.release()
	b.tick()
	b.release()
	a.tick()
	if _, e := x.DeleteObjectContext(stale, "current", nil); e == nil {
		t.Fatal("stale delete accepted")
	}
	if _, _, e := x.RemoveTenantContext(stale, tenant); e == nil {
		t.Fatal("stale purge accepted")
	}
	// Publisher refreshes peer changes without a prior management list.
	rr := request("GET", "/admin/config-bundle", "")
	var previous configBundlePayload
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &previous) != nil {
		t.Fatalf("bundle %d %s", rr.Code, rr.Body)
	}
	if _, e := y.UpsertObject(model.VLANObject{ID: "bundle-peer", TenantID: "foreign", Class: "server", CIDRs: []string{"10.3.0.0/24"}}); e != nil {
		t.Fatal(e)
	}
	rr = request("GET", "/admin/config-bundle", "")
	var next configBundlePayload
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &next) != nil || next.VLAN == nil || len(next.VLAN.Objects) != 4 || next.Generation <= previous.Generation {
		t.Fatalf("stale bundle: %d %s", rr.Code, rr.Body)
	}
	// A stale store's purge edits only the target tenant from the latest row.
	if objects, policies, e := x.RemoveTenantContext(captureCPWriteLease(context.Background()), "first"); e != nil || objects != 1 || policies != 1 {
		t.Fatalf("purge %d %d %v", objects, policies, e)
	}
	if rr := request("DELETE", "/admin/vlan-objects/current", ""); rr.Code != 200 {
		t.Fatalf("delete %d %s", rr.Code, rr.Body)
	}
	h = newServerWithConfig(config)
	rr = request("GET", "/admin/vlan-objects", "")
	if rr.Code != 200 || strings.Contains(rr.Body.String(), `"id":"current"`) || strings.Contains(rr.Body.String(), `"id":"first"`) || !strings.Contains(rr.Body.String(), "bundle-peer") {
		t.Fatalf("restart %d %s", rr.Code, rr.Body)
	}
	raw, e := p.Load()
	if e != nil {
		t.Fatal(e)
	}
	if e = p.Save([]byte(`{}`)); e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{"/admin/vlan-objects", "/admin/vlan-boundary-policies", "/admin/vlan-boundary-policies/export", "/admin/config-bundle"} {
		if rr := request("GET", path, ""); rr.Code != 503 {
			t.Fatalf("corrupt authority %s %d", path, rr.Code)
		}
	}
	if e = p.Save(raw); e != nil {
		t.Fatal(e)
	}
	outcomes := map[string]int{}
	for _, row := range readTransportAudits(t, w) {
		if row.EventType == "admin_config_change" && row.TargetID != nil && strings.HasPrefix(*row.TargetID, "/admin/vlan-") && row.Result != nil {
			outcomes[*row.Result]++
		}
	}
	if outcomes["error"] != 2 || outcomes["success"] != 3 {
		t.Fatalf("audit mismatch %v", outcomes)
	}
}
