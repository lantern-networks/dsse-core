package main

import (
	"context"
	"encoding/json"
	"github.com/lantern-networks/dsse-core/grantstore"
	"github.com/lantern-networks/dsse-core/logs"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPostgresGrantPeerTermReportReadAndAudit(t *testing.T) {
	leader, peer := postgresFailureElectors(t)
	db, e := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), "../../migrations", true)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	oldE, oldCP := cpLeaderElectorInstance, edgeIsControlPlane
	defer func() { cpLeaderElectorInstance = oldE; edgeIsControlPlane = oldCP }()
	cpLeaderElectorInstance = nil
	edgeIsControlPlane = true
	p := postgresBlobPersister{db: db, key: "grants"}
	saved, e := p.Load()
	if e != nil {
		t.Fatal(e)
	}
	db.Exec("DELETE FROM cp_state_blobs WHERE store_key='grants'")
	defer func() {
		if saved == nil {
			db.Exec("DELETE FROM cp_state_blobs WHERE store_key='grants'")
		} else {
			db.Exec("INSERT INTO cp_state_blobs(store_key,payload)VALUES('grants',$1)ON CONFLICT(store_key)DO UPDATE SET payload=$1", saved)
		}
	}()
	writer, e := logs.NewWriter(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer writer.Close()
	auth := newAdminAuthStore()
	tenant := "tenant_lab_001"
	now := time.Now().UTC()
	auth.UpsertPrincipal(adminPrincipal{ID: "grant-admin", TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
	auth.UpsertSession(adminSession{ID: "grant-session", TenantID: tenant, AdminPrincipalID: "grant-admin", Roles: []string{"admin"}, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "grant-csrf"}})
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth})
	a := theGrantStore.Load()
	gate := &runtimeLeaseGate{postgresBlobPersister: p}
	if e = a.SetPersister(gate); e != nil {
		t.Fatal(e)
	}
	b := grantstore.NewStore()
	if e = b.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	if _, e = a.Mint(grantstore.Grant{GrantID: "own", TenantID: tenant}, time.Hour, now); e != nil {
		t.Fatal(e)
	}
	if _, e = b.Mint(grantstore.Grant{GrantID: "foreign", TenantID: "other"}, time.Hour, now); e != nil {
		t.Fatal(e)
	}
	cpLeaderElectorInstance = leader
	leader.tick()
	if !leader.IsLeader() {
		t.Fatal("leader")
	}
	rotate := func() {
		leader.release()
		peer.tick()
		if !peer.IsLeader() {
			t.Fatal("peer")
		}
		peer.release()
		leader.tick()
		if !leader.IsLeader() {
			t.Fatal("reacquire")
		}
	}
	call := func(method, path string, want int) {
		t.Helper()
		r := httptest.NewRequest(method, path, nil)
		r.AddCookie(&http.Cookie{Name: "admin_session", Value: "grant-session"})
		r.Header.Set("X-CSRF-Token", "grant-csrf")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s: %d want %d: %s", path, w.Code, want, w.Body)
		}
	}
	gate.before = rotate
	call("POST", "/admin/grants/own/revoke", 500)
	if a.Valid("own", now) {
		t.Fatal("pre-callback refusal lost local denial")
	}
	if !b.Valid("own", now) {
		t.Fatal("old revoke applied")
	}
	old := captureCPWriteLease(context.Background())
	rotate()
	if _, e = b.MintContext(old, grantstore.Grant{GrantID: "old-mint", TenantID: tenant}, time.Hour, now); e == nil {
		t.Fatal("old mint accepted")
	}
	gate.before = nil
	call("POST", "/admin/grants/own/revoke", 200)
	call("POST", "/admin/grants/foreign/revoke", 404)
	if b.Valid("own", now) || !b.Valid("foreign", now) {
		t.Fatal("revocation/peer state")
	}
	reportMux := http.NewServeMux()
	registerGrantReportRoute(reportMux, a, nil, "", true)
	g := grantstore.Grant{GrantID: "reported", TenantID: tenant, IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)}
	raw, _ := json.Marshal(map[string]any{"grants": []grantstore.Grant{g}})
	for _, oldRequest := range []bool{true, false} {
		reader := &enrolmentTermBody{Reader: strings.NewReader(string(raw))}
		want := 200
		if oldRequest {
			reader.before = rotate
			want = 500
		}
		r := httptest.NewRequest("POST", "/grant-report", reader)
		w := httptest.NewRecorder()
		reportMux.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("report %d want %d %s", w.Code, want, w.Body)
		}
	}
	if section := grantBundleSection(b); !section.Complete || len(section.Grants) != 3 {
		t.Fatal("bundle missing peer")
	}
	if n, e := a.RemoveTenantContext(captureCPWriteLease(context.Background()), tenant); e != nil || n != 2 {
		t.Fatal("erase", n, e)
	}
	if rows, e := b.ListAllChecked(); e != nil || len(rows) != 1 || rows[0].GrantID != "foreign" {
		t.Fatal("foreign erased", e)
	}
	db.Exec("UPDATE cp_state_blobs SET payload='null' WHERE store_key='grants'")
	call("GET", "/admin/grants", 503)
	if section := grantBundleSection(a); section.Complete {
		t.Fatal("unavailable bundle marked complete")
	}
	audits, e := writer.ReadJSONL("audit.log.jsonl")
	if e != nil {
		t.Fatal(e)
	}
	good, bad, partial := 0, 0, 0
	for _, r := range audits {
		if r["event_type"] == "admin_access_grant_revoked" && r["result"] == "partial" {
			partial++
		}
		if r["event_type"] == "admin_config_change" {
			if r["result"] == "success" {
				good++
			} else {
				bad++
			}
		}
	}
	if good != 1 || bad != 2 || partial != 1 {
		t.Fatalf("audit successes %d errors %d partial %d", good, bad, partial)
	}
}
