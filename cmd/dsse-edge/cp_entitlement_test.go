package main

import (
	"bytes"
	"context"
	"github.com/lantern-networks/dsse-core/logs"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPostgresEntitlementPeerAndAcceptedTerm(t *testing.T) {
	a, b := postgresFailureElectors(t)
	db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), "../../migrations", true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p := postgresBlobPersister{db: db, key: "entitlements"}
	// This suite uses an isolated disposable database, like the other shared-store acceptance tests.
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
	fresh := func() *entitlementStore {
		s := newEntitlementStore(nil)
		if err := s.SetPersister(p); err != nil {
			t.Fatal(err)
		}
		return s
	}
	first, peer := fresh(), fresh()
	tenant := testEvaluator().PolicyBundle.TenantID
	if err := first.SetFeaturesContext(context.Background(), tenant, map[string]bool{featureDLP: true}); err != nil {
		t.Fatal(err)
	}
	if err := peer.SetFeaturesContext(context.Background(), "foreign", map[string]bool{featureDLP: true}); err != nil {
		t.Fatal(err)
	}
	if !fresh().Entitled(tenant, featureDLP) {
		t.Fatal("stale peer erased tenant")
	}
	now := time.Now()
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "entitlement-admin", TenantID: tenant, Roles: []string{"admin", "super_admin"}, Status: "active"})
	auth.UpsertSession(adminSession{ID: "entitlement-session", TenantID: tenant, AdminPrincipalID: "entitlement-admin", Roles: []string{"admin", "super_admin"}, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "entitlement-csrf"}})
	w, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	oldDB := cpStateBlobDB
	cpStateBlobDB = db
	defer func() { cpStateBlobDB = oldDB }()
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: w, AdminAuth: auth, OperatorTenantID: tenant, EntitlementStorePath: "postgres"})
	old := cpLeaderElectorInstance
	cpLeaderElectorInstance = a
	defer func() { cpLeaderElectorInstance = old }()
	a.tick()
	before, err := p.Load()
	if err != nil {
		t.Fatal(err)
	}
	body := &pausedSeatBody{Reader: strings.NewReader(`{"features":{"dlp":false}}`), entered: make(chan struct{}), resume: make(chan struct{})}
	req := httptest.NewRequest("PUT", "/admin/entitlements", body)
	req.AddCookie(&http.Cookie{Name: "admin_session", Value: "entitlement-session"})
	req.Header.Set("X-CSRF-Token", "entitlement-csrf")
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { defer close(done); h.ServeHTTP(rec, req) }()
	select {
	case <-body.entered:
	case <-done:
		t.Fatalf("body unread %d %s", rec.Code, rec.Body)
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
	after, err := p.Load()
	if err != nil {
		t.Fatal(err)
	}
	if rec.Code != 500 || !bytes.Equal(before, after) {
		t.Fatalf("stale accepted %d %s", rec.Code, rec.Body)
	}
	request := func(method, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/admin/entitlements", strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: "admin_session", Value: "entitlement-session"})
		req.Header.Set("X-CSRF-Token", "entitlement-csrf")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}
	if rr := request("PUT", `{"features":{"dlp":false}}`); rr.Code != 200 {
		t.Fatalf("fresh request %d %s", rr.Code, rr.Body)
	}
	restored := fresh()
	if restored.Entitled(tenant, featureDLP) || !restored.Entitled("foreign", featureDLP) {
		t.Fatal("restart mismatch")
	}
	if err := peer.SetFeaturesContext(captureCPWriteLease(context.Background()), tenant, map[string]bool{featureDLP: true}); err != nil {
		t.Fatal(err)
	}
	if rr := request("GET", ""); rr.Code != 200 || !strings.Contains(rr.Body.String(), `"dlp":true`) {
		t.Fatalf("read stale %d %s", rr.Code, rr.Body)
	}
	outcomes := map[string]int{}
	for _, row := range readTransportAudits(t, w) {
		if row.EventType == "admin_config_change" && row.TargetID != nil && *row.TargetID == "/admin/entitlements" {
			if row.ActorUserID == nil || *row.ActorUserID != "entitlement-admin" || row.TenantID != tenant {
				t.Fatal("audit identity mismatch")
			}
			if row.Result != nil {
				outcomes[*row.Result]++
			}
		}
	}
	if outcomes["error"] != 1 || outcomes["success"] != 1 {
		t.Fatalf("audit outcomes: %v", outcomes)
	}
}
