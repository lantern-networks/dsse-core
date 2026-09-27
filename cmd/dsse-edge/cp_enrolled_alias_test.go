package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/logs"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPostgresEnrolledAliasPeerAndAcceptedTerm(t *testing.T) {
	a, b := postgresFailureElectors(t)
	db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), "../../migrations", true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p := postgresBlobPersister{db: db, key: "test_enrolled_alias"}
	db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
	defer db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
	devices := []assetcatalog.EnrolledDevice{{Identity: "verified-device", Name: "original", Platform: "macos"}}
	fresh := func() *assetcatalog.Store {
		s := assetcatalog.NewStore()
		if err := s.SetPersister(p); err != nil {
			t.Fatal(err)
		}
		s.SyncEnrolledEndpoints("tenant_lab_001", devices, time.Now())
		return s
	}
	first, peer := fresh(), fresh()
	ep := first.ListEndpoints("tenant_lab_001")[0]
	ep.Alias = "peer-name"
	if _, err := first.UpsertEndpointContext(context.Background(), ep); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.UpsertGroup(assetcatalog.Group{TenantID: "foreign", ID: "kept", Alias: "foreign-group"}); err != nil {
		t.Fatal(err)
	}
	if err := peer.RefreshShared(); err != nil {
		t.Fatal(err)
	}
	if got, _ := peer.GetEndpoint(ep.TenantID, ep.ID); got.Alias != "peer-name" {
		t.Fatal("peer rename lost")
	}
	if got, _ := fresh().GetEndpoint(ep.TenantID, ep.ID); got.Alias != "peer-name" {
		t.Fatal("restart lost rename")
	}
	now := time.Now()
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "alias-admin", TenantID: ep.TenantID, Roles: []string{"admin"}, Status: "active"})
	auth.UpsertSession(adminSession{ID: "alias-session", TenantID: ep.TenantID, AdminPrincipalID: "alias-admin", Roles: []string{"admin"}, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "alias-csrf"}})
	w, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: w, AdminAuth: auth, AssetStore: first})
	old := cpLeaderElectorInstance
	cpLeaderElectorInstance = a
	defer func() { cpLeaderElectorInstance = old }()
	a.tick()
	ep.Alias = "stale-request"
	data, _ := json.Marshal(ep)
	before, _ := p.Load()
	body := &pausedSeatBody{Reader: strings.NewReader(string(data)), entered: make(chan struct{}), resume: make(chan struct{})}
	req := httptest.NewRequest("POST", "/admin/assets/endpoints", body)
	req.AddCookie(&http.Cookie{Name: "admin_session", Value: "alias-session"})
	req.Header.Set("X-CSRF-Token", "alias-csrf")
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
		t.Fatal("peer did not acquire")
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
	after, _ := p.Load()
	if rec.Code != 500 || !bytes.Equal(before, after) {
		t.Fatalf("stale rename accepted: %d %s", rec.Code, rec.Body)
	}
	ep.Alias = "fresh-request"
	if _, err := first.UpsertEndpointContext(captureCPWriteLease(context.Background()), ep); err != nil {
		t.Fatal(err)
	}
	reader := fresh()
	if got, _ := reader.GetEndpoint(ep.TenantID, ep.ID); got.Alias != "fresh-request" {
		t.Fatal("fresh rename lost")
	}
	if len(reader.ListGroups("foreign")) != 1 {
		t.Fatal("foreign group lost")
	}
}

func TestAdminEnrolledEndpointRejectsIdentityReplacement(t *testing.T) {
	s := assetcatalog.NewStore()
	ep := s.SyncEnrolledEndpoints("tenant_lab_001", []assetcatalog.EnrolledDevice{{Identity: "verified", Name: "original", Platform: "macos"}}, time.Now())[0]
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: newAdminAuthStore(), AssetStore: s})
	changed := ep
	changed.Identity = "forged"
	data, _ := json.Marshal(changed)
	rr := doAdmin(t, h, http.MethodPost, "/admin/assets/endpoints", string(data))
	if rr.Code != 400 {
		t.Fatalf("identity mutation: %d %s", rr.Code, rr.Body)
	}
	rr = doAdmin(t, h, http.MethodDelete, "/admin/assets/endpoints/"+ep.ID, "")
	if rr.Code != 400 {
		t.Fatalf("delete inventory endpoint: %d %s", rr.Code, rr.Body)
	}
	got, _ := s.GetEndpoint(ep.TenantID, ep.ID)
	if got.Identity != ep.Identity {
		t.Fatal("identity changed")
	}
}
