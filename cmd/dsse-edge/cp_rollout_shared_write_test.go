package main

import (
	"context"
	"github.com/lantern-networks/dsse-core/agentrollout"
	"github.com/lantern-networks/dsse-core/logs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPostgresRolloutPreservesPeerHaltAndPlans(t *testing.T) {
	db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), filepath.Join("..", "..", "migrations"), true)
	if os.Getenv("POSTGRES_QUEUE_E2E_DSN") == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p := postgresBlobPersister{db: db, key: "test_rollout_shared"}
	db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
	defer db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
	fresh := func() *agentrollout.AgentRolloutStore {
		s := agentrollout.NewAgentRolloutStore()
		if err := s.LoadFromPersister(p); err != nil {
			t.Fatal(err)
		}
		return s
	}
	author, stale := fresh(), fresh()
	now := time.Now()
	if _, err := author.Apply("target", agentrollout.AgentRolloutPlan{Intent: agentrollout.AgentRolloutIntentFreeze, Frozen: true, Reason: "incident"}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := author.Apply("foreign", agentrollout.AgentRolloutPlan{Intent: agentrollout.AgentRolloutIntentFreeze, Frozen: true, Reason: "foreign incident"}, now); err != nil {
		t.Fatal(err)
	}
	if got := stale.Get("target"); !got.Frozen {
		t.Error("a second CP answered not frozen after the halt was saved")
	}
	if _, err := stale.Apply("target", agentrollout.AgentRolloutPlan{Intent: agentrollout.AgentRolloutIntentSchedule}, now); err != nil {
		t.Fatal(err)
	}
	reloaded := fresh()
	if !reloaded.Get("target").Frozen || !reloaded.Get("foreign").Frozen {
		t.Fatal("schedule edit erased the incident hold or foreign plan")
	}
}

func TestPostgresRolloutOldRequestAndCorruptRead(t *testing.T) {
	a, b := postgresFailureElectors(t)
	db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), "../../migrations", true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p := postgresBlobPersister{db: db, key: "test_rollout_request"}
	db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
	defer db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
	plans := agentrollout.NewAgentRolloutStore()
	if err := plans.LoadFromPersister(p); err != nil {
		t.Fatal(err)
	}
	old := cpLeaderElectorInstance
	cpLeaderElectorInstance = a
	defer func() { cpLeaderElectorInstance = old }()
	a.tick()
	now := time.Now()
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "review", TenantID: "tenant_lab_001", Roles: []string{"admin"}, Status: "active"})
	auth.UpsertSession(adminSession{ID: "rollout-session", TenantID: "tenant_lab_001", AdminPrincipalID: "review", Roles: []string{"admin"}, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "rollout-csrf"}})
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	handler := newServerWithConfig(serverConfig{Writer: writer, Evaluator: testEvaluator(), AdminAuth: auth, AgentRolloutPlans: plans})
	body := &pausedSeatBody{Reader: strings.NewReader(`{"intent":"freeze","frozen":false,"reason":"resume"}`), entered: make(chan struct{}), resume: make(chan struct{})}
	req := httptest.NewRequest("PUT", "/admin/agent-rollout", body)
	req.AddCookie(&http.Cookie{Name: "admin_session", Value: "rollout-session"})
	req.Header.Set("X-CSRF-Token", "rollout-csrf")
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { defer close(done); handler.ServeHTTP(rec, req) }()
	select {
	case <-body.entered:
	case <-done:
		t.Fatalf("body not read: %d %s", rec.Code, rec.Body)
	case <-time.After(5 * time.Second):
		t.Fatal("body deadline")
	}
	lease := captureCPWriteLease(context.Background())
	a.release()
	b.tick()
	if !b.IsLeader() {
		t.Fatal("peer not elected")
	}
	peer := agentrollout.NewAgentRolloutStore()
	if err := peer.LoadFromPersister(p); err != nil {
		t.Fatal(err)
	}
	if err := peer.Set("tenant_lab_001", agentrollout.AgentRolloutPlan{Frozen: true, Reason: "peer hold", Intent: "freeze"}); err != nil {
		t.Fatal(err)
	}
	close(body.resume)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("request deadline")
	}
	if rec.Code != 500 || !strings.Contains(rec.Body.String(), agentrollout.ErrPersistence.Error()) || !plans.Get("tenant_lab_001").Frozen {
		t.Fatalf("stale request accepted: %d %s", rec.Code, rec.Body)
	}
	if _, err := plans.RemoveTenantContext(lease, "tenant_lab_001"); err == nil {
		t.Fatal("stale purge accepted")
	}
	b.release()
	a.tick()
	raw, _ := p.Load()
	if err := p.Save([]byte(`{"tenant_lab_001":{"intent":"freeze"}}`)); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/admin/agent-rollout", "/admin/agent-rollouts"} {
		req := httptest.NewRequest("GET", path, nil)
		req.AddCookie(&http.Cookie{Name: "admin_session", Value: "rollout-session"})
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != 503 {
			t.Fatalf("%s corrupt read = %d %s", path, rr.Code, rr.Body)
		}
	}
	if !plans.Get("tenant_lab_001").Frozen {
		t.Fatal("read failure released devices")
	}
	if _, err := plans.Apply("tenant_lab_001", agentrollout.AgentRolloutPlan{Intent: "schedule"}, now); err == nil {
		t.Fatal("corrupt store overwritten")
	}
	if err := p.Save(raw); err != nil {
		t.Fatal(err)
	}
	before, after, err := plans.ApplyContext(captureCPWriteLease(context.Background()), "tenant_lab_001", agentrollout.AgentRolloutPlan{Intent: "schedule"}, now)
	if err != nil || !before.Frozen || !after.Frozen {
		t.Fatalf("repair retry lost hold: %v", err)
	}
}
