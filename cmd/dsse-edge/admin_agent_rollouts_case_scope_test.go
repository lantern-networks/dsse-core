package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentrollout"
	"github.com/lantern-networks/dsse-core/logs"
)

func TestAgentRolloutsCaseDistinctCustomerCannotReadDeploymentPlans(t *testing.T) {
	declareOperatorTenantForTest(t, "Acme")
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "customer_admin", TenantID: "acme", Roles: []string{"admin"}, Status: "active"})
	auth.UpsertSession(adminSession{ID: "customer_session", TenantID: "acme", AdminPrincipalID: "customer_admin", Roles: []string{"admin"}, Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
	auth.UpsertPrincipal(adminPrincipal{ID: "operator_admin", TenantID: "Acme", Roles: []string{"admin"}, Status: "active"})
	auth.UpsertSession(adminSession{ID: "operator_session", TenantID: "Acme", AdminPrincipalID: "operator_admin", Roles: []string{"admin"}, Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
	plans := agentrollout.NewAgentRolloutStore()
	if err := plans.Set("acme", agentrollout.AgentRolloutPlan{Intent: agentrollout.AgentRolloutIntentFreeze, Frozen: true, Reason: "customer hold"}); err != nil {
		t.Fatal(err)
	}
	if err := plans.Set("private_other", agentrollout.AgentRolloutPlan{Intent: agentrollout.AgentRolloutIntentFreeze, Frozen: true, Reason: "other hold"}); err != nil {
		t.Fatal(err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	handler := newServerWithConfig(serverConfig{Writer: writer, Evaluator: testEvaluator(), AdminAuth: auth, AgentRolloutPlans: plans, OperatorTenantID: "Acme"})
	if got := operatorTenantConfigured(); got != "Acme" {
		t.Fatalf("operator tenant changed during server construction: %q", got)
	}
	if snapshot, err := plans.SnapshotChecked(); err != nil || len(snapshot) != 2 {
		t.Fatalf("rollout fixture missing: %v, %v", snapshot, err)
	}
	req := httptest.NewRequest(http.MethodGet, "/admin/agent-rollouts", nil)
	req.AddCookie(&http.Cookie{Name: "admin_session", Value: "customer_session"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Tenants map[string]json.RawMessage `json:"tenants"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Tenants) != 1 || body.Tenants["acme"] == nil {
		t.Fatalf("case-distinct customer saw deployment rollout plans: %s", rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/admin/agent-rollouts", nil)
	req.AddCookie(&http.Cookie{Name: "admin_session", Value: "operator_session"})
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("operator status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Tenants) != 2 {
		t.Fatalf("operator could not read deployment rollout plans: %s", rec.Body.String())
	}
}
