package main

import (
	"context"
	"encoding/json"
	"github.com/lantern-networks/dsse-core/model"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func TestTenantSettingsAuthenticatedRolesAndSessionReload(t *testing.T) {
	now := time.Now()
	path := filepath.Join(t.TempDir(), "tenants.json")
	tenants := newOperatorAwareAdminTenantModelStore(model.PolicyBundle{TenantID: "customer"}, now, path, "operations")
	for _, id := range []string{"operations", "customer", "other"} {
		if _, err := tenants.Put(context.Background(), adminTenantModel{TenantID: id, DisplayName: id, Timezone: "UTC", Status: "active"}, now); err != nil {
			t.Fatal(err)
		}
	}
	auth := newAdminAuthStore()
	for _, a := range []struct{ id, tenant, role string }{{"admin", "customer", "admin"}, {"auditor", "customer", "auditor"}, {"operator", "operations", "super_admin"}, {"other", "other", "admin"}} {
		auth.UpsertPrincipal(adminPrincipal{ID: a.id, TenantID: a.tenant, Roles: []string{a.role}, Status: "active"})
		auth.UpsertAPIToken(adminAPIToken{ID: a.id, TenantID: a.tenant, TokenHash: adminTokenHash("synthetic-" + a.id), Roles: []string{a.role}, Scopes: []string{"*"}, CreatedByAdminPrincipalID: a.id, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
	}
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: auth, TenantModelStore: tenants, OperatorTenantID: "operations"})
	call := func(who, method, url, target string, body any, want int) string {
		t.Helper()
		code, raw := operatorEnvelopeCall(t, h, "synthetic-"+who, method, url, target, body)
		if code != want {
			t.Fatalf("%s %s %s: %d want %d %s", who, method, url, code, want, raw)
		}
		return raw
	}
	call("auditor", "GET", "/admin/tenant", "", nil, 200)
	call("auditor", "POST", "/admin/tenant", "", map[string]any{"timezone": "Asia/Tokyo"}, 403)
	call("other", "POST", "/admin/tenant", "customer", map[string]any{"timezone": "Asia/Tokyo"}, 403)
	call("operator", "POST", "/admin/tenant", "customer", map[string]any{"timezone": "Asia/Tokyo"}, 403)
	call("admin", "POST", "/admin/tenant", "", map[string]any{"timezone": "Asia/Tokyo"}, 200)
	call("admin", "POST", "/admin/tenant", "", map[string]any{"tenant_id": "other", "timezone": "Europe/Berlin"}, 400)
	delegate(t, tenants, "customer", true, false)
	call("operator", "POST", "/admin/tenant", "customer", map[string]any{"timezone": "Europe/Berlin"}, 200)
	delegate(t, tenants, "customer", false, false)
	call("operator", "POST", "/admin/tenant", "customer", map[string]any{"timezone": "UTC"}, 403)
	// A newly opened authority reads the persisted value; a session query must use
	// that value rather than the node's policy bundle default.
	reloaded := newOperatorAwareAdminTenantModelStore(model.PolicyBundle{TenantID: "customer"}, now, path, "operations")
	h = newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: auth, TenantModelStore: reloaded, OperatorTenantID: "operations"})
	for _, who := range []string{"admin", "auditor"} {
		raw := call(who, http.MethodGet, "/admin/session", "", nil, 200)
		var session map[string]any
		if err := json.Unmarshal([]byte(raw), &session); err != nil {
			t.Fatal(err)
		}
		if session["timezone"] != "Europe/Berlin" {
			t.Fatalf("%s stale session timezone %v", who, session["timezone"])
		}
	}
	other, err := reloaded.Get(context.Background(), "other")
	if err != nil || other.Timezone != "UTC" {
		t.Fatal("another tenant changed")
	}
}
