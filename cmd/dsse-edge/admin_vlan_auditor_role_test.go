package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNetworkAuditorCanReadButCannotChangeCatalog(t *testing.T) {
	tenant := testEvaluator().PolicyBundle.TenantID
	auth := newAdminAuthStore()
	now := time.Now().UTC()
	auth.UpsertPrincipal(adminPrincipal{ID: "network-auditor", TenantID: tenant, Roles: []string{"auditor"}, Status: "active"})
	auth.UpsertAPIToken(adminAPIToken{
		ID: "network-audit-token", TenantID: tenant, TokenHash: adminTokenHash("fixture-network-reader"),
		Roles: []string{"auditor"}, Scopes: []string{"*"}, CreatedByAdminPrincipalID: "network-auditor",
		CreatedAt: now.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Status: "active",
	})
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: auth})
	call := func(method, path, body string, want int) string {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer fixture-network-reader")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("%s %s status %d want %d: %s", method, path, rec.Code, want, rec.Body)
		}
		return rec.Body.String()
	}
	call(http.MethodGet, "/admin/vlan-objects", "", http.StatusOK)
	call(http.MethodPost, "/admin/vlan-objects", `{"id":"forbidden","name":"Forbidden","class":"server","cidrs":["192.0.2.0/24"]}`, http.StatusForbidden)
	call(http.MethodDelete, "/admin/vlan-objects/forbidden", "", http.StatusForbidden)
	if body := call(http.MethodGet, "/admin/vlan-objects", "", http.StatusOK); strings.Contains(body, "forbidden") {
		t.Fatalf("read-only network request changed catalog: %s", body)
	}
}
