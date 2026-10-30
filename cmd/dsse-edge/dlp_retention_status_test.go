package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/dlp"
	"github.com/lantern-networks/dsse-core/logs"
)

func TestDLPRetentionStatusRequiresOperatorAndReturnsEffectiveProcessBudget(t *testing.T) {
	prior := operatorTenantConfigured()
	t.Cleanup(func() { declareOperatorTenant(prior, false) })
	auth := newAdminAuthStore()
	now := time.Now().UTC()
	for _, tenant := range []string{"operator", "customer"} {
		auth.UpsertPrincipal(adminPrincipal{ID: tenant, TenantID: tenant, Roles: []string{"owner"}, Status: "active"})
		auth.UpsertAPIToken(adminAPIToken{ID: tenant, TenantID: tenant, TokenHash: adminTokenHash(tenant), Roles: []string{"owner"}, Scopes: []string{"admin.state.read"}, CreatedByAdminPrincipalID: tenant, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	budget := dlp.DefaultRetentionBudget()
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, OperatorTenantID: "operator", DLPRetentionBudget: budget, LabMode: boolPtr(false)})
	for _, tenant := range []string{"operator", "customer", ""} {
		r := httptest.NewRequest(http.MethodGet, "/admin/dlp-retention-status?tenant_id=operator", nil)
		if tenant != "" {
			r.Header.Set("Authorization", "Bearer "+tenant)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if tenant != "operator" {
			if w.Code != http.StatusForbidden && w.Code != http.StatusUnauthorized {
				t.Fatalf("non-operator read process usage: %q status=%d", tenant, w.Code)
			}
			continue
		}
		var got dlp.RetentionStatus
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &got) != nil || got != budget.Status() {
			t.Fatalf("operator did not receive effective process budget: status=%d", w.Code)
		}
	}
}
