package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
)

// The archive is shared at the S3 layer. Customer administrators must still be
// confined to their own tenant when the Console asks the CP to inspect it.
func TestAuditArchiveCustomerCannotSelectAnotherTenant(t *testing.T) {
	const customer = "tenant_customer"
	const foreign = "tenant_foreign"
	const operator = "tenant_operator"
	declareOperatorTenantForTest(t, operator)

	foreignSegment, _ := buildAuditSegment(0, "", [][]byte{[]byte(`{"event":"foreign"}`)})
	arc := &fakeArchive{objs: map[string][]byte{
		"hot_events/" + foreign + "/audit/2026-01-01.ndjson.gz": foreignSegment,
	}}
	auth := newAdminAuthStore()
	for _, principal := range []struct {
		id, tenant string
		roles      []string
	}{
		{"customer-admin", customer, []string{"admin"}},
		{"customer-super", customer, []string{"admin", "super_admin"}},
		{"operator-super", operator, []string{"admin", "super_admin"}},
	} {
		auth.UpsertPrincipal(adminPrincipal{ID: principal.id, TenantID: principal.tenant, Roles: principal.roles, Status: "active"})
		auth.UpsertSession(adminSession{ID: principal.id + "-session", TenantID: principal.tenant,
			AdminPrincipalID: principal.id, Roles: principal.roles, Status: "active",
			ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
		auth.UpsertAPIToken(adminAPIToken{ID: principal.id + "-token", TenantID: principal.tenant,
			TokenHash: adminTokenHash(principal.id + "-secret"), Roles: principal.roles,
			Scopes: []string{"admin.retention.read"}, CreatedByAdminPrincipalID: principal.id,
			Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer,
		AdminAuth: auth, ColdArchive: arc, OperatorTenantID: operator})

	verify := func(id string, bearer, override bool, wantStatus int) auditChainVerifyResult {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/admin/audit-chain/verify?tenant_id="+foreign, nil)
		if bearer {
			req.Header.Set("Authorization", "Bearer "+id+"-secret")
		} else {
			req.AddCookie(&http.Cookie{Name: "admin_session", Value: id + "-session"})
		}
		if override {
			req.Header.Set("X-Operate-Tenant", foreign)
		}
		response := httptest.NewRecorder()
		h.ServeHTTP(response, req)
		if response.Code != wantStatus {
			t.Fatalf("%s status %d: %s", id, response.Code, response.Body.String())
		}
		if wantStatus != http.StatusOK {
			return auditChainVerifyResult{}
		}
		var result auditChainVerifyResult
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	for _, id := range []string{"customer-admin", "customer-super"} {
		for _, bearer := range []bool{false, true} {
			verify(id, bearer, true, http.StatusForbidden)
			result := verify(id, bearer, false, http.StatusOK)
			if result.Tenant != customer || result.Segments != 0 || result.Status != "empty" {
				t.Fatalf("%s bearer=%t crossed into another tenant's archive: %+v", id, bearer, result)
			}
		}
	}
	result := verify("operator-super", false, true, http.StatusOK)
	if result.Tenant != foreign || result.Segments != 1 || !result.OK {
		t.Fatalf("designated operator could not inspect the selected tenant: %+v", result)
	}
}
