package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ★★★ BOTH DEVICES ON A WORKING DEPLOYMENT WERE IN THE OPERATOR'S ORGANIZATION (2026-09-04, found by reading
// which organization they were actually in, after chasing the symptom on the device for half a day).
//
// A generated deployment makes one id do three jobs: -operator-tenant-id defaults to tenant_default, the
// starting policy bundle is tenant_default, and a flow whose organization does not resolve falls back to the
// node's tenant — tenant_default. So approving a device without naming a customer organization puts it in the
// operator's own, and everything then reports success while per-tenant PKI never engages:
//
//	steer_mux_tenant_resolved device="…" tenant="tenant_default"
//	signing_counts_since_start {"deployment_root_no_own_authority": 40}
//
// The operator organization administers the others. It has no devices.
func TestApprovingADeviceForTheOperatorOrganizationIsRefused(t *testing.T) {
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		AdminAuth:        newAdminAuthStore(),
		OperatorTenantID: "tenant_lab_001", // the node's own tenant in this harness
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/enrolment-tokens",
		strings.NewReader(`{"label":"a laptop","group":"default","expires_in_hours":24}`))
	req.Header.Set("X-Operate-Tenant", "tenant_lab_001")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("approving a device for the operator organization returned %d, want 409 — a device approved "+
			"there is enrolled under the deployment's own authority and nothing downstream says so; body: %s",
			rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "OPERATOR organization") {
		t.Fatalf("the refusal must say WHY and what to do instead, got: %s", rec.Body.String())
	}
}
