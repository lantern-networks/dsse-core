package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func scopeRequest(tenant string, operateHeader string, roles ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/admin/pki/certificates", nil)
	if operateHeader != "" {
		r.Header.Set("X-Operate-Tenant", operateHeader)
	}
	if len(roles) == 0 {
		roles = []string{"admin"}
	}
	return requestWithAdminIdentity(r, adminIdentity{
		PrincipalID: "adm_probe", TenantID: tenant, Roles: roles, AuthMethod: "admin_session",
	})
}

// ★★ TWO ROUTES ON ONE SCREEN DISAGREED ABOUT WHO THE ANSWER WAS ABOUT (2026-08-17, found by onboarding a new
// organization through the Console). An operator ENTERED "Contoso Ltd" — the banner said so — and
// GET /admin/state answered about Contoso while GET /admin/pki/certificates answered about the whole node, so
// Contoso's certificate screen said connections are verified with "Northwind Device Issuing CA 2028
// (tenant_northwind)" and warned in red about another organization's device.
//
// Entering an organization is a mode with a banner attached. It decides what the operator is SHOWN, not only
// what they act on.
func TestAnAnswerIsAboutTheOrganizationTheRequestNames(t *testing.T) {
	declareOperatorTenantForTest(t, "tenant_operator_001")
	// A customer administrator: their own organization, and a header they may not use changes nothing.
	if tenant, whole := adminAnswerScope(scopeRequest("tenant_northwind", "")); tenant != "tenant_northwind" || whole {
		t.Fatalf("a customer gets their own organization, got %q whole=%v", tenant, whole)
	}

	// An operator who has not entered one is asking about the deployment.
	if tenant, whole := adminAnswerScope(scopeRequest("tenant_operator_001", "", "owner")); !whole {
		t.Fatalf("an operator outside any organization asks about the deployment, got %q whole=%v", tenant, whole)
	}

	// An operator who HAS entered one gets that organization — the defect this exists to fix.
	tenant, whole := adminAnswerScope(scopeRequest("tenant_operator_001", "tenant_contoso_ltd", "owner"))
	if whole || tenant != "tenant_contoso_ltd" {
		t.Fatalf("inside an organization the answer must be about it, got %q whole=%v", tenant, whole)
	}
}
