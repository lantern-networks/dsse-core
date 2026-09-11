package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func bgRequestAs(tenant string, roles ...string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/break-glass/sessions", nil)
	if len(roles) == 0 {
		roles = []string{"admin"}
	}
	return requestWithAdminIdentity(r, adminIdentity{
		PrincipalID: "adm_probe", TenantID: tenant, Roles: roles, AuthMethod: "admin_session",
	})
}

// ★★★ A CREDENTIAL FROM ONE ORGANIZATION MINTED AN ACTIVE SESSION IN ANOTHER (2026-08-16, measured on the
// lab, not reasoned from the code). POST /break-glass/sessions on the device-facing listener, presenting an
// API token belonging to tenant_operator_001 — no cross-tenant permission — returned HTTP 201 with a live
// session in tenant_reference_lab for a user_id the caller supplied itself. admin.break_glass.write is held by
// the ordinary tenant `admin` role, so this was reachable by any customer administrator.
//
// The whole surface took its organization from the NODE's policy bundle instead of from the caller.
func TestBreakGlassActsInTheCallersOrganizationNotTheNodes(t *testing.T) {
	const node = "tenant_reference_lab"

	if got := breakGlassCallerTenant(bgRequestAs("tenant_operator_001"), node); got != "tenant_operator_001" {
		t.Fatalf("break-glass must act in the caller's organization, got %q", got)
	}
	// A deployment with no tenant model at all: every identity is unscoped and the node's tenant is the only
	// one there is, so single-tenant behaviour is unchanged.
	if got := breakGlassCallerTenant(bgRequestAs(""), node); got != node {
		t.Fatalf("an unscoped caller keeps the node's organization, got %q", got)
	}
}

func TestBreakGlassRequestsResolveOnlyWithinTheCallersOrganization(t *testing.T) {
	declareOperatorTenantForTest(t, "tenant_operator_001")
	const node = "tenant_reference_lab"
	foreign := breakGlassAccessRequest{ID: "bg_1", TenantID: "tenant_reference_lab"}
	own := breakGlassAccessRequest{ID: "bg_2", TenantID: "tenant_northwind"}

	customer := bgRequestAs("tenant_northwind")
	if breakGlassRequestVisibleTo(foreign, customer, node) {
		t.Fatal("a customer could act on another organization's break-glass request")
	}
	if !breakGlassRequestVisibleTo(own, customer, node) {
		t.Fatal("a customer must still act on their own")
	}

	// The control: an operator still reaches the whole deployment, or this was blinded rather than scoped.
	operator := bgRequestAs("tenant_operator_001", "owner")
	if !breakGlassRequestVisibleTo(foreign, operator, node) || !breakGlassRequestVisibleTo(own, operator, node) {
		t.Fatal("the operator lost access to the deployment's break-glass requests")
	}
}

func TestBreakGlassExportCarriesOnlyTheCallersOrganization(t *testing.T) {
	declareOperatorTenantForTest(t, "tenant_operator_001")
	const node = "tenant_reference_lab"
	events := []map[string]any{
		{"event_type": "break_glass_session_issued", "tenant_id": "tenant_reference_lab", "session_id": "s1"},
		{"event_type": "break_glass_session_issued", "tenant_id": "tenant_northwind", "session_id": "s2"},
	}
	got := breakGlassEventsForCaller(events, bgRequestAs("tenant_northwind"), node)
	if len(got) != 1 || got[0]["session_id"] != "s2" {
		t.Fatalf("the export must carry only the caller's organization, got %+v", got)
	}
	if all := breakGlassEventsForCaller(events, bgRequestAs("tenant_operator_001", "owner"), node); len(all) != 2 {
		t.Fatalf("the operator must still export the whole deployment, got %d", len(all))
	}
}
