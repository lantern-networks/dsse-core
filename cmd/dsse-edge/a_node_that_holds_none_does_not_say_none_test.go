package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// ★★ "THERE IS NONE" AND "NOT MINE TO SAY" ARE DIFFERENT ANSWERS (2026-08-21, measured across both planes of
// the reference deployment). Per-organization transport authorities live on a CONTROL PLANE. An Edge holds
// none by design — and answered has_authority:false for organizations that have one:
//
//	control plane  has_authority=true   server_name=lab.dsse.invalid
//	edge           has_authority=false  server_name=""
//
// The Console asks the control plane, so no screen was wrong. The ROUTE was: an answer that depends on which
// node replied, with the wrong one indistinguishable from the truth.
func TestANodeHoldingNoAuthoritiesRefusesInsteadOfReportingNone(t *testing.T) {
	declareOperatorTenantForTest(t, "tenant_operator_001")
	now := time.Now().UTC()

	auth := newAdminAuthStore()
	const bearer = "raw-operator-authority-read"
	auth.UpsertPrincipal(adminPrincipal{ID: "adm_auth", TenantID: "tenant_operator_001", Subject: "sub_auth",
		Email: "operator@example.invalid", Roles: []string{"admin", "super_admin"}, IDPID: "keycloak_lab",
		Status: "active", CreatedAt: now.Add(-time.Hour).Format(time.RFC3339)})
	auth.UpsertAPIToken(adminAPIToken{ID: "tok_auth", TenantID: "tenant_operator_001", Name: "operator",
		TokenHash: adminTokenHash(bearer), Roles: []string{"admin", "super_admin"}, Scopes: []string{"*"},
		CreatedByAdminPrincipalID: "adm_auth", CreatedAt: now.Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Status: "active"})

	tenants := newOperatorAwareAdminTenantModelStore(model.PolicyBundle{}, now, "", "tenant_operator_001")
	for _, id := range []string{"tenant_operator_001"} {
		if _, err := tenants.Put(context.Background(),
			adminTenantModel{TenantID: id, DisplayName: id, Status: "active"}, now); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}

	read := func(handler http.Handler) (int, string) {
		req := httptest.NewRequest(http.MethodGet, "/admin/tenant-transport-authority", nil)
		req.Header.Set("authorization", "Bearer "+bearer)
		// The operator's OWN organization: no delegation is needed there, so the envelope is not what this
		// test is measuring.
		req.Header.Set("x-operate-tenant", "tenant_operator_001")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}

	// A node with no authority store — an Edge.
	edge := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(), AdminAuth: auth, TenantModelStore: tenants,
		OperatorTenantID: "tenant_operator_001",
	})
	code, body := read(edge)
	if code == http.StatusOK && strings.Contains(body, `"has_authority":false`) {
		t.Fatal("★ a node that holds no authorities at all reported that this organization has none. That is " +
			"indistinguishable from the truth, and it is what an Edge answered for organizations whose " +
			"authority the control plane was holding.")
	}
	if code != http.StatusConflict {
		t.Fatalf("want HTTP 409 from a node that cannot answer; got %d %s", code, body)
	}
	if !strings.Contains(strings.ToUpper(body), "CONTROL PLANE") {
		t.Fatalf("the refusal does not tell the caller where the answer lives: %s", body)
	}

	// ★ THE CONTROL: a node that DOES hold them answers normally, or this just breaks the route.
	authority := newTenantTransportAuthority(nil, func([]byte) error { return nil }, time.Now)
	controlPlane := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(), AdminAuth: auth, TenantModelStore: tenants,
		OperatorTenantID: "tenant_operator_001", TenantTransportAuthority: authority,
	})
	code, body = read(controlPlane)
	if code != http.StatusOK {
		t.Fatalf("a control plane could not answer its own question: HTTP %d %s", code, body)
	}
	if !strings.Contains(body, `"has_authority":false`) {
		t.Fatalf("this organization genuinely has none, and the control plane must say so: %s", body)
	}
}
