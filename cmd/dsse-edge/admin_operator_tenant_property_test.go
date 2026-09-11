package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

// admin_operator_tenant_property_test.go — Slice 4 of the multi-tenant Admin Console Q5 operator-principal
// separation . These property/contract tests pin the operator-tenant
// invariants on top of the Slice 0 mechanism (is_operator flag / undeletable operator tenant) and the Slice 1
// owner-role convention guard, and reaffirm the lab default (-operator-tenant-id unset) is unchanged.

const (
	propOperatorTenantID = "tenant_operator_001"
)

// TestAdminOperatorTenantSeedingProperties is the operator-tenant invariant property: with -operator-tenant-id
// set, exactly ONE tenant (the operator) is flagged is_operator regardless of how many customer tenants exist,
// the flag is DERIVED from -operator-tenant-id (never trusted from stored/input data), the operator tenant is
// undeletable (409), and customer tenants delete normally.
func TestAdminOperatorTenantSeedingProperties(t *testing.T) {
	now := time.Now().UTC()
	store := newOperatorAwareAdminTenantModelStore(testEvaluator().PolicyBundle, now, "", propOperatorTenantID)

	// A spread of customer tenants, including one Put with IsOperator deceptively set true (must be overridden to
	// false on read) and a Put that re-creates the operator id with IsOperator=false (must be overridden to true).
	customers := []string{"tenant_acme_001", "tenant_beta_002", "tenant_gamma_003"}
	for _, id := range customers {
		if _, err := store.Put(context.Background(), adminTenantModel{TenantID: id, DisplayName: id, Status: "active", IsOperator: true}, now); err != nil {
			t.Fatalf("put customer %s: %v", id, err)
		}
	}
	// Re-Put the operator tenant with a hostile IsOperator=false — the derived flag must still resolve true.
	if _, err := store.Put(context.Background(), adminTenantModel{TenantID: propOperatorTenantID, DisplayName: "Operator", Status: "active", IsOperator: false}, now); err != nil {
		t.Fatalf("re-put operator tenant: %v", err)
	}

	list, err := store.List(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	operatorFlags := 0
	for _, tenant := range list {
		isOperator := tenant.TenantID == propOperatorTenantID
		if tenant.IsOperator != isOperator {
			t.Fatalf("tenant %q is_operator=%v, want %v (flag must be derived from -operator-tenant-id only)", tenant.TenantID, tenant.IsOperator, isOperator)
		}
		if tenant.IsOperator {
			operatorFlags++
		}
	}
	if operatorFlags != 1 {
		t.Fatalf("is_operator count = %d, want exactly 1 (the operator tenant) across %d tenants", operatorFlags, len(list))
	}

	// Get of an arbitrary (never-stored) tenant also derives is_operator=false.
	if got, err := store.Get(context.Background(), "tenant_never_stored"); err != nil || got.IsOperator {
		t.Fatalf("Get(unknown) is_operator=%v err=%v, want false nil", got.IsOperator, err)
	}
	// Get of the operator id derives true even though it was last Put with false.
	if got, err := store.Get(context.Background(), propOperatorTenantID); err != nil || !got.IsOperator {
		t.Fatalf("Get(operator) is_operator=%v err=%v, want true nil", got.IsOperator, err)
	}

	// HTTP lifecycle: operator delete refused (409, survives), customer delete accepted (200).
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Registry:         connector.NewRegistry(),
		AdminAuth:        newAdminAuthStore(),
		AdminAuditOutbox: &recordingAdminAuditOutboxDeadReader{},
		TenantModelStore: store,
		OperatorTenantID: propOperatorTenantID,
	})
	delOperator := httptest.NewRecorder()
	handler.ServeHTTP(delOperator, httptest.NewRequest(http.MethodDelete, "/admin/tenants/"+propOperatorTenantID, nil))
	if delOperator.Code != http.StatusConflict || !strings.Contains(delOperator.Body.String(), "operator tenant") {
		t.Fatalf("delete operator = %d body=%s, want 409 operator-tenant refusal", delOperator.Code, delOperator.Body.String())
	}
	delCustomer := httptest.NewRecorder()
	handler.ServeHTTP(delCustomer, httptest.NewRequest(http.MethodDelete, "/admin/tenants/tenant_acme_001", nil))
	if delCustomer.Code != http.StatusOK {
		t.Fatalf("delete customer = %d body=%s, want 200 (customer tenants delete normally)", delCustomer.Code, delCustomer.Body.String())
	}
	// Operator tenant still present after the rejected delete.
	if got, err := store.Get(context.Background(), propOperatorTenantID); err != nil || !got.IsOperator {
		t.Fatalf("operator tenant gone/altered after rejected delete: %#v err=%v", got, err)
	}
}

// TestAdminOperatorTenantFeatureOffPropertiesUnchanged pins the lab default as a property: with
// -operator-tenant-id unset, NO tenant is flagged is_operator no matter how many exist, and every tenant
// (including one named like the would-be operator) is deletable — the operator feature is entirely inert.
func TestAdminOperatorTenantFeatureOffPropertiesUnchanged(t *testing.T) {
	now := time.Now().UTC()
	store := newAdminTenantModelStore(testEvaluator().PolicyBundle, now) // no operator id => feature off
	for _, id := range []string{propOperatorTenantID, "tenant_acme_001", "tenant_beta_002"} {
		if _, err := store.Put(context.Background(), adminTenantModel{TenantID: id, DisplayName: id, Status: "active", IsOperator: true}, now); err != nil {
			t.Fatalf("put %s: %v", id, err)
		}
	}
	list, err := store.List(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, tenant := range list {
		if tenant.IsOperator {
			t.Fatalf("tenant %q flagged is_operator with the feature off: %#v", tenant.TenantID, tenant)
		}
	}

	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Registry:         connector.NewRegistry(),
		AdminAuth:        newAdminAuthStore(),
		AdminAuditOutbox: &recordingAdminAuditOutboxDeadReader{},
		TenantModelStore: store,
		// OperatorTenantID intentionally left empty (lab default).
	})
	// Even the tenant named like the operator deletes normally — no 409 lockout when the feature is off.
	delRec := httptest.NewRecorder()
	handler.ServeHTTP(delRec, httptest.NewRequest(http.MethodDelete, "/admin/tenants/"+propOperatorTenantID, nil))
	if delRec.Code != http.StatusOK {
		t.Fatalf("delete = %d body=%s, want 200 (no operator lockout when feature off)", delRec.Code, delRec.Body.String())
	}
}

// TestAdminOperatorTenantOperateWithin confirms an operator-tenant super_admin principal can "operate within" a
// customer tenant via X-Operate-Tenant (resolution + override flag), the very mechanism the runbook relies on for
// the operator to administer customer tenants from its own (operator) home tenant.
func TestAdminOperatorTenantOperateWithin(t *testing.T) {
	declareOperatorTenantForTest(t, propOperatorTenantID)
	const customerTenant = "tenant_acme_001"
	operator := adminIdentity{PrincipalID: "op_super_1", TenantID: propOperatorTenantID, Roles: []string{"super_admin"}, AuthMethod: "admin_api_token"}

	// With the header: the operator re-scopes into the customer tenant and the override is flagged.
	withHeader := requestWithOperateHeader(http.MethodPost, customerTenant, operator)
	if tenant, overridden := adminOperateTenant(withHeader, operator); tenant != customerTenant || !overridden {
		t.Fatalf("operate-within = (%q,%v), want (%q,true)", tenant, overridden, customerTenant)
	}
	if got := adminTenantIDFromRequest(withHeader); got != customerTenant {
		t.Fatalf("adminTenantIDFromRequest = %q, want %q (operator operates within customer tenant)", got, customerTenant)
	}

	// Without the header the operator stays on its OWN (operator) tenant — never a silent cross-tenant reach.
	noHeader := requestWithOperateHeader(http.MethodGet, "", operator)
	if tenant, overridden := adminOperateTenant(noHeader, operator); tenant != propOperatorTenantID || overridden {
		t.Fatalf("operate-within no header = (%q,%v), want (%q,false)", tenant, overridden, propOperatorTenantID)
	}

	// The effective override on a mutation is auditable (same predicate the gate uses), tenant'd to the target.
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	evaluator := testEvaluator()
	if tenant, overridden := adminOperateTenant(withHeader, operator); overridden && adminMutatingMethod(withHeader.Method) && tenant != operator.TenantID {
		if err := appendAdminAudit(context.Background(), writer, nil, adminOperateWithinTenantAuditLog(operator, tenant, withHeader.Method, withHeader.URL.Path, evaluator, "203.0.113.9", "test-agent"), time.Now().UTC()); err != nil {
			t.Fatalf("appendAdminAudit: %v", err)
		}
	}
	rows, err := writer.ReadJSONL("audit.log.jsonl")
	if err != nil {
		t.Fatalf("ReadJSONL: %v", err)
	}
	var operateRows int
	for _, row := range rows {
		if row["event_type"] == "admin_operate_within_tenant" {
			operateRows++
			if got := stringField(row, "tenant_id"); got != customerTenant {
				t.Fatalf("operate-within audit tenant_id = %q, want target %q", got, customerTenant)
			}
		}
	}
	if operateRows != 1 {
		t.Fatalf("operate-within audit rows = %d, want exactly 1", operateRows)
	}
}

// TestAdminOperatorTenantOwnerRoleGuardUnit is the Slice 1 convention truth table: owner is rejected only inside
// the operator tenant when the feature is on; super_admin (the intended operator role) and any customer tenant or
// feature-off case are allowed.
func TestAdminOperatorTenantOwnerRoleGuardUnit(t *testing.T) {
	cases := []struct {
		name       string
		operatorID string
		targetID   string
		roles      []string
		want       bool
	}{
		{"feature off", "", propOperatorTenantID, []string{"owner"}, false},
		{"customer tenant owner allowed", propOperatorTenantID, "tenant_acme_001", []string{"owner"}, false},
		{"operator tenant owner rejected", propOperatorTenantID, propOperatorTenantID, []string{"owner"}, true},
		{"operator tenant owner among others rejected", propOperatorTenantID, propOperatorTenantID, []string{"admin", "owner"}, true},
		{"operator tenant super_admin allowed", propOperatorTenantID, propOperatorTenantID, []string{"super_admin", "admin"}, false},
		{"operator tenant trims target", propOperatorTenantID, " " + propOperatorTenantID + " ", []string{"owner"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := adminOperatorTenantRejectsOwner(tc.operatorID, tc.targetID, tc.roles); got != tc.want {
				t.Fatalf("adminOperatorTenantRejectsOwner(%q,%q,%v) = %v, want %v", tc.operatorID, tc.targetID, tc.roles, got, tc.want)
			}
		})
	}
}

// newOperatorTenantAdminServer builds a server whose operator caller (admin+super_admin) lives in the home
// tenant, with two active first-party accounts (target + keeper) in that tenant so a non-owner role change does
// not trip the lockout guard. The home tenant is the evaluator's seed tenant (tenant_lab_001) so the API-token
// identity resolves against it (admin-auth binds tokens to the seed tenant in this plaintext lab path).
// operatorTenantID == "" reproduces the lab (feature-off) configuration; operatorTenantID == the seed tenant
// turns the home tenant INTO the operator tenant so the Slice 1 guard is exercised end to end.
func newOperatorTenantAdminServer(t *testing.T, operatorTenantID string) (http.Handler, string) {
	t.Helper()
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	const homeTenant = "tenant_lab_001" // the evaluator seed tenant the admin-auth token lookup binds to
	now := time.Now().UTC()
	creds := newLocalAdminCredentialStore("Lantern DSSE")
	seedActiveAdminAccount(t, creds, "target@op.example", homeTenant, "adm_op_target", []string{"admin"}, now)
	seedActiveAdminAccount(t, creds, "keeper@op.example", homeTenant, "adm_op_keeper", []string{"admin"}, now)

	auth := newAdminAuthStore()
	rawToken := "raw-operator-caller"
	auth.UpsertPrincipal(adminPrincipal{
		ID: "adm_op_caller", TenantID: homeTenant, Subject: "sub_op_caller",
		Email: "caller@op.example", Roles: []string{"admin", "super_admin"}, IDPID: "keycloak_lab",
		Status: "active", CreatedAt: now.Add(-time.Hour).Format(time.RFC3339),
	})
	auth.UpsertAPIToken(adminAPIToken{
		ID: "tok_op_caller", TenantID: homeTenant, Name: "operator-caller",
		TokenHash: adminTokenHash(rawToken), Roles: []string{"admin", "super_admin"}, Scopes: []string{"*"},
		CreatedByAdminPrincipalID: "adm_op_caller",
		CreatedAt:                 now.Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt:                 now.Add(time.Hour).Format(time.RFC3339), Status: "active",
	})

	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		Registry:         connector.NewRegistry(),
		AdminAuth:        auth,
		AdminAuditOutbox: &recordingAdminAuditOutboxDeadReader{},
		LocalCredentials: creds,
		TenantModelStore: newOperatorAwareAdminTenantModelStore(model.PolicyBundle{TenantID: homeTenant}, now, "", operatorTenantID),
		OperatorTenantID: operatorTenantID,
	})
	return handler, rawToken
}

// TestAdminOperatorTenantOwnerRoleGuardHTTP is the Slice 1 guard end-to-end: in the operator tenant, owner is
// refused (409) on both invite and role change while super_admin (and the default admin invite) is accepted; with
// the feature off the identical owner assignment is accepted (200) — the lab is unchanged.
func TestAdminOperatorTenantOwnerRoleGuardHTTP(t *testing.T) {
	do := func(handler http.Handler, method, path, bearer, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("authorization", "Bearer "+bearer)
		if body != "" {
			req.Header.Set("content-type", "application/json")
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	// Feature ON: the home (seed) tenant IS the operator tenant — it rejects owner, accepts super_admin / admin.
	on, onToken := newOperatorTenantAdminServer(t, "tenant_lab_001")
	if rec := do(on, http.MethodPost, "/admin/admins/adm_op_target/roles", onToken, `{"roles":["owner"]}`); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "operator tenant") {
		t.Fatalf("operator-tenant owner role = %d body=%s, want 409 operator-tenant refusal", rec.Code, rec.Body.String())
	}
	if rec := do(on, http.MethodPost, "/admin/admins/adm_op_target/roles", onToken, `{"roles":["super_admin"]}`); rec.Code != http.StatusOK {
		t.Fatalf("operator-tenant super_admin role = %d body=%s, want 200", rec.Code, rec.Body.String())
	}
	if rec := do(on, http.MethodPost, "/admin/admins/invite", onToken, `{"email":"new@op.example","roles":["owner"]}`); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "operator tenant") {
		t.Fatalf("operator-tenant owner invite = %d body=%s, want 409 operator-tenant refusal", rec.Code, rec.Body.String())
	}
	if rec := do(on, http.MethodPost, "/admin/admins/invite", onToken, `{"email":"sa@op.example","roles":["super_admin"]}`); rec.Code != http.StatusCreated {
		t.Fatalf("operator-tenant super_admin invite = %d body=%s, want 201", rec.Code, rec.Body.String())
	}

	// Feature OFF (lab): the identical owner assignment is accepted — behavior is unchanged.
	off, offToken := newOperatorTenantAdminServer(t, "")
	if rec := do(off, http.MethodPost, "/admin/admins/adm_op_target/roles", offToken, `{"roles":["owner"]}`); rec.Code != http.StatusOK {
		t.Fatalf("feature-off owner role = %d body=%s, want 200 (lab unchanged)", rec.Code, rec.Body.String())
	}
	if rec := do(off, http.MethodPost, "/admin/admins/invite", offToken, `{"email":"owner@lab.example","roles":["owner"]}`); rec.Code != http.StatusCreated {
		t.Fatalf("feature-off owner invite = %d body=%s, want 201 (lab unchanged)", rec.Code, rec.Body.String())
	}
}
