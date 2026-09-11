package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
)

const (
	operateTenantSelf   = "tenant_operate_self"
	operateTenantTarget = "tenant_operate_target"
)

// requestWithOperateHeader builds an authenticated admin request with the supplied identity in context and an
// optional X-Operate-Tenant override header.
func requestWithOperateHeader(method, override string, identity adminIdentity) *http.Request {
	req := httptest.NewRequest(method, "/admin/policies", nil)
	if override != "" {
		req.Header.Set("X-Operate-Tenant", override)
	}
	return requestWithAdminIdentity(req, identity)
}

// TestAdminOperateWithinTenantOverride covers Multi-Tenant Admin Console design/: only an operator that
// holds admin.tenant.admin can re-scope to a selected tenant via X-Operate-Tenant; everyone else is silently
// scoped to self (no cross-tenant leakage); resolution stays fail-closed.
func TestAdminOperateWithinTenantOverride(t *testing.T) {
	declareOperatorTenantForTest(t, operateTenantSelf)
	superAdmin := adminIdentity{PrincipalID: "op_super", TenantID: operateTenantSelf, Roles: []string{"super_admin"}, AuthMethod: "admin_api_token"}
	ownerAdmin := adminIdentity{PrincipalID: "op_owner", TenantID: operateTenantSelf, Roles: []string{"owner"}, AuthMethod: "admin_api_token"}
	tenantAdmin := adminIdentity{PrincipalID: "op_tenant_admin", TenantID: operateTenantSelf, Roles: []string{"tenant_admin"}, AuthMethod: "admin_api_token"}
	plainAdmin := adminIdentity{PrincipalID: "op_admin", TenantID: operateTenantSelf, Roles: []string{"admin"}, AuthMethod: "admin_api_token"}

	cases := []struct {
		name           string
		identity       adminIdentity
		override       string
		wantTenant     string
		wantOverridden bool
	}{
		// Operator (admin.tenant.admin via super_admin) → header honored.
		{"super_admin honors override", superAdmin, operateTenantTarget, operateTenantTarget, true},
		// Operator via owner "*" wildcard → header honored.
		{"owner honors override", ownerAdmin, operateTenantTarget, operateTenantTarget, true},
		// No header → operator stays on self (not overridden).
		{"super_admin without header stays self", superAdmin, "", operateTenantSelf, false},
		// Whitespace-only header is treated as absent → self.
		{"super_admin blank header stays self", superAdmin, "   ", operateTenantSelf, false},
		// Non-operator roles: header MUST be ignored (no cross-tenant reach).
		{"tenant_admin override ignored", tenantAdmin, operateTenantTarget, operateTenantSelf, false},
		{"admin override ignored", plainAdmin, operateTenantTarget, operateTenantSelf, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := requestWithOperateHeader(http.MethodPost, tc.override, tc.identity)
			gotTenant, gotOverridden := adminOperateTenant(req, tc.identity)
			if gotTenant != tc.wantTenant || gotOverridden != tc.wantOverridden {
				t.Fatalf("adminOperateTenant = (%q, %v), want (%q, %v)", gotTenant, gotOverridden, tc.wantTenant, tc.wantOverridden)
			}
			// adminTenantIDFromRequest is what every handler uses; it must resolve to the same tenant.
			if got := adminTenantIDFromRequest(req); got != tc.wantTenant {
				t.Fatalf("adminTenantIDFromRequest = %q, want %q", got, tc.wantTenant)
			}
		})
	}
}

// TestAdminTenantIDFromRequestFailClosed reaffirms/ fail-closed: no identity context, or an identity with
// no tenant and no honored override, resolves to "" (callers then 403).
func TestAdminTenantIDFromRequestFailClosed(t *testing.T) {
	declareOperatorTenantForTest(t, operateTenantSelf)
	// No identity in context at all.
	bare := httptest.NewRequest(http.MethodGet, "/admin/policies", nil)
	if got := adminTenantIDFromRequest(bare); got != "" {
		t.Fatalf("no-identity tenant = %q, want empty", got)
	}
	// Identity with empty tenant and no override → empty (deny).
	emptyTenant := requestWithAdminIdentity(httptest.NewRequest(http.MethodGet, "/admin/policies", nil), adminIdentity{PrincipalID: "p", TenantID: "", Roles: []string{"admin"}})
	if got := adminTenantIDFromRequest(emptyTenant); got != "" {
		t.Fatalf("empty-tenant identity tenant = %q, want empty", got)
	}
	// A non-operator with an override header and an empty tenant must STILL fail closed (header ignored).
	emptyWithHeader := requestWithOperateHeader(http.MethodGet, operateTenantTarget, adminIdentity{PrincipalID: "p", TenantID: "", Roles: []string{"admin"}})
	if got := adminTenantIDFromRequest(emptyWithHeader); got != "" {
		t.Fatalf("non-operator empty-tenant override tenant = %q, want empty (fail closed)", got)
	}
}

// TestAdminOperateWithinTenantAudit verifies the gate's audit policy: an effective operator override on a
// MUTATION is recorded (tenant'd to the target, naming the operator), while reads are NOT audited here.
func TestAdminOperateWithinTenantAudit(t *testing.T) {
	declareOperatorTenantForTest(t, operateTenantSelf)
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	evaluator := decision.Evaluator{EdgeRegionID: "region-test", EdgeClusterID: "cluster-test"}
	superAdmin := adminIdentity{PrincipalID: "op_super", TenantID: operateTenantSelf, Roles: []string{"super_admin"}, AuthMethod: "admin_api_token"}

	// gateAudit mirrors the adminEndpoint gate's override-audit predicate exactly: audit only when the override
	// is effective (overridden && resolved tenant != self) AND the method is a mutation.
	gateAudit := func(method, override string, identity adminIdentity) {
		req := requestWithOperateHeader(method, override, identity)
		if operateTenant, overridden := adminOperateTenant(req, identity); overridden &&
			adminMutatingMethod(req.Method) &&
			operateTenant != identity.TenantID {
			if err := appendAdminAudit(context.Background(), writer, nil, adminOperateWithinTenantAuditLog(identity, operateTenant, req.Method, req.URL.Path, evaluator, "203.0.113.7", "test-agent"), time.Now().UTC()); err != nil {
				t.Fatalf("appendAdminAudit: %v", err)
			}
		}
	}

	// Reads are not audited.
	gateAudit(http.MethodGet, operateTenantTarget, superAdmin)
	// Self-targeting (no header) mutation is a no-op.
	gateAudit(http.MethodPost, "", superAdmin)
	// Effective override mutation IS audited.
	gateAudit(http.MethodPost, operateTenantTarget, superAdmin)

	rows, err := writer.ReadJSONL("audit.log.jsonl")
	if err != nil {
		t.Fatalf("ReadJSONL: %v", err)
	}
	var operateRows []map[string]any
	for _, row := range rows {
		if row["event_type"] == "admin_operate_within_tenant" {
			operateRows = append(operateRows, row)
		}
	}
	if len(operateRows) != 1 {
		t.Fatalf("operate-within-tenant audit rows = %d, want exactly 1 (only the effective mutation)", len(operateRows))
	}
	row := operateRows[0]
	// Audit is tenant'd to the TARGET tenant (surfaces in that tenant's operator-access view).
	if got := stringField(row, "tenant_id"); got != operateTenantTarget {
		t.Fatalf("audit tenant_id = %q, want %q", got, operateTenantTarget)
	}
	// Operator principal is recorded.
	if got := stringField(row, "actor_user_id"); got != superAdmin.PrincipalID {
		t.Fatalf("audit actor_user_id = %q, want %q", got, superAdmin.PrincipalID)
	}
	meta, _ := row["metadata"].(map[string]any)
	if meta == nil {
		t.Fatalf("audit metadata missing")
	}
	if got, _ := meta["operator_principal_id"].(string); got != superAdmin.PrincipalID {
		t.Fatalf("metadata.operator_principal_id = %q, want %q", got, superAdmin.PrincipalID)
	}
	if got, _ := meta["operator_tenant_id"].(string); got != operateTenantSelf {
		t.Fatalf("metadata.operator_tenant_id = %q, want %q", got, operateTenantSelf)
	}
	if got, _ := meta["target_tenant_id"].(string); got != operateTenantTarget {
		t.Fatalf("metadata.target_tenant_id = %q, want %q", got, operateTenantTarget)
	}
	if got, _ := meta["method"].(string); got != http.MethodPost {
		t.Fatalf("metadata.method = %q, want POST", got)
	}
}

// stringField reads a string field from a decoded audit row regardless of being a *string-encoded value.
func stringField(row map[string]any, key string) string {
	if v, ok := row[key].(string); ok {
		return v
	}
	return ""
}
