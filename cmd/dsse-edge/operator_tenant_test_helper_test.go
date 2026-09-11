package main

import "testing"

// declareOperatorTenantForTest names the organization that operates the deployment under test, and puts it
// back afterwards.
//
// ★ WHY EVERY CROSS-ORGANIZATION TEST NOW SAYS THIS OUT LOUD (2026-08-21). Until the hole below was found,
// "operator" meant "holds admin.tenant.admin", a role a CUSTOMER organization grants inside itself — so a test
// could build an operator by handing an identity a role and never saying which organization it belonged to.
// That is exactly the confusion that let a super_admin of tenant_reference_lab read tenant_northwind's audit
// trail on the live lab. A test that means "the operator" must now name the operator.
func declareOperatorTenantForTest(t *testing.T, tenantID string) {
	t.Helper()
	previous := operatorTenantConfigured()
	declareOperatorTenant(tenantID, true)
	t.Cleanup(func() { declareOperatorTenant(previous, false) })
}
