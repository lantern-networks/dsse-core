package main

import "testing"

// admin_quota_authority_test.go — who may set a tenant's device quota.
//
// ★ THE RULE, STATED BECAUSE IT WAS WRONG TWICE (2026-08-14). The party a limit constrains must not be the
// party who writes it. Setting a tenant's quota — and applying the licence quotas are drawn from — is an
// MSSP-level act, so it belongs to the cross-tenant operator and not to the tenant's own administrator.
//
// The first attempt at this bound the route's tenant to the caller. That stopped a per-tenant `admin` taking
// seats from ANOTHER tenant and left the actual defect untouched: the same `admin` could still raise its own
// cap. What had been standing in for an authorisation control was the Lantern-signed pool total — a commercial
// mechanism doing a security job — and the OSS transition removes exactly that.
//
// So these assert the authority, not the arithmetic: capacity routes require admin.quota.write, the per-tenant
// role does not hold it, and the operator role does.

func TestATenantAdminCannotWriteAQuota(t *testing.T) {
	for _, scope := range []string{"admin.quota.write"} {
		if adminPermissionAllowed([]string{"admin"}, scope) {
			t.Fatalf("the per-tenant `admin` role must NOT hold %s — it is the role a quota constrains, and its "+
				"own definition says it only sees its own tenant", scope)
		}
	}
	// And it keeps the work that is legitimately a tenant admin's, which is why the capacity routes were split
	// out rather than this role being narrowed wholesale.
	for _, scope := range []string{"admin.enrollment.write", "admin.enrollment.read"} {
		if !adminPermissionAllowed([]string{"admin"}, scope) {
			t.Fatalf("a tenant admin must keep %s: enrolment tokens, enabling and disabling devices and device "+
				"groups are its own work", scope)
		}
	}
}

func TestTheCrossTenantOperatorCanWriteAQuota(t *testing.T) {
	if !adminPermissionAllowed([]string{"super_admin"}, "admin.quota.write") {
		t.Fatal("the cross-tenant operator must hold admin.quota.write — before this it held neither that nor " +
			"admin.enrollment.write, so the party whose job it is to allocate capacity could not do it at all")
	}
	if !adminPermissionAllowed([]string{"owner"}, "admin.quota.write") {
		t.Fatal("owner holds everything and must reach this too")
	}
}

// ★ AND THE READ SIDE IS DELIBERATELY NOT RESTRICTED. A tenant administrator seeing the quota they are held to
// is not a leak, it is the difference between a limit and a surprise — and after the same day's change the
// quota alerts rather than refuses, so the number is only useful to somebody who can see it.
func TestATenantAdminCanStillSeeItsQuota(t *testing.T) {
	if !adminPermissionAllowed([]string{"admin"}, "admin.state.read") {
		t.Fatal("a tenant admin must still be able to READ the licensing view that shows its quota")
	}
}
