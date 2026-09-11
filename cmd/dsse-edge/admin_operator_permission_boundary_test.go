package main

import "testing"

// ★ TWO OPERATOR ACTS A CUSTOMER COULD PERFORM (2026-08-15), both reproduced on the lab as an ordinary tenant
// `admin` — a role with no cross-tenant rights whatsoever — before they were closed.
//
// The permissions here are the fix, so this test is about the ROLES rather than the routes: it fails the
// moment somebody widens either permission back to something a customer holds.
func TestOperatorOnlyPermissionsAreNotHeldByCustomerRoles(t *testing.T) {
	// admin.quota.write gates entitlements (a tenant granting itself paid features — measured: an ordinary
	// admin granted its own tenant `dlp` and got 200) and seat allocation.
	//
	// admin.tenant.admin gates provisioning ANOTHER tenant's interception root — measured:
	// tenant_reference_lab's admin minted the root for tenant_northwind and received the certificate.
	for _, permission := range []string{"admin.quota.write", "admin.tenant.admin"} {
		for _, role := range []string{"admin", "tenant_admin", "analyst", "approver", "auditor"} {
			if adminPermissionAllowed([]string{role}, permission) {
				t.Fatalf("role %q holds %q — that is an operator act, and a customer holding it means the party a "+
					"limit constrains is the party who can lift it", role, permission)
			}
		}
		// And an operator does hold it, or the routes would be unreachable by anyone.
		if !adminPermissionAllowed([]string{"super_admin"}, permission) {
			t.Fatalf("super_admin does not hold %q, so no one can perform it", permission)
		}
	}
}

// The customer keeps what is genuinely theirs. Narrowing an operator route must not quietly take a tenant's
// own configuration away from it.
func TestCustomerRolesKeepTheirOwnConfiguration(t *testing.T) {
	for _, permission := range []string{"admin.config.write", "admin.policy.write"} {
		if !adminPermissionAllowed([]string{"admin"}, permission) {
			t.Fatalf("an ordinary admin lost %q — a tenant must still configure its own tenant", permission)
		}
	}
}

// The either-of gate must not become a way to widen a route by accident: each named permission still has to
// be held on its own, and an unknown one grants nothing.
func TestEitherOfPermissionGateStillRequiresARealPermission(t *testing.T) {
	if !adminPermissionAllowedAny([]string{"admin"}, "admin.policy.write|admin.tenant.admin") {
		t.Fatal("a tenant admin lost the route for its OWN organization")
	}
	if !adminPermissionAllowedAny([]string{"super_admin"}, "admin.policy.write|admin.tenant.admin") {
		t.Fatal("the operator cannot reach a route it is supposed to perform for customers")
	}
	if adminPermissionAllowedAny([]string{"auditor"}, "admin.policy.write|admin.tenant.admin") {
		t.Fatal("a read-only role passed an either-of gate")
	}
	if adminPermissionAllowedAny([]string{"admin"}, "admin.quota.write|admin.tenant.admin") {
		t.Fatal("an ordinary admin passed a gate naming only operator permissions")
	}
	if adminPermissionAllowedAny([]string{"admin"}, "|") || adminPermissionAllowedAny([]string{"admin"}, "") {
		t.Fatal("an empty permission string allowed the request — a route with no permission must not be open")
	}
	if adminPermissionAllowedAny([]string{"admin"}, "admin.not.a.real.permission") {
		t.Fatal("an unknown permission granted access")
	}
}

// ★ ACTS ON THE DEPLOYMENT, NOT ON A TENANT (2026-08-15). Fleet trust anchors, the foundation interception
// PKI and agent release publishing were all gated on permissions an ordinary tenant `admin` holds. Measured
// with a real customer account on the lab: it reached the trust-anchor and device-client-CA routes, reached
// agent publishing, and ROTATED THE INTERCEPTION INTERMEDIATE — the CA signing every intercepted TLS leaf on
// that Edge, for every tenant on it — receiving a 200.
func TestPlatformActsAreOperatorOnly(t *testing.T) {
	for _, role := range []string{"admin", "tenant_admin", "analyst", "approver", "auditor"} {
		if adminPermissionAllowed([]string{role}, "admin.platform.write") {
			t.Fatalf("role %q can act on the deployment itself (fleet trust anchors, foundation PKI, agent releases)", role)
		}
	}
	if !adminPermissionAllowed([]string{"super_admin"}, "admin.platform.write") {
		t.Fatal("the operator cannot act on the deployment, so nobody can")
	}
	if !adminPermissionAllowed([]string{"owner"}, "admin.platform.write") {
		t.Fatal("owner lost a permission it holds through the wildcard")
	}
}

// And the tenant keeps the acts that are genuinely its own, which share the scopes those routes used to sit
// on. Closing an operator hole must not take a customer's own configuration away — that is the mistake the
// interception-root fix made once already and had to undo.
func TestTenantsKeepTheirOwnSteeringAndPolicyWrites(t *testing.T) {
	for _, permission := range []string{
		"admin.steering.write", // steer exclusions: which apps this tenant excludes from steering
		"admin.policy.write",   // this tenant's own access policy
		"admin.agents.write",   // this tenant's own agent rollout pacing
	} {
		if !adminPermissionAllowed([]string{"admin"}, permission) {
			t.Fatalf("an ordinary admin lost %q — that is the tenant's own configuration", permission)
		}
	}
}
