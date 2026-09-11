package main

import (
	"context"
	"net/http/httptest"
	"testing"
)

// hasAdmins answers the one question the exception asks: does this organization have anybody who can
// administer it, and could that be established at all.
func hasAdmins(has bool) func(context.Context, string) (bool, bool) {
	return func(context.Context, string) (bool, bool) { return has, true }
}

// unknowable is a deployment where the question cannot be answered.
func unknowable() func(context.Context, string) (bool, bool) {
	return func(context.Context, string) (bool, bool) { return false, false }
}

// ★★ THE BOOTSTRAP DEAD END, AND THE SHAPE OF THE ONE EXCEPTION (2026-08-17, walked from the creation wizard).
//
// Create an organization, choose "it runs itself", name its first administrator — refused with "has not
// delegated its management", because the delegation is what supplies the operator's customer-side writes. The
// wizard then advises inviting from the Administrators screen, which refuses for the same reason. Measured:
// POST /admin/admins/invite → 403 and GET /admin/admins → 403, with no act available that would have
// unrefused it. A self-run organization could never be given the administrator that would let it run itself.
//
// Seating the FIRST administrator is the act that creates the party who could delegate at all. The exception
// is bounded by that and nothing wider, and every boundary below is a way it could have been widened by
// accident.
func TestOnlyTheFirstAdministratorOfAnEmptyOrganizationEscapesTheDelegationGate(t *testing.T) {
	empty := hasAdmins(false)
	inhabited := hasAdmins(true)
	verdict := operatorDelegatedVerdict{Resolved: true, Target: "tenant_customer"}
	post := httptest.NewRequest("POST", "/admin/admins/invite", nil)

	// The case it exists for.
	if !operatorMaySeatFirstAdministrator(context.Background(), post, "admin.accounts.write", verdict, empty) {
		t.Fatal("an organization with no administrator must be able to be given its first one")
	}

	// ★ It closes the moment there is somebody to ask — INCLUDING somebody invited who has not signed in yet.
	// The first version asked the auth store for its principal count, which is written at ACTIVATION, so after
	// seating the first administrator the count was still zero and a second invitation was accepted. Measured
	// live: invite → 201, invite again → 201. The exception never closed.
	if operatorMaySeatFirstAdministrator(context.Background(), post, "admin.accounts.write", verdict, inhabited) {
		t.Fatal("an organization that HAS an administrator — invited or activated — goes through its delegation " +
			"like any other act")
	}

	// One route only. Reading the roster, or any other accounts write, stays refused.
	for _, r := range []*struct {
		method string
		path   string
	}{
		{"GET", "/admin/admins"},
		{"POST", "/admin/admins/adm_x/roles"},
		{"DELETE", "/admin/admins/adm_x"},
		{"POST", "/admin/api-tokens"},
	} {
		req := httptest.NewRequest(r.method, r.path, nil)
		if operatorMaySeatFirstAdministrator(context.Background(), req, "admin.accounts.write", verdict, empty) {
			t.Fatalf("%s %s must not be covered by the first-administrator exception", r.method, r.path)
		}
	}

	// One permission only: the exception must not become a general key for an empty organization.
	for _, permission := range []string{"admin.policy.write", "admin.certs.write", "admin.accounts.read", "admin.tenant.admin"} {
		if operatorMaySeatFirstAdministrator(context.Background(), post, permission, verdict, empty) {
			t.Fatalf("permission %q must not be covered by the first-administrator exception", permission)
		}
	}

	// A store that cannot say how many administrators there are must not be read as "none". A bootstrap that
	// cannot be PROVEN is a delegation gate quietly widened.
	if operatorMaySeatFirstAdministrator(context.Background(), post, "admin.accounts.write", verdict, unknowable()) {
		t.Fatal("a question that cannot be answered must refuse, not assume the organization is empty")
	}
	if operatorMaySeatFirstAdministrator(context.Background(), post, "admin.accounts.write", verdict, nil) {
		t.Fatal("with no way to ask, refuse")
	}

	// And it needs a named organization: an unresolved target is not an empty one.
	if operatorMaySeatFirstAdministrator(context.Background(), post, "admin.accounts.write",
		operatorDelegatedVerdict{Resolved: true}, empty) {
		t.Fatal("with no target organization there is nothing to bootstrap")
	}
}
