package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ★★ THE TENANT WAS PROMISED A CLOSED DOOR THAT DOES NOT LOCK (2026-08-18, read from the customer's own
// Operator access screen).
//
// With the standing delegation off, that screen said: "Nobody outside your tenant can change your settings."
// The comment on PUT /admin/operator-delegation says the opposite and means it — "Either side may write it:
// the operator sets it at onboarding, and the organization can withdraw it" — and the guard on that route lets
// a cross-tenant operator name any tenant. So a tenant that withdraws the delegation is told the door is
// closed, on the one screen built to give it that control.
//
// The design decision is defensible: an operator must be able to enable delegation for a tenant that has no
// administrator yet, and a delegation only its holder can end is not a delegation. What is not defensible is
// telling the tenant otherwise.
//
// This gate ties the sentence to the behaviour. operator_may_enable is computed by running the real guard, so
// the two cannot drift: the only way to make the screen promise a closed door is to make the write refuse.
//
// ★★★ UPDATED THE DAY THE ANSWER CHANGED (2026-08-20). The operator decided that an MSSP operator may NOT
// reopen a delegation the customer withdrew. The line below that said "if that ever changes, this test is the
// one that says so" is that line, and this is it saying so: the onboarding direction still works, the reopen
// direction is refused, and the field the screen reads follows both.
func TestTheDelegationPromiseMatchesWhoMayActuallyWriteIt(t *testing.T) {
	declareOperatorTenantForTest(t, "tenant_operator_001")
	const tenant = "tenant_northwind"

	// An organization that has never withdrawn anything: the operator may still set this at onboarding, which
	// is the case a brand-new organization with no administrator of its own depends on.
	fresh := adminTenantModel{TenantID: tenant}
	claimed := operatorMayEnableDelegation(fresh)

	// ★ AND THE OTHER DIRECTION, WHICH IS THE DECISION. Once the customer withdraws it, the screen must say so
	// AND the write must refuse — one function answers both, so they cannot drift.
	withdrawn := adminTenantModel{TenantID: tenant, OperatorDelegationWithdrawnByCustomer: true}
	if operatorMayEnableDelegation(withdrawn) {
		t.Fatal("the screen tells an organization that withdrew its delegation that the operator may turn it " +
			"back on")
	}
	if err := delegationReopenRefusal(withdrawn, true, true); err == nil {
		t.Fatal("an operator may grant a delegation the organization itself withdrew — a permission the holder " +
			"can re-grant to itself is not a delegation")
	}
	// The operator ending their OWN engagement leaves it reopenable by the operator: nothing was closed by the
	// customer, and making this case refuse would strand an organization that never asked for anything.
	if err := delegationReopenRefusal(adminTenantModel{TenantID: tenant}, true, true); err != nil {
		t.Fatalf("an operator cannot resume a delegation they ended themselves: %v", err)
	}
	// And the customer is never refused by this rule — it exists to protect them, not to lock them out.
	if err := delegationReopenRefusal(withdrawn, false, true); err != nil {
		t.Fatalf("the organization cannot grant its own delegation again: %v", err)
	}

	// What actually happens: the guard the PUT handler runs, for a cross-tenant operator naming this tenant.
	r := httptest.NewRequest(http.MethodPut, "/admin/operator-delegation", nil)
	r = r.WithContext(context.WithValue(r.Context(), adminIdentityContextKey{}, adminIdentity{
		PrincipalID: "adm_operator", TenantID: "tenant_operator_001",
		Roles: []string{"super_admin"}, AuthMethod: "admin_session",
	}))
	actual := adminTenantPKITargetAllowed(r, tenant, "enabling the delegation of") == nil

	if claimed != actual {
		t.Fatalf("the screen is told operator_may_enable=%t and the guard says %t — the tenant is reading a "+
			"promise the code does not keep", claimed, actual)
	}

	// ★ AND IT MUST BE TRUE TODAY, or this test passes vacuously on a build where both are false for an
	// unrelated reason (a probe that fails to construct, a guard that refuses everything). The behaviour under
	// review is that an operator CAN re-grant; if that ever changes, this line is the one that says so, and
	// the screen's absolute sentence becomes correct again in the same commit.
	if !actual {
		t.Fatal("a cross-tenant operator can no longer name another organization on this route at all. That is " +
			"a bigger change than the withdrawal rule: onboarding an organization with no administrator of its " +
			"own now has no path, and this test is where to say what replaced it")
	}

	// ★ THE CONTROL: a caller who is NOT an operator must be refused, or operator_may_enable would be true for
	// reasons that have nothing to do with the envelope and the field would mean nothing.
	c := httptest.NewRequest(http.MethodPut, "/admin/operator-delegation", nil)
	c = c.WithContext(context.WithValue(c.Context(), adminIdentityContextKey{}, adminIdentity{
		PrincipalID: "adm_customer", TenantID: "tenant_acme",
		Roles: []string{"admin"}, AuthMethod: "admin_session",
	}))
	if adminTenantPKITargetAllowed(c, tenant, "enabling the delegation of") == nil {
		t.Fatal("one tenant may enable another tenant's delegation, which is a cross-tenant write, not an envelope")
	}
	// A tenant may of course write its own.
	own := httptest.NewRequest(http.MethodPut, "/admin/operator-delegation", nil)
	own = own.WithContext(context.WithValue(own.Context(), adminIdentityContextKey{}, adminIdentity{
		PrincipalID: "adm_customer", TenantID: tenant,
		Roles: []string{"admin"}, AuthMethod: "admin_session",
	}))
	if err := adminTenantPKITargetAllowed(own, tenant, "enabling the delegation of"); err != nil {
		t.Fatalf("a tenant cannot write its own delegation, so it cannot withdraw it either: %v", err)
	}
}
