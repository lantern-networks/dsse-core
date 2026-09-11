package main

import (
	"testing"

	"github.com/lantern-networks/dsse-core/seatallocation"
)

// ★ THE OWNER OF A FACT IS THE PLANE THAT HOLDS AND ENFORCES IT (2026-08-17, measured end to end on the lab).
//
// The device-allowance item declared the control plane as its owner. So the enforcing Edge — the node that
// holds the seat store, divides the licence pool with it, and consults it from POST /enrol — answered "not
// here, held on the control plane", and the control plane answered "no allowance" because nothing ever writes
// allocations there. 25 seats were allocated through the Console, appeared as 25 on the licensing screen, and
// the same organization's setup checklist reported the item MISSING. Two screens, one deployment, opposite
// answers about a change the operator had just made.
//
// This pins the two halves that have to agree: the plane that holds the store answers for real, and the plane
// that does not says where to ask.
func TestTheDeviceAllowanceIsOwnedByThePlaneThatEnforcesIt(t *testing.T) {
	seats := seatallocation.NewStore()
	if _, err := seats.Allocate(seatallocation.Policy{PoolSeats: 50}, "tenant_customer", 25, "adm_test", "lab", "2026-08-17T00:00:00Z"); err != nil {
		t.Fatalf("allocate: %v", err)
	}
	tenant := adminTenantModel{TenantID: "tenant_customer", DisplayName: "Customer"}

	// The enforcing Edge holds it, so it answers with the number.
	onEdge := findSetupItem(t, organizationSetupReport(organizationSetupSources{
		Tenant: tenant, TenantExists: true, EnforcementEdge: true, Seats: seats,
	}), "seats")
	if onEdge.State != organizationSetupDone {
		t.Fatalf("the plane holding 25 allocated seats must report them done, got %q (%s)", onEdge.State, onEdge.Detail)
	}
	if got := onEdge.Values["seats"]; got != 25 {
		t.Fatalf("seats = %v, want 25", got)
	}

	// A control plane that holds no pool says where to ask rather than reporting an absence as a fact.
	onCP := findSetupItem(t, organizationSetupReport(organizationSetupSources{
		Tenant: tenant, TenantExists: true, EnforcementEdge: false, Seats: seatallocation.NewStore(),
	}), "seats")
	if onCP.State != organizationSetupNotHere {
		t.Fatalf("a plane that does not own the allowance must answer not_here, got %q (%s) — "+
			"reporting zero from a store nothing writes to is what made the checklist contradict the licensing screen",
			onCP.State, onCP.Detail)
	}
	if onCP.Action != nil {
		t.Fatal("a plane that does not own the fact must not offer the action for it")
	}
}

func findSetupItem(t *testing.T, items []organizationSetupItem, key string) organizationSetupItem {
	t.Helper()
	for _, item := range items {
		if item.Key == key {
			return item
		}
	}
	t.Fatalf("no %q item in the setup report", key)
	return organizationSetupItem{}
}
