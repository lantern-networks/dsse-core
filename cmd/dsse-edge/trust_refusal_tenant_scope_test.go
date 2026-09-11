package main

import "testing"

// ★★ TRUST REFUSALS WERE WRITTEN PER TENANT AND READ FOR ONE (2026-08-18).
//
// The agent report merges under the DEVICE's tenant. The admin read was fixed to the node's own tenant, so
// every other tenant's refusals went into the store and came out of nowhere — the operator saw only the
// node's, and a customer saw the node's filtered down to devices they own, which is empty by construction.
//
// A trust refusal is the one signal that says a certificate replacement is breaking devices. A tenant whose
// whole fleet was refusing the Edge showed a clean screen.
func TestTrustRefusalsAreReadForTheTenantAsked(t *testing.T) {
	store := &trustRefusalStore{by: map[string][]observedTrustRefusal{}}
	store.Merge("tenant_reference_lab", "mac-dev-1", []observedTrustRefusal{{Reason: "unknown_ca"}})
	store.Merge("tenant_northwind", "nw-laptop-001", []observedTrustRefusal{{Reason: "unknown_ca"}})
	store.Merge("tenant_northwind", "nw-laptop-002", []observedTrustRefusal{{Reason: "expired"}})

	lab := store.ForTenant("tenant_reference_lab")
	if len(lab) != 1 || len(lab["mac-dev-1"]) != 1 {
		t.Fatalf("the node's own tenant reads %v", lab)
	}

	// ★ The tenant that was invisible.
	nw := store.ForTenant("tenant_northwind")
	if len(nw) != 2 {
		t.Fatalf("Northwind's refusals read as %d rows — its devices were refusing the Edge and its screen "+
			"was clean: %v", len(nw), nw)
	}

	// ★ And whoever answers for the deployment sees every tenant's, because a refusal spanning the fleet is
	// precisely the one no single tenant's screen would reveal.
	all := store.All()
	if len(all) != 3 {
		t.Fatalf("the deployment-wide read holds %d devices, want 3: %v", len(all), all)
	}
	for _, id := range []string{"mac-dev-1", "nw-laptop-001", "nw-laptop-002"} {
		if len(all[id]) == 0 {
			t.Fatalf("%s is missing from the deployment-wide read: %v", id, all)
		}
	}

	// ★ THE CONTROL: a tenant that has none must read as none, not as everyone's. Without this the fix could
	// be "return everything to everybody", which reads as working and is the cross-tenant leak next door.
	if other := store.ForTenant("tenant_acme"); len(other) != 0 {
		t.Fatalf("a tenant with no refusals was shown %v", other)
	}
}
