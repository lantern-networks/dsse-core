package main

import (
	"testing"

	"github.com/lantern-networks/dsse-core/policyrule"
)

// ★★★ AN AUTHORED RULE FOR ANY ORGANIZATION BUT THE NODE'S OWN NEVER BECAME A POLICY (2026-08-17, found by
// authoring one for a newly created organization through the Console). The recompile took its tenant from this
// node's policy bundle, so the rule was stored, listed and shown as "active · enforce" while nothing decided by
// it — the decision preview for the destination it denied came back with an empty trace.
//
// The store is the only thing that knows which organizations have rules, and it could not be asked. That is
// what Tenants() is for, and this is the property that made it necessary.
func TestTheRuleStoreNamesEveryOrganizationThatHasRules(t *testing.T) {
	store := policyrule.NewStore()
	mk := func(tenant, id string) {
		t.Helper()
		if _, err := store.Upsert(policyrule.Rule{
			ID: id, TenantID: tenant, Plane: policyrule.PlaneEgress, Priority: 100,
			Source: []string{"*"}, Destination: []string{"*"}, ServiceID: "builtin-svc-https",
			Action: policyrule.Action{Access: "deny", Inspection: "inspect"}, Status: "active",
		}); err != nil {
			t.Fatalf("seed %s/%s: %v", tenant, id, err)
		}
	}
	mk("tenant_reference_lab", "rule-lab")
	mk("tenant_contoso_ltd", "rule-contoso")
	mk("tenant_contoso_ltd", "rule-contoso-2")

	tenants := store.Tenants()
	if len(tenants) != 2 {
		t.Fatalf("every organization holding rules must be named, got %v", tenants)
	}
	seen := map[string]bool{}
	for _, x := range tenants {
		seen[x] = true
	}
	if !seen["tenant_reference_lab"] || !seen["tenant_contoso_ltd"] {
		t.Fatalf("both organizations must be named, got %v", tenants)
	}

	// And the rules themselves stay separated, which is what makes compiling per organization correct.
	if got := store.List("tenant_contoso_ltd", policyrule.PlaneEgress); len(got) != 2 {
		t.Fatalf("the second organization's rules must be its own, got %d", len(got))
	}
	if got := store.List("tenant_reference_lab", policyrule.PlaneEgress); len(got) != 1 {
		t.Fatalf("the node's own organization keeps its one rule, got %d", len(got))
	}
}
