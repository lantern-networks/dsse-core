package main

import (
	"context"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/policyrule"
)

// ★★ AN ORGANIZATION'S ACCESS RULES OUTLIVED THE ORGANIZATION (2026-08-17, measured: deleted through the
// Console, and its rule was still on both planes carrying its id). The purge covers the Postgres tables, the
// credential store, the enrolled ledger and the log files; the authored-rule store is file-backed and was not
// among them.
//
// The count is asserted alongside the erasure, because "erase it" is only checkable against "how much was
// there" — an erasure measured only over the stores it happens to know about is measuring itself.
func TestDeletingAnOrganizationErasesTheRulesItAuthored(t *testing.T) {
	rules := policyrule.NewStore()
	mk := func(tenant, id string) {
		t.Helper()
		if _, err := rules.Upsert(policyrule.Rule{
			ID: id, TenantID: tenant, Plane: policyrule.PlaneEgress, Priority: 100,
			Source: []string{"*"}, Destination: []string{"*"}, ServiceID: "builtin-svc-https",
			Action: policyrule.Action{Access: "deny", Inspection: "inspect"}, Status: "active",
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	mk("tenant_going", "rule-going")
	mk("tenant_staying", "rule-staying")

	now := time.Now().UTC()
	before := countAdminTenantFootprint(context.Background(), "node", "tenant_going", nil, nil, nil, nil, rules, nil, nil, adminTenantExtraStores{}, now)
	if before.Total == 0 {
		t.Fatalf("the footprint must COUNT the authored rules, or completeness is measured over a set that excludes them: %+v", before)
	}

	result := purgeAdminTenantData(context.Background(), "node", "tenant_going", nil, nil, nil, nil, rules, nil, "", nil, nil, adminTenantExtraStores{}, nil, now)
	if len(result.Failures) != 0 {
		t.Fatalf("purge failures: %+v", result.Failures)
	}
	if got := rules.List("tenant_going", policyrule.PlaneEgress); len(got) != 0 {
		t.Fatalf("the deleted organization's rules survived: %+v", got)
	}
	if !result.Remaining.Clean() {
		t.Fatalf("the purge must be able to report itself complete, got %+v", result.Remaining)
	}

	// The control: nobody else's rules were touched.
	if got := rules.List("tenant_staying", policyrule.PlaneEgress); len(got) != 1 {
		t.Fatalf("another organization's rules were erased with it, got %+v", got)
	}
}
