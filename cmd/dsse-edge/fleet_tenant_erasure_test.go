package main

import (
	"testing"
	"time"
)

// ★ THE MEASURED DEFECT (2026-08-15). Fleet membership is "whoever is reporting now", which is right for
// configuration — instances come and go, and one that stopped reporting has overwhelmingly been removed.
// Applied to ERASURE it is wrong, and the lab showed how: stopping region-b removed it from the fleet within
// one poll and the view went on answering in_sync=true. The same disappearance would have read as "every node
// holds nothing for this tenant", while a machine that is powered off still has the customer's logs on its
// disk and brings them back when it returns.
func TestANodeThatWentQuietKeepsAnErasureIncomplete(t *testing.T) {
	store := newFleetConfigStatusStore(10 * time.Second)
	start := time.Now().UTC()

	store.Record(fleetConfigReport{RegionID: "region-a", NodeID: "edge-a", Erasures: []fleetTenantErasure{
		{TenantID: "tenant_gone", Clean: true, Remaining: 0},
	}}, start)
	store.Record(fleetConfigReport{RegionID: "region-b", NodeID: "edge-b", Erasures: []fleetTenantErasure{
		{TenantID: "tenant_gone", Clean: false, Remaining: 3},
	}}, start)

	// While both are reporting: not complete, obviously.
	nodes, complete := store.TenantErasure("tenant_gone", start.Add(time.Second))
	if complete || len(nodes) != 2 {
		t.Fatalf("complete=%v nodes=%d — one node still holds three records", complete, len(nodes))
	}

	// edge-b goes away. It has dropped out of the FLEET list by now...
	later := start.Add(time.Hour)
	store.Record(fleetConfigReport{RegionID: "region-a", NodeID: "edge-a", Erasures: []fleetTenantErasure{
		{TenantID: "tenant_gone", Clean: true, Remaining: 0},
	}}, later)
	if entries := store.List(0, "", later); len(entries) != 1 {
		t.Fatalf("the fleet list should hold only the reporting node, got %d", len(entries))
	}
	// ...and its answer must NOT have gone with it.
	nodes, complete = store.TenantErasure("tenant_gone", later)
	if complete {
		t.Fatal("the erasure was reported COMPLETE while a node that held three records was merely switched off")
	}
	var sawStale bool
	for _, n := range nodes {
		if n.NodeID == "edge-b" {
			sawStale = n.Stale
			if n.Remaining != 3 {
				t.Fatalf("the quiet node's last answer changed: remaining=%d", n.Remaining)
			}
		}
	}
	if !sawStale {
		t.Fatal("the quiet node is not marked stale, so an operator cannot tell its answer is old")
	}
}

// Once every node that ever answered says clean, it is complete — the mechanism has to be able to reach yes,
// or an operator learns to ignore it.
func TestAnErasureIsCompleteWhenEveryAnsweringNodeIsClean(t *testing.T) {
	store := newFleetConfigStatusStore(10 * time.Second)
	now := time.Now().UTC()
	for _, node := range []string{"edge-a", "edge-b"} {
		store.Record(fleetConfigReport{NodeID: node, Erasures: []fleetTenantErasure{
			{TenantID: "tenant_gone", Clean: false, Remaining: 2},
		}}, now)
	}
	if _, complete := store.TenantErasure("tenant_gone", now); complete {
		t.Fatal("complete with two nodes still holding data")
	}
	for _, node := range []string{"edge-a", "edge-b"} {
		store.Record(fleetConfigReport{NodeID: node, Erasures: []fleetTenantErasure{
			{TenantID: "tenant_gone", Clean: true, Remaining: 0},
		}}, now.Add(time.Minute))
	}
	nodes, complete := store.TenantErasure("tenant_gone", now.Add(time.Minute))
	if !complete || len(nodes) != 2 {
		t.Fatalf("complete=%v nodes=%d — every node that answered is clean", complete, len(nodes))
	}
}

// Nobody answering is not completion. This is the same zero-case decision fleetInSync makes for an empty
// fleet, and for the same reason: an empty list and universal agreement render identically unless the zero
// case is decided on purpose.
func TestATenantNobodyHasAnsweredAboutIsNotComplete(t *testing.T) {
	store := newFleetConfigStatusStore(10 * time.Second)
	nodes, complete := store.TenantErasure("tenant_never_mentioned", time.Now().UTC())
	if complete || len(nodes) != 0 {
		t.Fatalf("complete=%v nodes=%d — nobody has answered, which is not evidence of anything", complete, len(nodes))
	}
}
