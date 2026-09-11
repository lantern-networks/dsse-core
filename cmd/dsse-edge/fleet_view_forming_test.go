package main

import (
	"testing"
	"time"
)

// ★ THE GUARD: prove the OLD behaviour is what this rejects.
//
// Measured 2026-08-25 on the generated two-region deployment: the leader was stopped, and fifteen seconds
// later /admin/fleet/config-status answered "2 edges, in_sync: true" — the whole fleet agreeing, computed
// over half of it, because the other two Edges had not yet reported to the node that had just been promoted.
func TestAFormingFleetViewIsNotAFleet(t *testing.T) {
	poll := 10 * time.Second
	store := newFleetConfigStatusStore(poll)
	// newFleetConfigStatusStore floors the window at 30s; that floor is the thing being asserted against.
	start := store.authoritySince

	if store.HasFormed(start) {
		t.Fatal("a store that has just started claims to know the fleet")
	}
	if store.HasFormed(start.Add(29 * time.Second)) {
		t.Fatal("a store 29s old claims to know the fleet, but a node is only considered gone after 30s")
	}
	if !store.HasFormed(start.Add(31 * time.Second)) {
		t.Fatal("a store older than its own freshness window still refuses to answer")
	}

	// And the half-fleet case end to end: two nodes report, both current, and that must NOT read as agreement
	// while the view is forming.
	for _, node := range []string{"edge-a", "edge-b"} {
		store.Record(fleetConfigReport{
			NodeID: node, RegionID: "region-a", Generation: 7, Epoch: "e", HaveApplied: true,
		}, start.Add(time.Second))
	}
	edges := store.List(7, "e", start.Add(2*time.Second))
	if len(edges) != 2 {
		t.Fatalf("want the two reports back, got %d", len(edges))
	}
	if !fleetInSync(edges) {
		t.Fatal("the two nodes that DID report disagree — this test can no longer show what it means to")
	}
	// fleetInSync is right about what it was given. The point is that what it was given is not the fleet.
	if store.HasFormed(start.Add(2 * time.Second)) {
		t.Fatal("two nodes reporting made the view claim to be complete")
	}
}

// A single control plane with no election has been the authority for as long as it has been running, so it
// must not spend its first thirty seconds refusing every question — that would make a fresh single-node
// deployment look broken on the walk that installs it.
func TestASingleAuthorityStillFormsOnItsOwnClock(t *testing.T) {
	store := newFleetConfigStatusStore(10 * time.Second)
	if !store.HasFormed(store.authoritySince.Add(31 * time.Second)) {
		t.Fatal("a node that has been running longer than its freshness window still says it does not know")
	}
	// cpLeaderElectorInstance is nil here — no election configured — and a nil elector must not be read as
	// "promoted just now", which would leave every single-node deployment permanently unformed.
	if got := cpLeaderElectorInstance.LeaderSince(); !got.IsZero() {
		t.Fatalf("a nil elector reported a promotion time: %v", got)
	}
}
