package main

import (
	"testing"
	"time"
)

// The denominator a connector uses to say whether it covers its region's fleet. It must count DISTINCT nodes
// of the asked-for region, drop the ones that have gone quiet, and never inflate — an over-count turns "you
// are only on half your fleet" into a permanent, unreachable warning; an under-count merely stops the search
// early and says so.
func TestNodesInRegionCountsDistinctRecentReportersOfThatRegion(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	// The store keeps a report fresh for three poll intervals, so a one-minute poll means three minutes.
	store := newFleetConfigStatusStore(time.Minute)

	store.Record(fleetConfigReport{RegionID: "region-a", ClusterID: "c1", NodeID: "n1"}, now)
	store.Record(fleetConfigReport{RegionID: "region-a", ClusterID: "c1", NodeID: "n2"}, now)
	store.Record(fleetConfigReport{RegionID: "region-b", ClusterID: "c1", NodeID: "n3"}, now)

	if got := store.NodesInRegion("region-a", now); got != 2 {
		t.Fatalf("region-a: got %d, want 2", got)
	}
	if got := store.NodesInRegion("region-b", now); got != 1 {
		t.Fatalf("another region's nodes must not be counted: got %d, want 1", got)
	}

	// A node reporting again is the same node.
	store.Record(fleetConfigReport{RegionID: "region-a", ClusterID: "c1", NodeID: "n1"}, now.Add(time.Minute))
	if got := store.NodesInRegion("region-a", now.Add(time.Minute)); got != 2 {
		t.Fatalf("a repeat report must not add a node: got %d, want 2", got)
	}

	// A node that has gone quiet past the freshness window drops out rather than being carried.
	if got := store.NodesInRegion("region-a", now.Add(3*time.Minute+30*time.Second)); got != 1 {
		t.Fatalf("a node gone quiet must drop out: got %d, want 1", got)
	}

	// An unknown region, and an empty one, are zero — which every reader must treat as "not known".
	if got := store.NodesInRegion("region-z", now); got != 0 {
		t.Fatalf("region-z: got %d, want 0", got)
	}
	if got := store.NodesInRegion("  ", now); got != 0 {
		t.Fatalf("an unnamed region: got %d, want 0", got)
	}
}
