package main

import "testing"

// ★ THE CASE THE COUNT CANNOT SEE. Two replicas, both beside the primary, is what a deployment with one
// state-bearing region looks like — and the redundancy check passes on it.
func TestCountingReplicasCannotAnswerWhetherARegionCanBeLost(t *testing.T) {
	sameRegion := []string{"region-a-postgres-a", "region-a-postgres-b"}
	if who, ok := replicaOutsideThisRegion(sameRegion, "region-a"); ok {
		t.Fatalf("both replicas are in region-a; %q was reported as elsewhere", who)
	}
	elsewhere := []string{"region-a-postgres-b", "region-b-postgres-a"}
	who, ok := replicaOutsideThisRegion(elsewhere, "region-a")
	if !ok {
		t.Fatal("a replica in region-b is the only kind that survives losing region-a, and it was not reported")
	}
	if who != "region-b-postgres-a" {
		t.Fatalf("the wrong member was named: %q", who)
	}
}

// ★ A NODE THAT DOES NOT KNOW ITS OWN REGION MUST NOT CLAIM ANYTHING. Answering "yes, elsewhere" because the
// comparison had nothing to compare against would report survivability that nobody established.
func TestANodeWithNoRegionClaimsNothing(t *testing.T) {
	if who, ok := replicaOutsideThisRegion([]string{"dsse-postgres-b"}, ""); ok {
		t.Fatalf("a node with no region of its own reported %q as being in another one", who)
	}
	// And a member from before per-region names is reported rather than counted as proof.
	if _, ok := replicaOutsideThisRegion([]string{"dsse-postgres-b"}, "region-a"); !ok {
		t.Fatal("a member whose name carries no region is not evidence of this region, and saying nothing " +
			"about it leaves an operator believing the check looked")
	}
}
