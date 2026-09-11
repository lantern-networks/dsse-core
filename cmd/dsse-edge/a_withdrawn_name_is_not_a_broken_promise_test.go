package main

import (
	"strings"
	"testing"
)

// ★★★ THIS TOOK BOTH LAB EDGES DOWN (2026-08-22, measured).
//
// A transport rename was abandoned on the control plane. The certificate went back to three names in the same
// minute; the fleet-wide announcement, which is durable and only changes when a RUNNING Edge recomputes it,
// still promised the abandoned one. Both Edges restarted inside that window, read a promise their own fresh
// material could not keep, and exited — the whole data plane, at once. The only way back was to re-create the
// name that had just been abandoned.
//
// The guard was right that the node could not serve the name. It was wrong about whose fault that was.
func TestAWithdrawnNameIsNotAPromiseThisNodeIsBreaking(t *testing.T) {
	const anchor = "1111111111111111111111111111111111111111111111111111111111111111"
	announced := "tenant_lab=" + anchor + ",tenant_lab@gone.invalid,tenant_lab@here.invalid"
	canServe := func(n string) bool { return n == "here.invalid" }
	yes := func(string) bool { return true }

	// This node holds the authority the fleet is announcing: its material is current, so "gone.invalid" is
	// gone from the control plane and nobody can serve it.
	current := fleetPromisesThisNodeCannotKeepWithAnchors(announced, canServe, yes,
		func(string) []string { return []string{anchor} })
	if len(current) != 0 {
		t.Fatalf("a node holding the announced authority must JOIN and publish the retraction, not exit: %v", current)
	}

	// ★ THE GUARD MUST STILL BITE for the case it was written for: a node that holds a DIFFERENT authority
	// cannot tell "the name was withdrawn" from "I am behind", and a node that is behind refuses devices.
	behind := fleetPromisesThisNodeCannotKeepWithAnchors(announced, canServe, yes,
		func(string) []string {
			return []string{"2222222222222222222222222222222222222222222222222222222222222222"}
		})
	if len(behind) == 0 {
		t.Fatal("a node whose material is NOT the announced one must still refuse to join — otherwise this " +
			"change disarmed the guard instead of correcting it")
	}
	found := false
	for _, m := range behind {
		if strings.Contains(m, "gone.invalid") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the withdrawn name should be the finding for a behind node, got %v", behind)
	}

	// ★ And with no anchor information at all — the oldest call shape — nothing may be excused.
	blind := fleetPromisesThisNodeCannotKeep(announced, canServe, yes)
	if len(blind) == 0 {
		t.Fatal("with no anchors to judge by, a node cannot excuse itself; it must refuse")
	}
}
