package main

import (
	"strings"
	"testing"
)

// ★★★ A NODE THAT CANNOT SEE THE MATERIAL MUST NOT UNDO A WITHDRAWAL (2026-08-21, measured).
//
// A scale-out Edge existed for half an hour. It is not on the per-organization material path, so it
// recomputed the announcement from what it holds — and the keep-filter, which carried per-organization
// anchors by testing for a 64-hex fingerprint, dropped "tenant=shared-anchor-withdrawn" because that value is
// twenty-two characters. The organization's bundle named the deployment-wide anchor again, the serial
// advanced, and win-dev-1 went from holding one anchor to two: roadmap D moved backwards because a node
// appeared under load.
//
// The guard here is the first case — without carrying the marker it fails exactly as the lab did.
func TestANodeThatCannotSeeTheMaterialKeepsAWithdrawal(t *testing.T) {
	fleetSaid := strings.Join([]string{
		"tenant_reference_lab=" + strings.Repeat("a", 64),
		"tenant_reference_lab=" + sharedAnchorWithdrawnMarker,
		"tenant_northwind=" + strings.Repeat("b", 64),
		"recovery-name-for-tenant_reference_lab=recovery.lab.dsse.invalid",
		"tenant_reference_lab@lab.dsse.invalid",
	}, ",")

	// This node holds none of the per-organization material, so it computes only its own answers.
	got := announcementKeepingWhatThisNodeCannotSee(
		[]string{"policy-keys=", "recovery-sni=recovery.dsse.invalid"}, fleetSaid, false)
	joined := strings.Join(got, ",")

	if !strings.Contains(joined, "tenant_reference_lab="+sharedAnchorWithdrawnMarker) {
		t.Fatalf("the withdrawal was dropped, so this node would put the deployment-wide anchor back into that "+
			"organization's bundle: %v", got)
	}
	for _, anchor := range []string{"tenant_reference_lab=" + strings.Repeat("a", 64),
		"tenant_northwind=" + strings.Repeat("b", 64)} {
		if !strings.Contains(joined, anchor) {
			t.Fatalf("an anchor this node cannot see was dropped: %v", got)
		}
	}
	// Its own answers are still its own: the name and the recovery SNI are not carried over from the fleet.
	if strings.Contains(joined, "lab.dsse.invalid Transport") || strings.Contains(joined, "@lab.dsse.invalid") {
		t.Fatalf("this node adopted an answer about itself from the fleet: %v", got)
	}
}

// A node that CAN see everything is authoritative and its answer stands — including a withdrawal it has
// genuinely stopped making, which is how a rotation ends.
func TestANodeThatSeesEverythingIsNotOverriddenByTheFleet(t *testing.T) {
	fleetSaid := "tenant_reference_lab=" + sharedAnchorWithdrawnMarker
	got := announcementKeepingWhatThisNodeCannotSee([]string{"tenant_reference_lab=" + strings.Repeat("c", 64)},
		fleetSaid, true)
	if strings.Contains(strings.Join(got, ","), sharedAnchorWithdrawnMarker) {
		t.Fatalf("a node on the material path had the fleet's older answer forced back onto it: %v", got)
	}
}
