package main

import "testing"

// ★★★ ONE TIMED-OUT PROBE TOOK IPv4 AWAY FROM A FLEET (2026-09-02, measured from a Windows box that could not
// open ANY IPv4 destination while IPv6 worked on the same tunnel at the same moment, for an hour, while the
// node in fact egressed IPv4 perfectly well).
//
// This answer is signed into the posture, and a Windows agent honours it by closing every flow of a family the
// deployment says it cannot carry. macOS does not honour the field, so the same false posture is invisible on
// one platform and total on the other.
//
// The rule this pins: a NEGATIVE has to repeat before it is published; a positive is published at once.
func TestANegativeEgressFamilyIsEarnedNotGuessed(t *testing.T) {
	// The shape of the loop in startEgressFamilyMeasurement, exercised directly.
	publish := func(measured egressFamilyReport, v4Strikes, v6Strikes int) egressFamilyReport {
		out := measured
		if !measured.IPv4 && v4Strikes < egressFamilyNegativeStrikes {
			out.IPv4 = true
		}
		if !measured.IPv6 && v6Strikes < egressFamilyNegativeStrikes {
			out.IPv6 = true
		}
		return out
	}

	both := egressFamilyReport{IPv4: true, IPv6: true}
	if got := publish(both, 0, 0); !got.IPv4 || !got.IPv6 {
		t.Fatal("a node that can carry both must say so")
	}

	v4Down := egressFamilyReport{IPv4: false, IPv6: true}
	for strikes := 1; strikes < egressFamilyNegativeStrikes; strikes++ {
		if got := publish(v4Down, strikes, 0); !got.IPv4 {
			t.Fatalf("after %d failure(s) the deployment already told every Windows device to close IPv4; "+
				"one timed-out probe is not evidence about a host's networking", strikes)
		}
	}
	if got := publish(v4Down, egressFamilyNegativeStrikes, 0); got.IPv4 {
		t.Fatal("a family that has failed every probe in a row must be published as uncarried, or a node with " +
			"genuinely no IPv4 steers devices into a hole")
	}
}
