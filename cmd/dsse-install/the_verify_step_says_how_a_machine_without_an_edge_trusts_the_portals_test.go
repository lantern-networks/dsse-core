package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// 0.4.1 acceptance D (2026-11-08): following the published order exactly, the final -verify failed on the Portals
// (0 of 9 pairs), because it runs on a control-plane machine that holds no Edge and so trusts no private Portal
// CA. The installer takes that CA with -portal-ca; the step that runs the check now says so.
func TestTheVerifyStepSaysHowAMachineWithoutAnEdgeTrustsThePortals(t *testing.T) {
	cases := map[string]bool{
		"three-regions-multi-edge.json":             true,
		"three-regions.json":                        false,
		"one-region-three-independent-entries.json": false,
		"single-region.json":                        false,
	}
	for file, wantHint := range cases {
		p, err := LoadPlan(filepath.Join("..", "..", "docs", "plans", file))
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		steps := orderOf(t, p)
		last := steps[len(steps)-1]
		if !strings.Contains(last.Do, "-verify") {
			t.Fatalf("%s: the last step is not the verification: %s", file, last.Do)
		}
		if got := strings.Contains(last.Needs, "-portal-ca"); got != wantHint {
			t.Errorf("%s: the verify step mentions -portal-ca = %v, want %v (the verifier machine holds an Edge: %v)",
				file, got, wantHint, !wantHint)
		}
	}
}
