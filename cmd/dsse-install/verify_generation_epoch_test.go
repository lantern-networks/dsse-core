package main

import "testing"

func TestEdgeConfigurationGenerationRequiresCurrentEpoch(t *testing.T) {
	for _, tc := range []struct {
		name      string
		edgeGen   uint64
		edgeEpoch string
		cpGen     uint64
		cpEpoch   string
		current   bool
	}{
		{"same epoch and generation", 7, "new", 7, "new", true},
		{"same epoch but behind", 6, "new", 7, "new", false},
		{"old epoch has larger generation", 99, "old", 7, "new", false},
		{"new authority epoch is not yet reported", 99, "", 7, "new", false},
		{"legacy authority without epoch", 7, "", 7, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := edgeConfigurationCurrent(tc.edgeGen, tc.edgeEpoch, tc.cpGen, tc.cpEpoch); got != tc.current {
				t.Fatalf("current=%v, want %v for Edge generation %d epoch %q and CP generation %d epoch %q",
					got, tc.current, tc.edgeGen, tc.edgeEpoch, tc.cpGen, tc.cpEpoch)
			}
		})
	}
}
