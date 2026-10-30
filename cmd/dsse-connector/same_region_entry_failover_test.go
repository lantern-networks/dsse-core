package main

import (
	"errors"
	"testing"
)

func TestSameRegionEntryFailurePreservesOtherEdgeTunnels(t *testing.T) {
	doors := parseConnectorEndpoints("hibari=https://node-a.example;hibari=https://node-b.example;hibari=https://node-c.example")
	moves := 0
	doors.SetOnMove(func() { moves++ })
	for _, want := range []string{"https://node-b.example", "https://node-c.example", "https://node-a.example"} {
		if got := doors.advance(errors.New("entry unavailable")); got != want {
			t.Fatalf("next entry = %q, want %q", got, want)
		}
		if moves != 0 {
			t.Fatalf("same-region entry switch evicted healthy Edge tunnels %d times", moves)
		}
	}
}

func TestReturningToPreferredEntryInSameRegionDoesNotHideNextFailure(t *testing.T) {
	doors := parseConnectorEndpoints("hibari=https://node-a.example;hibari=https://node-b.example")
	doors.advance(errors.New("a unavailable"))
	if doors.resetToPreferred() {
		t.Fatal("returning to an entry in the same DSSE Region must not evict tunnels")
	}
	if got := doors.advance(errors.New("a unavailable again")); got != "https://node-b.example" {
		t.Fatalf("a real failure after same-region failback was suppressed: %q", got)
	}
}

func TestDifferentAndUnnamedRegionsStillMoveHeldTunnels(t *testing.T) {
	for _, raw := range []string{
		"osaka=https://a.example;tokyo=https://b.example",
		"https://a.example;https://b.example",
	} {
		doors := parseConnectorEndpoints(raw)
		moves := 0
		doors.SetOnMove(func() { moves++ })
		doors.advance(errors.New("region unavailable"))
		if moves != 1 {
			t.Fatalf("%q: cross-region or unknown-region move must evict old tunnels, got %d", raw, moves)
		}
		if !doors.resetToPreferred() {
			t.Fatalf("%q: returning across a region boundary must retire old tunnels", raw)
		}
	}
}
