package main

import (
	"errors"
	"testing"
)

// ★★★ A CONNECTOR REACHES THE FLEET, AND A FLEET HAS MORE THAN ONE DOOR (the operator's instruction,
// 2026-08-26). It had one --edge-url and retried it for ever, so one region being away took everything behind
// that connector with it — in a deployment that exists in two regions precisely so that it need not.
func TestAConnectorMovesToTheNextDoorAndBack(t *testing.T) {
	doors := parseConnectorEndpoints("region-a=https://a.example;region-b=https://b.example")
	if doors.count() != 2 {
		t.Fatalf("want 2 doors, got %d", doors.count())
	}
	if doors.current() != "https://a.example" || doors.currentRegion() != "region-a" {
		t.Fatalf("the first door is not the operator's first choice: %q %q", doors.current(), doors.currentRegion())
	}

	doors.advance(errors.New("connection refused"))
	if doors.current() != "https://b.example" {
		t.Fatalf("it did not move to the second door: %q", doors.current())
	}

	// ★ AND IT COMES BACK. A connector that fails over and stays there leaves every flow crossing the mesh for
	// ever — correct, and slower and more fragile than it needs to be.
	doors.resetToPreferred()
	if doors.current() != "https://a.example" {
		t.Fatalf("it did not return to the first door: %q", doors.current())
	}

	// ★ THE FIRST FAILURE AFTER GOING HOME IS THE TUNNEL GOING HOME ENDED, and is not counted — see
	// TestGoingHomeIsNotEvidenceAgainstHome, and the outage that produced it: the connector decided to return
	// every three minutes and reconnected to the region it was leaving, because tearing the old tunnel down
	// was read as the new door failing. This line used to be part of the wrap below, which is why the loop
	// was possible to write.
	doors.advance(errors.New("use of closed network connection"))
	if doors.current() != "https://a.example" {
		t.Fatalf("the tunnel that going home ended was counted against home: %q", doors.current())
	}

	// Wrapping, so a two-door connector alternates rather than stopping at the end of the list.
	doors.advance(errors.New("x"))
	doors.advance(errors.New("x"))
	if doors.current() != "https://a.example" {
		t.Fatalf("advancing past the end did not wrap: %q", doors.current())
	}
}

// ★ ONE DOOR STAYS ONE DOOR. Announcing a failover to the same address would be a lie in the log, and the
// behaviour of a single-endpoint connector must be exactly what it was.
func TestASingleDoorConnectorIsUnchanged(t *testing.T) {
	doors := parseConnectorEndpoints("https://only.example")
	before := doors.current()
	doors.advance(errors.New("x"))
	if doors.current() != before {
		t.Fatalf("a single-door connector moved: %q -> %q", before, doors.current())
	}
}

// Order is the decision — it is the order a connector tries — so nothing sorts or de-duplicates it.
func TestTheOrderTheOperatorWroteIsTheOrderTried(t *testing.T) {
	doors := parseConnectorEndpoints(" region-c=https://c.example , region-a=https://a.example ;;  https://d.example ")
	want := []string{"https://c.example", "https://a.example", "https://d.example"}
	for i, w := range want {
		if got := doors.current(); got != w {
			t.Fatalf("door %d is %q, want %q", i, got, w)
		}
		doors.advance(errors.New("x"))
	}
}
