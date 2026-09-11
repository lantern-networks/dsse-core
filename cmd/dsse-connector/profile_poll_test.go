package main

import (
	"testing"
)

// ★★★ THE DOORS ARE A DEPLOYMENT FACT AND THEY MOVE. A connector's list used to be whatever its one-time
// token carried, so a region added afterwards could never be failed over to.
func TestTheDoorListIsReplacedByTheDeploymentsAnswer(t *testing.T) {
	doors := parseConnectorEndpoints("region-b=https://b.example;region-a=https://a.example")

	// The same list again is not a change — a settled connector re-reads this every poll.
	if doors.replace(parseConnectorEndpoints("region-b=https://b.example;region-a=https://a.example")) {
		t.Fatal("an identical list must not count as a change")
	}
	if doors.replace(nil) || doors.replace(parseConnectorEndpoints("")) {
		t.Fatal("an empty answer must not wipe the doors this connector is using")
	}

	// A region added to the deployment reaches a connector already in the field.
	if !doors.replace(parseConnectorEndpoints("region-b=https://b.example;region-a=https://a.example;region-c=https://c.example")) {
		t.Fatal("a new region must reach a connector already enrolled")
	}
	if doors.count() != 3 {
		t.Fatalf("count: got %d", doors.count())
	}
	if got := doors.describe(); got != "region-b=https://b.example;region-a=https://a.example;region-c=https://c.example" {
		t.Fatalf("describe: %q", got)
	}
}

// ★ STAYING PUT MATTERS AS MUCH AS UPDATING. A connector that has failed over to the second region and is
// working there must not be moved back to the first every time it re-reads the list.
func TestReplacingTheDoorListKeepsThisConnectorWhereItIs(t *testing.T) {
	doors := parseConnectorEndpoints("region-b=https://b.example;region-a=https://a.example")
	doors.advance(errConnectorNodeAlreadyHeld) // now on region-a
	if doors.currentRegion() != "region-a" {
		t.Fatalf("fixture: on %q", doors.currentRegion())
	}

	// The deployment adds a region and re-orders. Position is kept by NAME, not by index.
	doors.replace(parseConnectorEndpoints("region-c=https://c.example;region-a=https://a.example;region-b=https://b.example"))
	if doors.currentRegion() != "region-a" {
		t.Fatalf("a working connector was moved off its door by a refreshed list: now on %q", doors.currentRegion())
	}
	// And its preferred door is the deployment's new first, so failback goes where the operator now says.
	if home, region := doors.preferred(); home != "https://c.example" || region != "region-c" {
		t.Fatalf("preferred: %q %q", home, region)
	}

	// A door that disappears from the list leaves this connector at the new first — there is nowhere else to be.
	doors.replace(parseConnectorEndpoints("region-c=https://c.example;region-b=https://b.example"))
	if doors.currentRegion() != "region-c" {
		t.Fatalf("after its door was removed the connector should start at the first: %q", doors.currentRegion())
	}
}
