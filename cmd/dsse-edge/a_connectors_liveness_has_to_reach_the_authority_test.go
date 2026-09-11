package main

import (
	"testing"
	"time"
)

// ★★★ A HEALTHY SITE READ "DOWN — 0 OF 2 CONNECTORS ONLINE" (2026-09-01, found on the Console).
//
// A connector's heartbeat never left the Edge node that received it, so the authority's copy stopped at
// registration and every connector read Offline with a frozen LAST HEARTBEAT while holding a live tunnel.
// Carrying every beat would be traffic; carrying none is what this was. So: a change always travels, and an
// unchanged connector travels at a floor.
func TestAConnectorsLivenessTravelsOnChangeAndAtAFloor(t *testing.T) {
	c := newConnectorLivenessCarrier()
	t0 := time.Date(2026, 9, 1, 2, 0, 0, 0, time.UTC)

	if !c.shouldCarry("conn-x", "online", "osaka", t0) {
		t.Fatal("the first beat was not carried — the authority would never hear of this connector at all")
	}
	if c.shouldCarry("conn-x", "online", "osaka", t0.Add(2*time.Second)) {
		t.Error("an unchanged beat two seconds later was carried; a connector beats far more often than an " +
			"operator needs the authority to know")
	}
	// ★ A CHANGE NEVER WAITS. Status and region are what a screen shows and what routing reads; delaying
	// either is the frozen-liveness defect again with a smaller number.
	if !c.shouldCarry("conn-x", "degraded", "osaka", t0.Add(3*time.Second)) {
		t.Error("a status change was held back by the floor")
	}
	if !c.shouldCarry("conn-x", "degraded", "tokyo-west", t0.Add(4*time.Second)) {
		t.Error("a region change was held back by the floor — the deployment would route to where it was")
	}
	// ★ AND STILL-ALIVE BECOMES A FACT THE AUTHORITY HOLDS, without being told every beat.
	if !c.shouldCarry("conn-x", "degraded", "tokyo-west", t0.Add(4*time.Second+connectorLivenessFloor)) {
		t.Error("an unchanged connector was never carried again, which is how LAST HEARTBEAT freezes")
	}
	// Each connector is remembered on its own: one busy connector must not silence another.
	if !c.shouldCarry("conn-y", "online", "osaka", t0.Add(5*time.Second)) {
		t.Error("a second connector's first beat was swallowed by the first connector's floor")
	}
}
