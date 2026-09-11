package main

import (
	"strings"
	"testing"
)

// ★★★ A SECOND REGION'S CONTROL PLANE HAD NO MACHINE OF ITS OWN (2026-08-27, found by trying to install one).
//
// "Control-plane-only" was a fifth REGION shape rather than a machine's role, so it could only describe the
// FOUNDING region. An operator standing up a second region with one component per machine had two commands
// and neither was right:
//
//	-region B -holds-state                  the control plane's machine also defines a fleet of Edges
//	-region B -control-plane-only           the region stands up its own consensus store — a second opinion
//	                                        about which database is primary, which is the one thing a joining
//	                                        region must not have
//
// A region kind and a machine's role are independent questions. Now they are two fields, and every
// combination an operator can ask for is expressible.
func TestAJoiningRegionsControlPlaneCanHaveItsOwnMachine(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	shape := shapeFromFlags(true, "region-b", true, false, false)
	if shape.holds != regionShapeStateBearingJoin {
		t.Fatalf("a control-plane machine in a joining region holds %v; the region joins, it does not found", shape.holds)
	}
	if shape.runsEdges() {
		t.Fatal("the Control Plane component's machine runs Edges")
	}
	compose := composeForShape(t, dir, shape)

	// Everything the Control Plane component IS.
	// ★ ONE OF EACH (2026-09-02): a pair on one machine survives a process crash and not the machine, and the
	// deployment answers the machine dying with the control plane in the next region.
	for _, want := range []string{"dsse-control-plane-a", "dsse-postgres-a",
		"dsse-clickhouse", "dsse-archive", "dsse-console"} {
		if !strings.Contains(compose, "\n  "+want+":") {
			t.Errorf("a joining region's Control Plane machine does not run %s", want)
		}
	}
	// ★★★ AND NO CONSENSUS STORE. There is ONE per deployment with a member per region; standing up a second
	// cluster here is a second opinion about which database is primary.
	if strings.Contains(compose, "\n  dsse-store-a:") {
		t.Error("a JOINING region stands up its own consensus store — that is a second deployment wearing " +
			"different clothes, and it is exactly what -control-plane-only used to do here")
	}
	// ★ AND NO EDGES BESIDE THE AUTHORITY.
	for _, unwanted := range []string{"dsse-edge-a", "dsse-edge-b"} {
		if strings.Contains(compose, "\n  "+unwanted+":") {
			t.Errorf("the Control Plane machine of a joining region defines %s", unwanted)
		}
	}
	// ★ THE DOORWAY IS STILL HERE, because it is not part of the Edge: every machine that serves a plane needs
	// a door to it.
	if !strings.Contains(compose, "\n  dsse-edge:") {
		t.Error("this machine serves the authority with no door to it")
	}
}

// ★ AND THE EDGE MACHINE OF THAT SAME REGION IS THE OTHER HALF. Together they are the region; neither of them
// is the whole of it, and that is the point.
func TestTheSameRegionsEdgeMachineHoldsNoAuthority(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	shape := shapeFromFlags(false, "region-b", false, false, false)
	if shape.holds != regionShapeEdgesOnly || !shape.runsEdges() {
		t.Fatalf("the Edge machine of a second region came out as %+v", shape)
	}
	compose := composeForShape(t, dir, shape)
	if !strings.Contains(compose, "\n  dsse-edge-a:") {
		t.Fatal("the Edge machine defines no Edge")
	}
	for _, unwanted := range []string{"dsse-control-plane-a", "dsse-postgres-a", "dsse-store-a", "dsse-console"} {
		if strings.Contains(compose, "\n  "+unwanted+":") {
			t.Errorf("the Edge machine defines %s, which belongs to the Control Plane's machine", unwanted)
		}
	}
}

// ★★ AND THE FOUNDING REGION'S TWO MACHINES STILL COME OUT RIGHT. The founding shape is the one every
// existing deployment was minted with; a change to how shapes are expressed must not move it.
func TestTheFoundingRegionsTwoMachinesAreUnchanged(t *testing.T) {
	cp := shapeFromFlags(true, "", false, false, false)
	if cp.holds != regionShapeStateBearing || cp.runsEdges() {
		t.Fatalf("the founding Control Plane machine came out as %+v", cp)
	}
	whole := shapeFromFlags(false, "", false, false, false)
	if whole.holds != regionShapeStateBearing || !whole.runsEdges() {
		t.Fatalf("the one-host reference came out as %+v — it is a real deployment many people run", whole)
	}
}
