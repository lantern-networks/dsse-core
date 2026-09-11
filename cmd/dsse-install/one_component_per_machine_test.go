package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ★★★ THERE WAS NO SHAPE FOR "THE CONTROL PLANE, ALONE" (2026-08-27, found by standing the deployment up with
// one component per machine).
//
// Every shape that held a control plane also DEFINED the Edges. So the control plane's machine offered their
// admin ports, and the moment anything started the region doorway it started Edge processes beside the
// authority — measured, on the first two-machine deployment. The operator's constraint is that no two
// components share a machine, and it could not be expressed.
func TestAControlPlaneMachineDefinesNoEdges(t *testing.T) {
	dir := t.TempDir()
	foundingShape = machineShape{holds: regionShapeStateBearing, edges: false}
	defer func() { foundingShape = machineShape{holds: regionShapeStateBearing, edges: true} }()
	if err := run(dir, "dsse.lab", "Example", 3, false); err != nil {
		t.Fatalf("mint: %v", err)
	}
	compose := readCompose(t, dir)

	// Everything a Control Plane IS, by the operator's definition: the process, its database, its consensus
	// store, its hot store, its archive and its Console.
	// ★ ONE OF EACH (2026-09-02, the operator: "why are two control planes running on one machine with an
	// haproxy in front of them"). A pair on one host survives a process crash and not the host, and the
	// deployment already answers the host dying — every region holds a control plane and the authority is one
	// across them. The same argument retired the second database member beside the first.
	for _, want := range []string{"dsse-control-plane-a", "dsse-postgres-a",
		"dsse-store-a", "dsse-clickhouse", "dsse-archive", "dsse-console"} {
		if !strings.Contains(compose, "\n  "+want+":") {
			t.Fatalf("a Control Plane machine must run %s — it is part of what the word means here", want)
		}
	}
	// ★ AND THE DOORWAY IS HERE TOO, because it is not part of the Edge: it routes by the name in the
	// ClientHello, so it belongs with whatever planes the machine serves. Removing it with the Edges left a
	// machine offering the authority with no door to it — measured, on the first control-plane-only render.
	for _, want := range []string{"dsse-edge", "dsse-edge"} {
		if !strings.Contains(compose, "\n  "+want+":") {
			t.Fatalf("the Control Plane machine has no doorway (%s), so nothing presents admin, authority or "+
				"the Console on 443", want)
		}
	}
	// And nothing that belongs on an Edge's machine.
	for _, unwanted := range []string{"dsse-edge-a", "dsse-edge-b"} {
		if strings.Contains(compose, "\n  "+unwanted+":") {
			t.Fatalf("the Control Plane machine defines %s — its admin port is offered from here, and anything "+
				"that starts the doorway starts an Edge process beside the authority", unwanted)
		}
	}
	// ★ AND IT DOES NOT DECLARE STORAGE FOR THEM EITHER. A volume for a service this machine does not run
	// says the machine holds something it does not, in the one file somebody reads to find out.
	for _, vol := range []string{"edge-a-state:", "edge-b-state:"} {
		if strings.Contains(compose, "\n  "+vol) {
			t.Fatalf("storage is declared for %s on a machine that runs no Edge", vol)
		}
	}
	assertNoDanglingDependsOn(t, compose)
}

// ★ AND THE ONE-HOST REFERENCE IS UNCHANGED, because it is a real deployment that many people will run.
func TestTheOneHostReferenceStillCarriesEverything(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.lab", "Example", 3, false); err != nil {
		t.Fatalf("mint: %v", err)
	}
	compose := readCompose(t, dir)
	for _, want := range []string{"dsse-control-plane-a", "dsse-edge-a", "dsse-edge", "dsse-console"} {
		if !strings.Contains(compose, "\n  "+want+":") {
			t.Fatalf("the one-host reference lost %s", want)
		}
	}
}

func readCompose(t *testing.T, dir string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
	if err != nil {
		t.Fatalf("read compose: %v", err)
	}
	return string(raw)
}
