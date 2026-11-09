package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Found 2026-11-08 on acceptance C's third walk: with the leader's entrance stopped, the Edge on that machine
// reached the control plane only through it, and lost sessions, configuration and revocations until it came
// back. Every Edge is told the door its names resolve to and the other doors, and never told its own door as
// another.
func assertEdgeDoors(t *testing.T, who string, env map[string]string, local string, want []string) {
	t.Helper()
	if got := strings.TrimSpace(env["DSSE_EDGE_LOCAL_DOORS"]); got != local {
		t.Fatalf("%s: this machine's door = %q, want %q", who, got, local)
	}
	got := strings.TrimSpace(env["DSSE_EDGE_DOOR_FALLBACKS"])
	if got == "" {
		t.Fatalf("%s: the Edge is given no other door", who)
	}
	doors, err := newDoorListForTest(got)
	if err != nil {
		t.Fatalf("%s: %v", who, err)
	}
	if strings.Join(doors, ",") != strings.Join(want, ",") {
		t.Fatalf("%s: other doors = %v, want %v", who, doors, want)
	}
	for _, d := range doors {
		if d == local {
			t.Fatalf("%s: its own door is listed as another", who)
		}
	}
}

func TestEachNodesEdgeIsToldItsDoorAndTheOthers(t *testing.T) {
	p, err := LoadPlan(filepath.Join("..", "..", "docs", "plans", "one-region-three-independent-entries.json"))
	if err != nil {
		t.Fatal(err)
	}
	machines := p.Regions[0].Machines
	for _, m := range machines {
		env, err := p.MachineEnvironment(m.Name)
		if err != nil {
			t.Fatal(err)
		}
		var want []string
		for _, other := range machines {
			if other.Name != m.Name {
				want = append(want, net.JoinHostPort(other.reachableAt(), "443"))
			}
		}
		assertEdgeDoors(t, m.Name, env, net.JoinHostPort(env["DSSE_FRONT_DOOR_A"], "443"), want)
	}
}

func TestEveryMachineOfThreeRegionsIsToldItsDoorAndTheOtherRegions(t *testing.T) {
	p, err := LoadPlan(filepath.Join("..", "..", "docs", "plans", "three-regions-multi-edge.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range p.Regions {
		var want []string
		for _, other := range p.Regions {
			if other.ID != r.ID {
				want = append(want, net.JoinHostPort(other.controlPlane().reachableAt(), "443"))
			}
		}
		for _, m := range r.Machines {
			env, err := p.MachineEnvironment(m.Name)
			if err != nil {
				t.Fatal(err)
			}
			// A control-plane machine's names resolve to the door beside it; an Edge machine's to its Region's
			// door on the control-plane machine.
			local := net.JoinHostPort(r.controlPlane().reachableAt(), "443")
			if m.Holds.has("control-plane") {
				local = net.JoinHostPort(env["DSSE_FRONT_DOOR_A"], "443")
			}
			assertEdgeDoors(t, m.Name, env, local, want)
		}
	}
}

// TestTheComposeFilePassesTheDoorsToTheEdgeAndTheControlPlane: a value the plan computes and the compose file
// never passes in is the same as no value — the shape of DSSE_CP_ENDPOINTS before it was wired.
func TestTheComposeFilePassesTheDoorsToTheEdgeAndTheControlPlane(t *testing.T) {
	b, err := os.ReadFile("compose.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"DSSE_EDGE_DOOR_FALLBACKS: ${DSSE_EDGE_DOOR_FALLBACKS:-}", "DSSE_EDGE_LOCAL_DOORS: ${DSSE_EDGE_LOCAL_DOORS:-}"} {
		if n := strings.Count(string(b), line); n != 2 {
			t.Errorf("%q appears %d time(s) in compose.go; the Edge and the control plane each need it", line, n)
		}
	}
}
