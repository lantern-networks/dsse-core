package main

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
)

// Found 2026-11-08 on acceptance C: stopping the leader's entrance cost sign-in at all three entrances, because
// the Console beside the leader left for admin.<host> only through the door on its own machine. Every machine
// that serves a Console is told where the other doors are, and never told its own.
func assertConsoleDoorFallbacks(t *testing.T, who string, env map[string]string, want []string) {
	t.Helper()
	got := strings.TrimSpace(env["DSSE_CONSOLE_DOOR_FALLBACKS"])
	if got == "" {
		t.Fatalf("%s: the Console is given no other door, so its own stopped door locks every administrator out", who)
	}
	doors, err := newDoorListForTest(got)
	if err != nil {
		t.Fatalf("%s: %v", who, err)
	}
	if strings.Join(doors, ",") != strings.Join(want, ",") {
		t.Fatalf("%s: other doors = %v, want %v", who, doors, want)
	}
}

// newDoorListForTest reads the value the way the Console reads it: host:port, comma separated.
func newDoorListForTest(raw string) ([]string, error) {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		host, port, err := net.SplitHostPort(strings.TrimSpace(part))
		if err != nil || host == "" || port != "443" {
			return nil, err
		}
		out = append(out, net.JoinHostPort(host, port))
	}
	return out, nil
}

func TestEachNodesConsoleIsToldTheOtherNodesDoors(t *testing.T) {
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
		assertConsoleDoorFallbacks(t, m.Name, env, want)
		if strings.Contains(env["DSSE_CONSOLE_DOOR_FALLBACKS"], net.JoinHostPort(m.reachableAt(), "443")) {
			t.Errorf("%s: told its own door as another", m.Name)
		}
	}
}

func TestEachRegionsConsoleIsToldTheOtherRegionsDoors(t *testing.T) {
	p, err := LoadPlan(filepath.Join("..", "..", "docs", "plans", "three-regions-multi-edge.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range p.Regions {
		cp := r.controlPlane()
		env, err := p.MachineEnvironment(cp.Name)
		if err != nil {
			t.Fatal(err)
		}
		var want []string
		for _, other := range p.Regions {
			if other.ID != r.ID {
				want = append(want, net.JoinHostPort(other.controlPlane().reachableAt(), "443"))
			}
		}
		assertConsoleDoorFallbacks(t, cp.Name, env, want)
	}
}
