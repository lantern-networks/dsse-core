package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// A door that reached the Console on its own machine through the machine's published address had that
// connection relayed by the container runtime's port proxy, so the Console saw the network gateway, not the
// door's fixed address, refused the PROXY header, and the door on the control-plane leader's machine had no
// Console at all. Each door reaches its own machine's Console over the container network; the other
// machines' Consoles keep their machine addresses, where the door's machine address arrives as it is.

func consoleServerLines(backend string) []string {
	var lines []string
	for _, line := range strings.Split(backend, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "server console") {
			lines = append(lines, strings.TrimSpace(line))
		}
	}
	return lines
}

func assertOneLocalConsole(t *testing.T, who, backend, local string) {
	t.Helper()
	lines := consoleServerLines(backend)
	if len(lines) == 0 {
		t.Fatalf("%s: no Console server lines:\n%s", who, backend)
	}
	containers := 0
	for _, line := range lines {
		if !strings.Contains(line, "send-proxy") {
			t.Errorf("%s: a Console is reached without the PROXY header: %s", who, line)
		}
		if strings.Contains(line, " dsse-console:8443 ") {
			containers++
			if !strings.Contains(line, "resolvers containers") {
				t.Errorf("%s: the local Console is named without the container resolver: %s", who, line)
			}
			continue
		}
		if local != "" && strings.Contains(line, " "+local+" ") {
			t.Errorf("%s: its own Console is still reached through the machine address %s: %s", who, local, line)
		}
	}
	if containers != 1 {
		t.Errorf("%s: %d Console servers on the container network, want exactly this machine's one:\n%s", who, containers, backend)
	}
}

func TestEachNodesDoorReachesItsOwnConsoleOverTheContainerNetwork(t *testing.T) {
	p, err := LoadPlan(filepath.Join("..", "..", "docs", "plans", "one-region-three-independent-entries.json"))
	if err != nil {
		t.Fatal(err)
	}
	seenLocal := map[string]bool{}
	var position []int
	for _, m := range p.Regions[0].Machines {
		env, err := p.MachineEnvironment(m.Name)
		if err != nil {
			t.Fatal(err)
		}
		local := env["DSSE_CONSOLE_LOCAL_BACKEND"]
		if local == "" || !strings.Contains(","+env["DSSE_CONSOLE_BACKENDS"]+",", ","+local+",") {
			t.Fatalf("%s: its own Console backend %q is not one of %q", m.Name, local, env["DSSE_CONSOLE_BACKENDS"])
		}
		if seenLocal[local] {
			t.Errorf("%s: names %s as its own Console, as another node already did", m.Name, local)
		}
		seenLocal[local] = true
		backend, err := oneRegionThreeNodesConsoleBackends(env["DSSE_CONSOLE_BACKENDS"], "console.example.test", consoleLocalBackend(env))
		if err != nil {
			t.Fatal(err)
		}
		assertOneLocalConsole(t, m.Name, backend, local)
		for i, line := range consoleServerLines(backend) {
			if strings.Contains(line, " dsse-console:8443 ") {
				position = append(position, i)
			}
		}
	}
	// The shared order still names the same Console in the same place on every door: node-a's door has its
	// own first, node-b's second, node-c's third.
	if len(position) != 3 || position[0] == position[1] || position[1] == position[2] || position[0] == position[2] {
		t.Errorf("the local Console moved the shared order: positions %v", position)
	}
}

func TestEachRegionsDoorReachesItsOwnConsoleOverTheContainerNetwork(t *testing.T) {
	p, err := LoadPlan(filepath.Join("..", "..", "docs", "plans", "three-regions-multi-edge.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, region := range p.Regions {
		cp := region.controlPlane()
		env, err := p.MachineEnvironment(cp.Name)
		if err != nil {
			t.Fatal(err)
		}
		local := env["DSSE_CONSOLE_LOCAL_BACKEND"]
		if local == "" || !strings.Contains(","+env["DSSE_CONSOLE_BACKENDS"]+",", ","+local+",") {
			t.Fatalf("%s: its own Console backend %q is not one of %q", cp.Name, local, env["DSSE_CONSOLE_BACKENDS"])
		}
		backend, err := oneRegionThreeNodesConsoleBackends(env["DSSE_CONSOLE_BACKENDS"], "console.example.test", consoleLocalBackend(env))
		if err != nil {
			t.Fatal(err)
		}
		assertOneLocalConsole(t, region.ID, backend, local)
	}
}

func TestTheSingleControlPlaneDoorReachesItsConsoleOverTheContainerNetwork(t *testing.T) {
	_, _, console, err := singleCPMultiEdgeBackends(map[string]string{"DSSE_CP_A_BIND": "10.0.0.1:"}, "admin.example.test", "console.example.test")
	if err != nil {
		t.Fatal(err)
	}
	assertOneLocalConsole(t, "one-region-multi-edge", console, "10.0.0.1:19544")
}

func TestALocalConsoleOutsideTheListIsRefused(t *testing.T) {
	if _, err := oneRegionThreeNodesConsoleBackends("10.20.0.1:19544,10.20.0.2:19544,10.20.0.3:19544", "console.example.test", "10.20.0.9:19544"); err == nil {
		t.Fatal("a local Console that is none of the backends was accepted; the door would reach its own Console through the machine address")
	}
	// Without the generated value, the Console's bind address and port name the local one.
	env := map[string]string{"DSSE_CONSOLE_BIND": "10.20.0.2:", "DSSE_CONSOLE_PORT": "19544"}
	if got := consoleLocalBackend(env); got != "10.20.0.2:19544" {
		t.Fatalf("fallback local Console = %q", got)
	}
}
