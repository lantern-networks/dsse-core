package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// every_topology_reaches_its_console_test.go — an administrator can open this deployment's Console from a
// machine this deployment steers, WHATEVER SHAPE the deployment was installed in.
//
// ★★★ THE STANDING RULE (operator, 2026-08-30): whatever topology is built from now on, the setting that
// lets a device reach this deployment's Console must be in it. It is not a property of the two-region lab
// that found it. Every device this product steers sends its traffic to an Edge; an Edge is a forward proxy to the
// public internet and refuses internal destinations; a sovereign deployment keeps its Console on the
// customer's own network. So on EVERY topology, the deployment must name its own Console as a destination the
// device does not steer — and the screens that could fix it by hand are behind the thing that is broken.
//
// Documented in docs/operations/a_steered_device_must_reach_its_own_console.ja.md. These are the assertions
// that keep the documentation true.

// Every machine shape this installer can be asked for. If a shape is added, add it here: the point of the
// table is that no topology gets to be the exception.
func everyMachineShape() map[string]machineShape {
	return map[string]machineShape{
		"founding region, edges on the same machine":  shapeFromFlags(false, "", false, false, false),
		"founding region, control plane only":         shapeFromFlags(true, "", false, false, false),
		"joining region, edges only":                  shapeFromFlags(false, "region-b", false, false, false),
		"joining region, edges only, control plane":   shapeFromFlags(true, "region-b", false, false, false),
		"joining region that holds state":             shapeFromFlags(false, "region-b", true, false, false),
		"joining region that holds state, CP machine": shapeFromFlags(true, "region-b", true, false, false),
		"joining region with a standby control plane": shapeFromFlags(false, "region-b", false, true, false),
	}
}

func TestEveryTopologyGivesItsDevicesTheConsole(t *testing.T) {
	for name, shape := range everyMachineShape() {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := writeComposeFileFor(dir, shape); err != nil {
				t.Fatalf("render compose: %v", err)
			}
			if err := writeLaunchScripts(dir); err != nil {
				t.Fatalf("render launch scripts: %v", err)
			}
			compose, err := os.ReadFile(filepath.Join(dir, composeFileName()))
			if err != nil {
				t.Fatalf("read compose: %v", err)
			}
			edge, err := os.ReadFile(filepath.Join(dir, "start-edge.sh"))
			if err != nil {
				t.Fatalf("read start-edge.sh: %v", err)
			}
			// The wiring lives in the one start script, so the assertion is that it is there AND that a shape
			// which runs Edges actually goes through it. A shape that grew its own edge command line would
			// silently drop this, which is precisely how a fix becomes true of one topology only.
			for _, want := range []string{"-admin-console-origins=", "$CONSOLE_ORIGINS", "$CONSOLE_ORIGIN "} {
				if !strings.Contains(string(edge), want) {
					t.Errorf("start-edge.sh does not carry %q: a device installed from this topology is never "+
						"told where its Console is, and loses it the moment steering comes up", want)
				}
			}
			if shape.runsEdges() && !strings.Contains(string(compose), "start-edge.sh") {
				t.Error("this topology runs Edges but does not start them with start-edge.sh, so the Console " +
					"wiring above never reaches them")
			}
		})
	}
}

// ★ AND THE DERIVATION HOLDS FOR ANY NUMBER OF REGIONS, not just the two the lab happened to have. Run, not
// read: a sed that produces nothing renders a flag with an empty value, which reads as configured.
func TestTheConsoleSetIsDerivedForAnyNumberOfRegions(t *testing.T) {
	edge, _ := launchScriptsForTest(t)
	fragment := extractShellFragment(t, edge, "CONSOLE_ORIGINS=\"\"", "\nCONSOLE_ORIGIN=\"\"")
	for _, tc := range []struct{ name, regions, want string }{
		{"one region", "a=https://agents.a.example",
			"-admin-console-origins=https://console.a.example"},
		{"two regions", "a=https://agents.a.example;b=https://agents.b.example",
			"-admin-console-origins=https://console.a.example,https://console.b.example"},
		{"three regions", "a=https://agents.a.example;b=https://agents.b.example;c=https://agents.c.example",
			"-admin-console-origins=https://console.a.example,https://console.b.example,https://console.c.example"},
		// A deployment that declares no regions at all is single-region and says nothing here; the Edge still
		// gets -admin-console-origin, so the one Console it has is covered. An empty flag would read as
		// configured, so the absence has to be an absence.
		{"no regions declared", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := "set -eu\nDSSE_REGION_ENDPOINTS='" + tc.regions + "'\nADMIN_CONSOLE_ORIGINS=''\n" +
				fragment + "\nprintf '%s' \"$CONSOLE_ORIGINS\"\n"
			out, err := exec.Command("/bin/sh", "-c", script).CombinedOutput()
			if err != nil {
				t.Fatalf("the derivation does not run under /bin/sh: %v\n%s", err, out)
			}
			if got := strings.TrimSpace(string(out)); got != tc.want {
				t.Errorf("regions %q derived %q, want %q", tc.regions, got, tc.want)
			}
		})
	}
}
