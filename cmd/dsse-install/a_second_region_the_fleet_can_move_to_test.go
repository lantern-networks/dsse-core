package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ★★★ THE SECOND REGION WAS DECORATION FOR THE FLEET (2026-08-30, reported by win-dev-1 from a real box).
//
// -steer-region-failover is the CP-signed posture that tells devices they may fail over. It is a START-UP
// flag on the Edge: there is no admin API for it, so a deployment that did not render it cannot be given
// region failover afterwards — the operator rebuilds or does without. Nothing in the generated launch scripts
// rendered it, so every deployment this installer has produced shipped with it OFF, however many regions the
// operator declared. The Windows agent could not be told to fail over at all; the Mac's own client-side
// controller armed itself and hid the gap.
func TestTheLaunchScriptsGiveDevicesTheRegionsTheDeploymentDeclares(t *testing.T) {
	edge, cp := launchScriptsForTest(t)
	for name, body := range map[string]string{"start-edge.sh": edge, "start-control-plane.sh": cp} {
		if !strings.Contains(body, "-steer-region-failover") {
			t.Errorf("%s never renders -steer-region-failover, so a deployment with two regions ships with "+
				"devices that cannot move between them and no way to turn it on short of a rebuild", name)
		}
		if !strings.Contains(body, "$REGION_FAILOVER") {
			t.Errorf("%s does not pass the derived value to the binary", name)
		}
		// Derived from the regions already declared — a second variable for the same fact is how the two come
		// to disagree, and this pair fails silently.
		if !strings.Contains(body, "DSSE_REGION_ENDPOINTS") {
			t.Errorf("%s asks for the fact twice instead of deriving it from the declared regions", name)
		}
	}
}

// One region must leave it absent: that is what the flag's default already means, and a single-region
// deployment telling its devices to fail over has nowhere to send them.
func TestOneRegionLeavesItOff(t *testing.T) {
	edge, _ := launchScriptsForTest(t)
	i := strings.Index(edge, "REGION_FAILOVER=\"\"")
	if i < 0 {
		t.Fatal("no REGION_FAILOVER derivation in start-edge.sh")
	}
	derivation := edge[i:]
	if j := strings.Index(derivation, "\nfi\n"); j > 0 {
		derivation = derivation[:j]
	}
	if !strings.Contains(derivation, "-gt 1") {
		t.Fatalf("the derivation does not require more than one region:\n%s", derivation)
	}
}

func launchScriptsForTest(t *testing.T) (edge, cp string) {
	t.Helper()
	dir := t.TempDir()
	if err := writeLaunchScripts(dir); err != nil {
		t.Fatalf("render launch scripts: %v", err)
	}
	read := func(name string) string {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return string(raw)
	}
	return read("start-edge.sh"), read("start-control-plane.sh")
}

// ★★★ AN ORGANIZATION HAD AS MANY INTERCEPTION ROOTS AS THE REGION HAD EDGE PROCESSES (2026-08-30, measured).
//
// The per-tenant interception root registry is in-memory unless -interception-per-tenant-root-dir names a
// directory, and the generated launch scripts never named one. On a region with two Edge processes behind one
// door that is worse than "lost on restart":
//
//	osaka-edge-a signs Sakura Foods under  0a8fc598…
//	the door's trust bundle announces      d5e54171…   (minted by osaka-edge-b)
//
// all different, none written down, and which one signs a device's traffic depends on which process the door
// picked. A device told to trust one fails on the others. Provisioning answered 200 four times on the way.
func TestAnOrganizationsInterceptionRootOutlivesTheProcessThatMintedIt(t *testing.T) {
	edge, _ := launchScriptsForTest(t)
	if !strings.Contains(edge, "-interception-per-tenant-root-dir=") {
		t.Fatal("start-edge.sh never names a directory for per-tenant interception roots, so each Edge process " +
			"mints its own and an organization's devices are told to trust a root that only one of them uses")
	}
	// It must be the durable edge state, not a temporary path: a root that does not outlive the deployment
	// directory is the same defect with a longer fuse.
	if !strings.Contains(edge, "DSSE_EDGE_STATE_DIR") {
		t.Fatal("the per-tenant root directory is not under the Edge's durable state")
	}
}

// ★★★ AND DURABLE IS NOT THE SAME AS SHARED (2026-08-30, measured after the first fix). Making the per-tenant
// interception roots durable stopped them being lost on restart and left a region with one root PER EDGE
// PROCESS: osaka-edge-a signed Sakura Foods under 0a8fc598… while the door's trust bundle announced
// d5e54171…, minted by osaka-edge-b. A device is told one fingerprint and any Edge may serve it. Durable and
// divergent is the same outage with a longer memory.
// ★ AND FROM 2026-09-02 A MACHINE RUNS ONE EDGE, so the property this was written for is about a shape that
// no longer exists on one host — a region is made redundant by another MACHINE behind the same doorway, not by
// a second container beside the first. The check is kept and inverted into its remaining form: however many
// Edge processes a file defines, they all mount the SAME directory. With one, that is one mount; with two it
// would be two of the same, and never one each.
func TestTheNodesEdgeProcessesShareOneSetOfInterceptionRoots(t *testing.T) {
	compose := composeTemplateForTest(t)
	edges := strings.Count(compose, "\n    entrypoint: [\"/deployment/start-edge.sh\"]")
	mounts := strings.Count(compose, `- "./interception-roots:/var/lib/dsse/interception-roots"`)
	if edges == 0 {
		t.Fatal("this compose defines no Edge process at all")
	}
	if mounts != edges {
		t.Fatalf("%d Edge process(es) and %d shared interception-root mount(s) — an Edge without it mints its "+
			"own, and which root signs a device's traffic depends on which process the door picked", edges, mounts)
	}
}

// ★★★ AND THE CONSOLE OF THE REGION THAT TAKES OVER (2026-08-30, the operator: when a region fails over,
// the Console of the region that took over has to open too).
//
// A steered device sends its traffic to an Edge, and an Edge refuses internal destinations — so an
// administrator on a managed machine reaches the Console only because the profile names it as a destination
// the device does not steer. Naming ONE region's Console is a fix that lasts until the region holding it is
// the one that failed, which is exactly when an administrator needs it. This asserts the shell actually
// derives the set, and derives it correctly: running the rendered fragment is the only way to know, because a
// sed that quietly produces nothing renders a flag with an empty value and reads as configured.
func TestTheLaunchScriptGivesDevicesEveryRegionsConsole(t *testing.T) {
	edge, _ := launchScriptsForTest(t)
	for _, want := range []string{"-admin-console-origins=", "$CONSOLE_ORIGINS", "ADMIN_CONSOLE_ORIGINS"} {
		if !strings.Contains(edge, want) {
			t.Errorf("start-edge.sh never renders %q, so a device is told about the Console of one region and "+
				"loses it when that region fails", want)
		}
	}

	// The derivation itself, run rather than read. Two regions declared the way an operator declares them.
	script := `set -eu
DSSE_REGION_ENDPOINTS='nagoya=https://agents.nagoya.example.test;fukuoka=https://agents.fukuoka.example.test'
ADMIN_CONSOLE_ORIGINS=''
` + extractShellFragment(t, edge, "CONSOLE_ORIGINS=\"\"", "\nCONSOLE_ORIGIN=\"\"") + `
printf '%s' "$CONSOLE_ORIGINS"
`
	out, err := exec.Command("/bin/sh", "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("the derivation does not run under /bin/sh: %v\n%s", err, out)
	}
	got := strings.TrimSpace(string(out))
	want := "-admin-console-origins=https://console.nagoya.example.test,https://console.fukuoka.example.test"
	if got != want {
		t.Errorf("the rendered script derives %q, want %q", got, want)
	}

	// And an operator who states them wins over anything derived: a deployment whose Console is not a label on
	// the agent host is exactly the case the derivation cannot serve.
	stated := `set -eu
DSSE_REGION_ENDPOINTS='nagoya=https://agents.nagoya.example.test'
ADMIN_CONSOLE_ORIGINS='https://admin-ui.example.test'
` + extractShellFragment(t, edge, "CONSOLE_ORIGINS=\"\"", "\nCONSOLE_ORIGIN=\"\"") + `
printf '%s' "$CONSOLE_ORIGINS"
`
	out, err = exec.Command("/bin/sh", "-c", stated).CombinedOutput()
	if err != nil {
		t.Fatalf("the derivation does not run under /bin/sh: %v\n%s", err, out)
	}
	if got, want := strings.TrimSpace(string(out)), "-admin-console-origins=https://admin-ui.example.test"; got != want {
		t.Errorf("a stated list was overridden by a derived one: got %q, want %q", got, want)
	}
}

// extractShellFragment lifts one block out of a rendered script so it can be RUN. Reading a shell fragment
// tells you it is present; running it tells you what it produces, and a sed that produces nothing renders a
// flag with an empty value that reads as configured.
func extractShellFragment(t *testing.T, script, from, to string) string {
	t.Helper()
	i := strings.Index(script, from)
	if i < 0 {
		t.Fatalf("the rendered script has no %q", from)
	}
	rest := script[i:]
	j := strings.Index(rest, to)
	if j < 0 {
		t.Fatalf("the rendered script has no %q after %q", to, from)
	}
	return rest[:j]
}
