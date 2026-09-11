package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ★★★ THE PLACE THAT ISSUES THE PROFILE HAS TO KNOW THE CONSOLE (2026-08-31, measured on a live deployment).
//
// A steered device sends everything to an Edge, which is a forward proxy to the public internet and refuses
// internal addresses — so an administrator on a managed machine loses the Console the moment the agent arms,
// and the screen that would fix it is on the other side of the thing that broke. The fix is that the profile
// names the Console as a destination the device does not steer.
//
// That was wired into the EDGE on 2026-08-30: its launcher derives the origins, its /admin/agent-profile route
// puts them in the profile. It never reached a device. The profile a device is actually given is issued by the
// CONTROL PLANE, whose launcher had no such derivation, so every profile went out with no passthrough_domains
// and every armed Mac loaded domain_count=0. On the deployment where this was measured the Edge held both
// flags, correctly derived, and console.<zone> still answered 502 through the tunnel.
//
// So the test is over BOTH launchers. Naming one of them is what produced the defect.
func TestEveryLauncherKnowsItsConsole(t *testing.T) {
	dir := t.TempDir()
	if err := writeLaunchScripts(dir); err != nil {
		t.Fatalf("writeLaunchScripts: %v", err)
	}
	for _, script := range []string{"start-control-plane.sh", "start-edge.sh"} {
		raw, err := os.ReadFile(filepath.Join(dir, script))
		if err != nil {
			t.Fatalf("reading %s: %v", script, err)
		}
		body := string(raw)
		// It must DERIVE the origins from the regions the operator already declared...
		if !strings.Contains(body, "ADMIN_CONSOLE_ORIGINS") || !strings.Contains(body, "DSSE_REGION_ENDPOINTS") {
			t.Errorf("%s does not derive the Console origins. A device given a profile from here cannot reach "+
				"the Console once it is steered, and the screen that fixes that is behind the same wall.", script)
		}
		// ...and it must actually PASS them, which is the half that was missing.
		if !strings.Contains(body, "$CONSOLE_ORIGIN $CONSOLE_ORIGINS") {
			t.Errorf("%s builds the Console origins and never hands them to the process. The flags exist, the "+
				"log looks right, and every profile it issues has no passthrough_domains.", script)
		}
	}
}
