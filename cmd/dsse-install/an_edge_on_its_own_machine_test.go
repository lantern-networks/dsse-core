package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ★★★ THE SHAPE THAT EXISTS SO A MACHINE CAN RUN ONLY EDGES POINTED THEM AT A CONTAINER ON ANOTHER MACHINE
// (2026-08-27, measured by installing one). The default was
//
//	DSSE_CONTROL_PLANE: ${DSSE_CONTROL_PLANE:-https://dsse-control-plane:9443}
//
// which is the compose service in front of the control-plane pair. It exists on the control plane's machine
// and nowhere else, deployment.env writes no value to override it, and the Edges therefore come up pointed at
// a name they cannot resolve — having been installed exactly as generated.
//
// On one host the same default is exactly right, which is why it survived: every reader saw a deployment
// where it worked.
func TestAnEdgesOnlyMachineIsToldWhereTheAuthorityIs(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	compose := composeForShape(t, dir, machineShape{holds: regionShapeEdgesOnly, edges: true})

	if strings.Contains(compose, "DSSE_CONTROL_PLANE:-https://dsse-control-plane:") {
		t.Fatal("an Edges-only machine defaults to the control plane's CONTAINER name, which exists on another machine")
	}
	planes := planeNamesFor("dsse.example")
	for _, want := range []string{
		"DSSE_CONTROL_PLANE:-https://" + planes.Admin,
		"DSSE_CONTROL_PLANE_DATA:-https://" + planes.Authority,
	} {
		if !strings.Contains(compose, want) {
			t.Errorf("an Edges-only machine is not told %q", want)
		}
	}

	// ★★★ AND BOTH ARE ON 443. Every mouth of this deployment is 443 and the planes are separated by NAME; a
	// default carrying a port is the thing an enterprise proxy stops, for the administrator as much as for
	// the device.
	for _, line := range strings.Split(compose, "\n") {
		if !strings.Contains(line, "DSSE_CONTROL_PLANE") || !strings.Contains(line, "https://") {
			continue
		}
		if strings.Contains(line, ".dsse.example:") {
			t.Errorf("an Edges-only machine reaches the authority on a port rather than by name alone: %s",
				strings.TrimSpace(line))
		}
	}
}

// ★ AND THE ONE-HOST DEPLOYMENT IS UNTOUCHED. There the control plane IS on this machine, on the compose
// network, and naming it by its service is both correct and shorter than going out through the front door.
// Without this the fix above would be a change of default for every deployment rather than for the shape that
// needed it.
func TestAMachineThatHoldsAControlPlaneStillReachesItDirectly(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	compose := composeForShape(t, dir, machineShape{holds: regionShapeStateBearing, edges: true})
	// ★ IT NAMES THE CONTROL PLANE ITSELF (2026-09-02) — the proxy that stood in front of it on this machine
	// is gone, and the region's 443 door already finds the leader across the deployment.
	if !strings.Contains(compose, "DSSE_CONTROL_PLANE:-https://dsse-control-plane-a:9443") {
		t.Fatal("a machine that runs the control plane no longer reaches it on its own network")
	}
}

func composeForShape(t *testing.T, dir string, shape machineShape) string {
	t.Helper()
	body, err := composeBodyFor(dir, shape)
	if err != nil {
		t.Fatalf("render %v: %v", shape, err)
	}
	if body == "" {
		t.Fatal("the render produced nothing, so this test measures nothing")
	}
	// Sanity: the file on disk is not what is being read, or a shape that failed to render would be scored
	// against the founding machine's compose.
	onDisk, _ := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
	if shape != foundingShape && string(onDisk) == body {
		t.Fatal("the shape rendered identically to the founding machine's compose")
	}
	return body
}
