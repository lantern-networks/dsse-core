package main

import (
	"os/exec"
	"strings"
	"testing"
)

// Exercise the generated shell expression, since Console Add Connector sends
// no edge_url override and the single URL in its token is used for the first CSR.
func connectorURLFromLaunch(t *testing.T, values map[string]string) (string, error) {
	t.Helper()
	_, cp := launchScriptsForTest(t)
	start := strings.Index(cp, "# ★★★ WHERE A CONNECTOR DIALS")
	end := strings.Index(cp, "# ★★★ THE BREAK-GLASS")
	if start < 0 || end <= start {
		t.Fatal("generated control-plane script has no Connector URL derivation")
	}
	cmd := exec.Command("sh", "-eu", "-c", cp[start:end]+"\nprintf '%s' \"$DSSE_CONNECTOR_EDGE_URL\"\n")
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	for key, value := range values {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	raw, err := cmd.CombinedOutput()
	return string(raw), err
}

func TestOneRegionThreeNodesConnectorEnrollmentUsesOwnedDoor(t *testing.T) {
	plan, err := LoadPlan("../../docs/plans/one-region-three-independent-entries.json")
	if err != nil {
		t.Fatal(err)
	}
	regionMap := plan.RegionEndpoints()
	firstDoor := strings.SplitN(strings.SplitN(regionMap, ";", 2)[0], "=", 2)[1]
	common := map[string]string{
		"DSSE_TOPOLOGY_PROFILE": "one-region-three-nodes",
		"DSSE_REGION_ENDPOINTS": regionMap,
		"DSSE_AGENT_PLANE_NAME": "agents.example.test", // generated legacy name, not an owned door
		"DSSE_REGION_PORT":      "443",
	}
	got, err := connectorURLFromLaunch(t, common)
	if err != nil || got != firstDoor {
		t.Fatalf("three-node default Connector enrollment URL = %q, %v; want first owned door %q", got, err, firstDoor)
	}

	override := make(map[string]string, len(common)+1)
	for k, v := range common {
		override[k] = v
	}
	thirdDoor := strings.SplitN(strings.Split(regionMap, ";")[2], "=", 2)[1]
	override["DSSE_CONNECTOR_EDGE_URL"] = thirdDoor
	got, err = connectorURLFromLaunch(t, override)
	if err != nil || got != thirdDoor {
		t.Fatalf("owned Connector URL override = %q, %v; want %q", got, err, thirdDoor)
	}
	override["DSSE_CONNECTOR_EDGE_URL"] = "https://agents.example.test"
	if _, err = connectorURLFromLaunch(t, override); err == nil {
		t.Fatal("three-node Connector enrollment accepted an unowned default name")
	}
}

func TestOtherTopologiesKeepPublishedAgentDoorDefault(t *testing.T) {
	got, err := connectorURLFromLaunch(t, map[string]string{
		"DSSE_TOPOLOGY_PROFILE": "three-regions-multi-edge",
		"DSSE_REGION_ENDPOINTS": "a=https://agents.a.example.test;b=https://agents.b.example.test",
		"DSSE_AGENT_PLANE_NAME": "agents.a.example.test",
		"DSSE_REGION_PORT":      "443",
	})
	if err != nil || got != "https://agents.a.example.test" {
		t.Fatalf("other topology Connector URL = %q, %v", got, err)
	}
}
