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

func TestThreeRegionMultiEdgeConnectorEnrollmentUsesOwnedDoor(t *testing.T) {
	values := map[string]string{
		"DSSE_TOPOLOGY_PROFILE": "three-regions-multi-edge",
		"DSSE_REGION_ENDPOINTS": "a=https://agents.a.example.test;b=https://agents.b.example.test;c=https://agents.c.example.test",
		"DSSE_AGENT_PLANE_NAME": "agents.example.test",
		"DSSE_REGION_PORT":      "443",
	}
	got, err := connectorURLFromLaunch(t, values)
	if err != nil || got != "https://agents.a.example.test" {
		t.Fatalf("three-region default Connector URL = %q, %v", got, err)
	}
	values["DSSE_CONNECTOR_EDGE_URL"] = "https://agents.c.example.test"
	got, err = connectorURLFromLaunch(t, values)
	if err != nil || got != values["DSSE_CONNECTOR_EDGE_URL"] {
		t.Fatalf("owned override = %q, %v", got, err)
	}
	values["DSSE_CONNECTOR_EDGE_URL"] = "https://agents.example.test"
	if _, err = connectorURLFromLaunch(t, values); err == nil {
		t.Fatal("three-region enrollment accepted the unowned deployment name")
	}
	delete(values, "DSSE_CONNECTOR_EDGE_URL")
	delete(values, "DSSE_REGION_ENDPOINTS")
	if _, err = connectorURLFromLaunch(t, values); err == nil {
		t.Fatal("three-region enrollment accepted a missing region map")
	}
}

func TestSingleRegionMultiEdgeKeepsPublishedAgentDoorDefault(t *testing.T) {
	got, err := connectorURLFromLaunch(t, map[string]string{
		"DSSE_TOPOLOGY_PROFILE": "one-region-multi-edge",
		"DSSE_REGION_ENDPOINTS": "a=https://agents.a.example.test;b=https://agents.b.example.test",
		"DSSE_AGENT_PLANE_NAME": "agents.a.example.test",
		"DSSE_REGION_PORT":      "443",
	})
	if err != nil || got != "https://agents.a.example.test" {
		t.Fatalf("other topology Connector URL = %q, %v", got, err)
	}
}

// Found 2026-11-04 by installing docs/plans/single-region.json from the published 0.4.0 images: the default
// agents.<deployment> was not in the region map, so every Connector enrolment command was refused with 409.
func TestSingleMachineConnectorEnrollmentDefaultsToItsRegionDoor(t *testing.T) {
	plan, err := LoadPlan("../../docs/plans/single-region.json")
	if err != nil {
		t.Fatal(err)
	}
	regionMap := plan.RegionEndpoints()
	door := strings.SplitN(strings.SplitN(regionMap, ";", 2)[0], "=", 2)[1]
	values := map[string]string{
		"DSSE_REGION_ENDPOINTS": regionMap,
		"DSSE_AGENT_PLANE_NAME": "agents." + plan.Deployment, // what the generator writes; not a listed door
		"DSSE_EDGE_REGION":      plan.Regions[0].ID,
		"DSSE_REGION_PORT":      "443",
	}
	got, err := connectorURLFromLaunch(t, values)
	if err != nil || got != door {
		t.Fatalf("single-machine default Connector URL = %q, %v; want its region door %q", got, err, door)
	}

	// An operator's explicit choice is passed through unchanged; the control plane decides whether it is permitted.
	values["DSSE_CONNECTOR_EDGE_URL"] = "https://connectors.example.test"
	got, err = connectorURLFromLaunch(t, values)
	if err != nil || got != "https://connectors.example.test" {
		t.Fatalf("explicit Connector URL = %q, %v; want it unchanged", got, err)
	}
}

func TestCombinedThreeRegionsConnectorEnrollmentPrefersOwnRegionDoor(t *testing.T) {
	values := map[string]string{
		"DSSE_REGION_ENDPOINTS": "a=https://agents.a.example.test;b=https://agents.b.example.test;c=https://agents.c.example.test",
		"DSSE_AGENT_PLANE_NAME": "agents.example.test",
		"DSSE_EDGE_REGION":      "b",
		"DSSE_REGION_PORT":      "443",
	}
	got, err := connectorURLFromLaunch(t, values)
	if err != nil || got != "https://agents.b.example.test" {
		t.Fatalf("combined three-region default Connector URL = %q, %v; want this region's door", got, err)
	}
	delete(values, "DSSE_EDGE_REGION")
	got, err = connectorURLFromLaunch(t, values)
	if err != nil || got != "https://agents.a.example.test" {
		t.Fatalf("without a region the default should be the first listed door, got %q, %v", got, err)
	}
	delete(values, "DSSE_REGION_ENDPOINTS")
	got, err = connectorURLFromLaunch(t, values)
	if err != nil || got != "https://agents.example.test" {
		t.Fatalf("without a region map the legacy default should remain, got %q, %v", got, err)
	}
}
