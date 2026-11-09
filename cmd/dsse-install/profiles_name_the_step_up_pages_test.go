package main

import (
	"os/exec"
	"strings"
	"testing"
)

// Found 2026-11-04 walking the step-up on a Windows device enrolled in docs/plans/single-region.json: the
// Console's profile came from the control plane, which was never told where the Edges serve the sign-in page,
// so the agent refused every sign-in URL (invalid_or_expired_portal_request) and the held connection closed
// after two minutes without a browser opening.
func stepUpOriginsFromLaunch(t *testing.T, values map[string]string) string {
	t.Helper()
	_, cp := launchScriptsForTest(t)
	start := strings.Index(cp, "STEPUP_PORTAL_ORIGINS=\"\"")
	end := strings.Index(cp, "CONSOLE_ORIGIN=\"\"")
	if start < 0 || end <= start {
		t.Fatal("generated control-plane script has no step-up portal origin derivation")
	}
	cmd := exec.Command("sh", "-eu", "-c", cp[start:end]+"\nprintf '%s' \"$STEPUP_PORTAL_ORIGINS\"\n")
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	for key, value := range values {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("derivation failed: %v\n%s", err, raw)
	}
	return string(raw)
}

func TestTheControlPlaneNamesEveryRegionsStepUpPage(t *testing.T) {
	for _, file := range []string{"single-region.json", "three-regions.json"} {
		plan, err := LoadPlan("../../docs/plans/" + file)
		if err != nil {
			t.Fatal(err)
		}
		regionMap := plan.RegionEndpoints()
		want := []string{}
		for _, entry := range strings.Split(regionMap, ";") {
			_, door, _ := strings.Cut(entry, "=")
			want = append(want, door)
		}
		got := stepUpOriginsFromLaunch(t, map[string]string{
			"DSSE_REGION_ENDPOINTS": regionMap,
			"DSSE_AGENT_PLANE_NAME": "agents." + plan.Deployment,
			"EDGE_HOST":             plan.Deployment,
		})
		if got != "-step-up-portal-origins="+strings.Join(want, ",") {
			t.Errorf("%s: control plane step-up origins = %q, want every region's door %v", file, got, want)
		}
	}
}

func TestDeclaredStepUpPortalsStillWin(t *testing.T) {
	got := stepUpOriginsFromLaunch(t, map[string]string{
		"DSSE_STEPUP_PORTAL_ORIGINS": "https://portal-a.example.test,https://portal-b.example.test",
		"DSSE_REGION_ENDPOINTS":      "region-a=https://agents.region-a.example.test",
		"EDGE_HOST":                  "example.test",
	})
	if got != "-step-up-portal-origins=https://portal-a.example.test,https://portal-b.example.test" {
		t.Fatalf("declared portals were replaced: %q", got)
	}
}

func TestWithoutARegionMapTheDeploymentAgentNameIsThePage(t *testing.T) {
	got := stepUpOriginsFromLaunch(t, map[string]string{"EDGE_HOST": "example.test", "DSSE_AGENT_PLANE_NAME": "agents.example.test"})
	if got != "-step-up-portal-origins=https://agents.example.test" {
		t.Fatalf("no-map origin = %q", got)
	}
	got = stepUpOriginsFromLaunch(t, map[string]string{"EDGE_HOST": "example.test", "DSSE_REGION_PORT": "18443"})
	if got != "-step-up-portal-origins=https://example.test:18443" {
		t.Fatalf("no-map lab-port origin = %q", got)
	}
	if got = stepUpOriginsFromLaunch(t, map[string]string{}); got != "" {
		t.Fatalf("nothing to name, but derived %q", got)
	}
}
