package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
)

// ★★★ COMPOSE ITSELF IS ASKED WHETHER THE FILE IS A FILE (2026-09-02).
//
// Retiring the local haproxy that fronted a pair of control planes took an item out of the Console's
// depends_on and left the key behind, so the generator emitted `depends_on:` with nothing under it. Compose
// refuses the WHOLE file for that:
//
//	validating /opt/dsse/tokyo-west/docker-compose.yml: services.dsse-console.depends_on must be a array
//
// A deployment that cannot be parsed cannot be started, stopped or rolled — and it was found on a live
// machine, by a repair that had already written the broken file to disk, with the message naming the Console
// rather than the change that caused it. Every other gate here reads the text; none of them is the parser.
//
// So this one runs the parser, over every shape a machine can have. It needs docker, and it says so rather
// than passing when it is not there: a check that quietly does nothing is the thing it is guarding against.
func TestTheGeneratedFileIsValidCompose(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not on PATH — this gate asks compose itself and cannot run without it")
	}
	if out, err := exec.Command("docker", "compose", "version").CombinedOutput(); err != nil {
		t.Skipf("docker compose is not usable here (%v): %s", err, out)
	}
	for _, tc := range []struct {
		name  string
		shape machineShape
	}{
		{"a founding machine", foundingShape},
		{"a machine whose store spans regions", machineShape{holds: regionShapeStateBearing, edges: true, storeSpansRegions: true}},
		{"a joining region", machineShape{holds: regionShapeStateBearingJoin, edges: true, storeSpansRegions: true}},
		{"a warm control plane", machineShape{holds: regionShapeStandbyCP, edges: true}},
		{"a control-plane machine with no Edges", machineShape{holds: regionShapeStateBearing, edges: false, storeSpansRegions: true}},
		{"edges only", machineShape{holds: regionShapeEdgesOnly, edges: true}},
		{"edges behind the region's door", machineShape{holds: regionShapeEdgesOnly, edges: true, behindDoorway: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := writeComposeFileFor(dir, tc.shape); err != nil {
				t.Fatalf("render the compose file: %v", err)
			}
			if err := writeEnvironment(dir, []string{"localhost"}, nil); err != nil {
				t.Fatalf("render the environment file: %v", err)
			}
			if tc.shape.holds != regionShapeStateBearing {
				if err := setRegionEnvironment(dir, "region-b", tc.shape.holds == regionShapeStandbyCP, false); err != nil {
					t.Fatalf("prepare the region's environment: %v", err)
				}
			}
			// The images and secrets are the operator's; this gate is about the file's shape, so give the
			// required variables any value rather than asking compose to interpolate nothing.
			env, err := os.ReadFile(filepath.Join(dir, "deployment.env"))
			if err != nil {
				t.Fatalf("read the environment file: %v", err)
			}
			extra := "\nDSSE_IMAGE=dsse:test\nDSSE_CONSOLE_IMAGE=dsse-console:test\n"
			if err := os.WriteFile(filepath.Join(dir, "deployment.env"), append(env, []byte(extra)...), 0o600); err != nil {
				t.Fatal(err)
			}
			// ★ AND NO PLACEHOLDER SURVIVES. The generator threads a machine's shape in by replacing
			// __NAME__ markers; one that is never replaced is valid YAML and a broken deployment.
			rendered, err := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
			if err != nil {
				t.Fatal(err)
			}
			if m := regexp.MustCompile(`__[A-Z0-9_]+__`).FindString(string(rendered)); m != "" {
				t.Errorf("the generated file still contains the placeholder %s", m)
			}
			cmd := exec.Command("docker", "compose", "-f", filepath.Join(dir, "docker-compose.yml"),
				"--env-file", filepath.Join(dir, "deployment.env"), "config", "--quiet")
			cmd.Dir = dir
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("compose refuses the generated file: %v\n%s", err, out)
			}
		})
	}
}
