package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// ★★★ AN INSTALLER WHOSE OUTPUT CANNOT BE STARTED BY ITS OWN INSTRUCTIONS HAS NOT INSTALLED ANYTHING
// (2026-08-26, found by generating a deployment and running the command printed at the top of its compose
// file). The compose requires DSSE_IMAGE with `:?` — correctly, because a deployment that silently ran
// `latest` would be a fleet nobody chose — and nothing wrote it, so every generated deployment stopped on its
// first command:
//
//	error while interpolating services.dsse-control-plane-b.image:
//	required variable DSSE_IMAGE is missing a value
//
// The lab did not show it because a human had added the line by hand once, months ago, and the file was
// carried forward from there.
//
// This is the general form: every variable the compose REFUSES TO START WITHOUT must have a value in the
// environment file generated beside it. Written against the real generator rather than a list, so a new
// required variable is covered the day it is added.
// ★ EVERY SHAPE A REGION CAN HAVE, because the first version of this check looked only at the state-bearing
// one and passed while a JOINING region — the very next command in the printed procedure — stopped on
// DSSE_POSTGRES_DSN. A gate that covers one of three shapes reports the family closed while two thirds of it
// is open.
func TestEveryVariableTheComposeDemandsIsInTheGeneratedEnvironment(t *testing.T) {
	for _, shape := range []struct {
		name    string
		holding regionHolding
		standby bool
	}{
		{"the region that holds the state", regionShapeStateBearing, false},
		{"a joining region", regionShapeEdgesOnly, false},
		{"a joining region with a warm control plane", regionShapeStandbyCP, true},
	} {
		t.Run(shape.name, func(t *testing.T) {
			checkComposeAndEnvironmentAgree(t, shape.holding, shape.standby)
		})
	}
}

func checkComposeAndEnvironmentAgree(t *testing.T, holding regionHolding, standby bool) {
	t.Helper()
	dir := t.TempDir()
	if err := writeComposeFileFor(dir, machineShape{holds: holding, edges: true}); err != nil {
		t.Fatalf("render the compose file: %v", err)
	}
	if err := writeEnvironment(dir, []string{"localhost"}, nil); err != nil {
		t.Fatalf("render the environment file: %v", err)
	}
	if holding != regionShapeStateBearing {
		if err := setRegionEnvironment(dir, "region-b", standby, false); err != nil {
			t.Fatalf("prepare the region's environment: %v", err)
		}
	}
	compose, err := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	envRaw, err := os.ReadFile(filepath.Join(dir, "deployment.env"))
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, line := range strings.Split(string(envRaw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if name, _, ok := strings.Cut(line, "="); ok {
			have[strings.TrimSpace(name)] = true
		}
	}
	// ${NAME:?message} — the form that refuses to start.
	required := regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*):\?`)
	missing := []string{}
	seen := map[string]bool{}
	for _, m := range required.FindAllStringSubmatch(string(compose), -1) {
		name := m[1]
		if seen[name] {
			continue
		}
		seen[name] = true
		if !have[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("the generated compose refuses to start without %s, and the generated deployment.env does not "+
			"set %s — the first command this installer prints would fail", strings.Join(missing, ", "),
			map[bool]string{true: "them", false: "it"}[len(missing) > 1])
	}
	if len(seen) == 0 {
		t.Fatal("no ${VAR:?} was found in the generated compose — this check is looking at the wrong thing")
	}
}

// ★★★ THE PRINTED CHECK MUST BE THE CHECK THAT PASSES. Following the instruction this installer prints left a
// redundant authority reporting as a single point of failure, because the instruction omitted the flag that
// names the control planes — and through a front door the check cannot infer them. An operator was told to
// fix something that was not wrong and had nothing to do about it.
func TestThePrintedCheckNamesEveryControlPlane(t *testing.T) {
	dir := t.TempDir()
	if err := writeComposeFile(dir); err != nil {
		t.Fatal(err)
	}
	compose, err := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(compose), "-control-plane-peers") {
		t.Fatal("the compose file's own instructions do not pass -control-plane-peers, so following them " +
			"reports this deployment's authority as a single point of failure")
	}
}
