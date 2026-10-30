package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestMultiEdgePlanTellsEveryProfileIssuerAboutAllPortals(t *testing.T) {
	p := threeRegionsMultiEdgePlan()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	want := []string{"https://portal.region-a.dsse.example", "https://portal.region-b.dsse.example", "https://portal.region-c.dsse.example"}
	for _, r := range p.Regions {
		for _, m := range r.Machines {
			env, err := p.MachineEnvironment(m.Name)
			if err != nil {
				t.Fatal(err)
			}
			got := strings.Split(env["DSSE_STEPUP_PORTAL_ORIGINS"], ",")
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s profile issuer portal origins = %v, want %v", m.Name, got, want)
			}
			for _, origin := range got {
				if strings.Contains(env["ADMIN_CONSOLE_ORIGINS"], origin) {
					t.Errorf("%s added portal %s to Console CORS", m.Name, origin)
				}
			}
		}
	}
}

func TestOneRegionThreeNodesTellsEveryProfileIssuerAboutAllPortals(t *testing.T) {
	p := threeNodesOneRegionPlan()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	want := []string{"https://portal-a.example.test", "https://portal-b.example.test", "https://portal-c.example.test"}
	for _, m := range p.Regions[0].Machines {
		env, err := p.MachineEnvironment(m.Name)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Split(env["DSSE_STEPUP_PORTAL_ORIGINS"], ","); !reflect.DeepEqual(got, want) {
			t.Errorf("%s profile issuer portal origins = %v, want %v", m.Name, got, want)
		}
		for key, plane := range map[string]string{"DSSE_CONTROL_PLANE": "admin", "DSSE_CONTROL_PLANE_DATA": "authority"} {
			if env[key] != "https://"+p.PlaneNamesFor(p.Regions[0].ID)[plane] {
				t.Errorf("%s %s must use the elected Region doorway, got %q", m.Name, key, env[key])
			}
		}
		for _, origin := range want {
			if strings.Contains(env["ADMIN_CONSOLE_ORIGINS"], origin) {
				t.Errorf("%s added authentication Portal to Console CORS", m.Name)
			}
		}
	}
}

func TestEveryProfileLauncherPassesPortalOriginsSeparatelyFromConsoleCORS(t *testing.T) {
	dir := t.TempDir()
	if err := writeLaunchScripts(dir); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"start-edge.sh", "start-control-plane.sh"} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		s := string(raw)
		if !strings.Contains(s, "-step-up-portal-origins=$DSSE_STEPUP_PORTAL_ORIGINS") || !strings.Contains(s, "$CONSOLE_ORIGIN $CONSOLE_ORIGINS $STEPUP_PORTAL_ORIGINS") {
			t.Errorf("%s does not pass the explicit portal list to the profile issuer", name)
		}
	}
}

func TestStagedMachineRefreshesOldLaunchersWithoutChangingAuthoritySource(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatal(err)
	}
	old := []byte("#!/bin/sh\n# old installer launcher\n")
	if err := os.WriteFile(filepath.Join(dir, "start-control-plane.sh"), old, 0700); err != nil {
		t.Fatal(err)
	}
	staged, err := stageForMachine(dir, map[string]string{"DSSE_STEPUP_PORTAL_ORIGINS": "https://portal.example"})
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(staged)
	raw, err := os.ReadFile(filepath.Join(staged, "start-control-plane.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "$STEPUP_PORTAL_ORIGINS") {
		t.Fatal("carry still uses the old launcher, losing the portal origin flag")
	}
	source, err := os.ReadFile(filepath.Join(dir, "start-control-plane.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if string(source) != string(old) {
		t.Fatal("staging rewrote the source deployment")
	}
}
