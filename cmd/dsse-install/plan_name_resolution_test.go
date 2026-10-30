package main

import (
	"encoding/json"
	"go.yaml.in/yaml/v3"
	"os"
	"path/filepath"
	"testing"
)

func TestThreeNodePlanResolvesConsoleAndPeersWithoutHostEdits(t *testing.T) {
	p := threeNodesOneRegionPlan()
	work := t.TempDir()
	planFile := filepath.Join(work, "plan.json")
	b, _ := json.Marshal(p)
	if err := os.WriteFile(planFile, b, 0600); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(work, "source")
	installFromPlan(t, planFile, source)
	for _, name := range []string{"node-a", "node-b", "node-c"} {
		dir := source
		if name != "node-a" {
			archive := filepath.Join(work, name+".tgz")
			if err := carryPlanMachine(p, source, archive, name); err != nil {
				t.Fatal(err)
			}
			dir = unpackCarry(t, archive)
		}
		env := readDeploymentEnv(dir)
		if env[planHostAliasesKey] == "" {
			t.Fatal("carry lost the name-resolution plan")
		}
		body := string(beforeFile(t, dir, "docker-compose.yml"))
		var parsed struct {
			Services map[string]struct {
				ExtraHosts map[string]string `yaml:"extra_hosts"`
			}
		}
		if err := yaml.Unmarshal([]byte(body), &parsed); err != nil {
			t.Fatal(err)
		}
		for _, service := range []string{"dsse-store-a", "dsse-postgres-a", "dsse-control-plane-a", "dsse-edge-a", "dsse-console"} {
			aliases := parsed.Services[service].ExtraHosts
			for _, target := range p.nodeAdminTargets() {
				if aliases[target.Label+".admin."+p.Deployment] != env["DSSE_FRONT_DOOR_A"] {
					t.Fatalf("%s on %s lost admin alias %s", service, name, target.Label)
				}
			}
			if aliases["admin.example.test"] != env["DSSE_FRONT_DOOR_A"] || aliases["node-b.example.test"] != "10.20.0.2" || aliases["portal-c.example.test"] != env["DSSE_FRONT_DOOR_A"] {
				t.Fatalf("%s on %s cannot resolve declared planes/peers", service, name)
			}
		}
		if got := consoleEdgeUpstreamFor(dir, machineShape{}); got != "https://kiri-"+name+"-edge-a.admin.example.test" {
			t.Fatalf("%s Console asks the wrong Edge: %s", name, got)
		}
	}
}
