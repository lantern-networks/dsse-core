package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestDedicatedControlPlaneConsoleUsesDeclaredRegionalEdge(t *testing.T) {
	for _, p := range []*Plan{oneRegionMultiEdgePlan(), threeRegionsMultiEdgePlan()} {
		t.Run(p.Profile, func(t *testing.T) {
			work := t.TempDir()
			planFile := filepath.Join(work, "plan.json")
			raw, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(planFile, raw, 0600); err != nil {
				t.Fatal(err)
			}
			source := filepath.Join(work, "source")
			installFromPlan(t, planFile, source)
			for _, region := range p.Regions {
				cp := region.controlPlane()
				archive := filepath.Join(work, cp.Name+".tgz")
				if err := carryPlanMachine(p, source, archive, cp.Name); err != nil {
					t.Fatal(err)
				}
				dir := unpackCarry(t, archive)
				if err := applyPlanToThisMachine(p, dir, cp.Name); err != nil {
					t.Fatal(err)
				}
				body := deploymentFileContents(t, dir, "docker-compose.yml")
				var parsed struct {
					Services map[string]struct {
						Environment map[string]string `yaml:"environment"`
						ExtraHosts  map[string]string `yaml:"extra_hosts"`
					}
				}
				if err := yaml.Unmarshal([]byte(body), &parsed); err != nil {
					t.Fatal(err)
				}
				if _, present := parsed.Services["dsse-edge-a"]; present {
					t.Fatal("CP has a local Edge")
				}
				env := readDeploymentEnv(dir)
				targets, err := readPlanNodeAdminTargets(env)
				if err != nil {
					t.Fatal(err)
				}
				console := parsed.Services["dsse-console"]
				got := console.Environment["ADMIN_API_UPSTREAM"]
				matched := false
				for _, target := range targets {
					if target.Role != "edge" {
						continue
					}
					host := target.Label + ".admin." + p.Deployment
					if got != "${DSSE_ADMIN_API_UPSTREAM:-https://"+host+"}" {
						continue
					}
					matched = true
					if console.ExtraHosts[host] != env["DSSE_FRONT_DOOR_A"] {
						t.Fatalf("%s has no declared Console route", host)
					}
					front := deploymentFileContents(t, dir, "haproxy-edge.cfg")
					if !strings.Contains(front, "verifyhost "+host) || !strings.Contains(front, target.Address) {
						t.Fatal("admin route does not authenticate its declared Edge")
					}
				}
				if !matched {
					t.Fatalf("%s Console cannot reach any Edge in its Region: %s", cp.Name, got)
				}
			}
		})
	}
}
