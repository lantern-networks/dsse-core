package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func oneRegionMultiEdgePlan() *Plan {
	p := threeRegionsMultiEdgePlan()
	p.Profile = "one-region-multi-edge"
	p.Regions = p.Regions[:1]
	return p
}

func TestOneRegionMultiEdgePlacementAndSharedPortal(t *testing.T) {
	p := oneRegionMultiEdgePlan()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if threeVoterProfile(p.Profile) {
		t.Fatal("single CP misrepresented as three voters")
	}
	for _, m := range p.machines() {
		env, err := p.MachineEnvironment(m.Name)
		if err != nil {
			t.Fatal(err)
		}
		if env["DSSE_STEPUP_PORTAL_ORIGINS"] != "https://portal.region-a.dsse.example" {
			t.Fatalf("unexpected origins: %q", env["DSSE_STEPUP_PORTAL_ORIGINS"])
		}
		if env["DSSE_CP_QUORUM_ENDPOINTS"] != "" {
			t.Fatal("single CP requires unavailable quorum")
		}
		if m.Holds.has("edges") && env["DSSE_CLIENTLESS_BASE_URL"] != "https://portal.region-a.dsse.example" {
			t.Fatal("Edge uses node-specific portal")
		}
	}
	for _, edit := range []func(*Plan){
		func(p *Plan) { p.Regions[0].Machines = p.Regions[0].Machines[:2] },
		func(p *Plan) { p.Regions[0].Machines[0].Holds = heldComponents{"control-plane", "edges"} },
		func(p *Plan) { p.Regions[0].Machines[1].Portal = "portal-node.example" },
		func(p *Plan) { p.Regions[0].Machines[1].Reachable = p.sharedPortalName() },
		func(p *Plan) { p.Regions[0].Machines[2].FailureDomain = p.Regions[0].Machines[1].FailureDomain },
	} {
		bad := oneRegionMultiEdgePlan()
		edit(bad)
		if err := bad.Validate(); err == nil {
			t.Fatal("invalid dedicated topology accepted")
		}
	}
}

func TestOneRegionMultiEdgePacksIndependentRoles(t *testing.T) {
	p := oneRegionMultiEdgePlan()
	work := t.TempDir()
	planFile := filepath.Join(work, "plan.json")
	data, _ := json.Marshal(p)
	if err := os.WriteFile(planFile, data, 0600); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(work, "deployment")
	installFromPlan(t, planFile, source)
	for _, m := range p.machines() {
		t.Run(m.Name, func(t *testing.T) {
			archive := filepath.Join(work, m.Name+".tar.gz")
			if err := carryPlanMachine(p, source, archive, m.Name); err != nil {
				t.Fatal(err)
			}
			dir := unpackCarry(t, archive)
			if err := applyPlanToThisMachine(p, dir, m.Name); err != nil {
				t.Fatal(err)
			}
			env := readDeploymentEnv(dir)
			if _, err := readPlanNodeAdminTargets(env); err != nil {
				t.Fatal(err)
			}
			body := deploymentFileContents(t, dir, "docker-compose.yml")
			if m.Holds.has("control-plane") {
				if strings.Contains(body, "\n  dsse-edge-a:") || strings.Contains(body, "./cp-quorum-key.pem:") {
					t.Fatal("CP renders Edge or false quorum")
				}
				front := deploymentFileContents(t, dir, "haproxy-edge.cfg")
				portal := backendBlock(front, "edge_region_portal")
				if strings.Count(portal, "    server ") != 2 || !strings.Contains(portal, "balance roundrobin") || strings.Contains(front, "edge_owned_portal_") {
					t.Fatal("Portal is not a two-Edge shared backend")
				}
				for _, e := range p.Regions[0].Machines[1:] {
					if !strings.Contains(portal, e.reachableAt()+":8443") {
						t.Fatal("Portal omits Edge")
					}
				}
				for _, name := range []string{"cp_admin_plane", "cp_data_plane"} {
					if strings.Count(backendBlock(front, name), "    server ") != 1 || strings.Contains(backendBlock(front, name), "verify none") {
						t.Fatal("CP traffic does not authenticate the sole CP")
					}
				}
				checkThreeNodeHAProxySyntax(t, dir, 2, 1)
			} else {
				for _, service := range []string{"dsse-store-a", "dsse-postgres-a", "dsse-control-plane-a", "dsse-console", "dsse-edge"} {
					if strings.Contains(body, "\n  "+service+":") {
						t.Fatalf("Edge includes %s", service)
					}
				}
				if !strings.Contains(body, "\n  dsse-edge-a:") || !strings.Contains(body, "./deployment-anchor.pem:") {
					t.Fatal("Edge deployment incomplete")
				}
				for _, name := range []string{cpQuorumKeyFile, storeClientKeyFile, databaseServerKeyFile} {
					if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
						t.Fatalf("Edge received state identity %s", name)
					}
				}
			}
		})
	}
}

func TestOneRegionMultiEdgeHostsAndInstallOrder(t *testing.T) {
	p := oneRegionMultiEdgePlan()
	cp := p.Regions[0].controlPlane()
	if _, err := p.RenderClientHosts("192.0.2.20", nil); err != nil {
		t.Fatal(err)
	}
	hosts, err := p.RenderClientHostsWithNodeIPs("192.0.2.20", map[string]string{cp.Name: "192.0.2.20"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := parseClientHosts(hosts)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.validateClientHostEntries(entries, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(hosts, "192.0.2.20 portal.region-a.dsse.example") || strings.Contains(hosts, "portal-edge-") {
		t.Fatal("client hosts lack common portal")
	}
	if _, err := p.ClientHostNames([]string{"tenant-a"}); err == nil {
		t.Fatal("per-tenant hostnames accepted")
	}
	if len(p.verifyEdges()) != 1 || len(p.verifyEdgeAdmins()) != 2 || len(p.verifyControlPlanes()) != 1 {
		t.Fatal("verification lost dedicated role owners")
	}
	steps := p.InstallOrder("/opt/dsse", "/opt/plan.json")
	if strings.Contains(steps[3].Do, "dsse-edge-a") {
		t.Fatal("founding CP restart includes absent Edge")
	}
	for _, step := range steps {
		if strings.Contains(step.Do, "member promote") || strings.Contains(step.Do, "synchronous_mode_strict=true") {
			t.Fatal("single CP order requires nonexistent state replicas")
		}
	}
}

func TestSharedRegionPortalRejectsAmbiguousTargets(t *testing.T) {
	for _, raw := range []string{
		`[{"name":"portal.example","address":"10.1.0.2"},{"name":"other.example","address":"10.1.0.3"}]`,
		`[{"name":"portal.example","address":"10.1.0.2"},{"name":"portal.example","address":"10.1.0.2"}]`,
		`[{"name":"portal.example","address":"10.1.0.2"},{"name":"portal.example","address":"0.0.0.0"}]`,
	} {
		if _, _, err := sharedRegionPortalRoutes(map[string]string{threeRegionPortalsKey: raw, "DSSE_EDGE_CHECK_TLS_NAME": "agents.example"}); err == nil {
			t.Fatal("ambiguous portal accepted")
		}
	}
}
