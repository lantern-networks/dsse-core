package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestThreeRegionsMultiEdgePacksDedicatedNodes(t *testing.T) {
	p := threeRegionsMultiEdgePlan()
	p.DataLayer = candidateDataLayer()
	// Different Region sizes must render independently, not assume two Edges.
	p.Regions[2].Machines = append(p.Regions[2].Machines, PlanMachine{Name: "edge-3-c", Holds: heldComponents{"edges"}, FailureDomain: "rack-c-3", Addresses: []string{"10.22.0.6"}, Reachable: "edge-3-c.dsse.example", ReachableAddress: "10.22.0.6"})
	work := t.TempDir()
	planPath := filepath.Join(work, "plan.json")
	data, _ := json.Marshal(p)
	if err := os.WriteFile(planPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(work, "source")
	installFromPlan(t, planPath, source)
	// Reapplying an already-admitted remote Edge on the founding door must
	// retain the local pool and must not invent an Edge on this CP host.
	before := deploymentFileContents(t, source, "haproxy-edge.cfg")
	if err := addAnEdgeToARunningRegion(source, planPath, p.Regions[1].Machines[1].Name); err != nil {
		t.Fatal(err)
	}
	if after := deploymentFileContents(t, source, "haproxy-edge.cfg"); after != before {
		t.Fatal("shared-fleet reapplication changed the admitted pool")
	}
	certificate := readCert(t, filepath.Join(source, "transport.crt"))
	for _, region := range p.Regions {
		if err := certificate.VerifyHostname(p.regionPortalName(region.ID)); err == nil {
			t.Fatalf("generated transport TLS SAN impersonates %s's browser Portal", region.ID)
		}
		if err := certificate.VerifyHostname(p.PlaneNamesFor(region.ID)["agents"]); err != nil {
			t.Fatalf("transport TLS SAN omits %s's agent entrance: %v", region.ID, err)
		}
	}
	for _, name := range certificate.DNSNames {
		if strings.HasPrefix(name, "portal-") {
			t.Fatal("certificate retains per-Edge Portal SANs")
		}
	}
	management := readCert(t, filepath.Join(source, "management.crt"))
	for _, portal := range p.BrowserPortalNames() {
		if err := management.VerifyHostname(portal); err == nil {
			t.Fatalf("management certificate covers browser Portal %q", portal)
		}
	}
	for _, r := range p.Regions {
		for _, m := range r.Machines {
			t.Run(m.Name, func(t *testing.T) {
				archive := filepath.Join(work, m.Name+".tar.gz")
				if err := carryPlanMachine(p, source, archive, m.Name); err != nil {
					t.Fatal(err)
				}
				dir := unpackCarry(t, archive)
				// Reapplying a carried plan must preserve node identities without CA keys.
				preserved := map[string][]byte{}
				for _, file := range []string{cpQuorumFile, cpQuorumKeyFile, storeMemberFile, storeMemberKeyFile, databaseServerFile, databaseServerKeyFile} {
					b, err := os.ReadFile(filepath.Join(dir, file))
					if err == nil {
						preserved[file] = b
					} else if !os.IsNotExist(err) {
						t.Fatal(err)
					}
				}
				if err := applyPlanToThisMachine(p, dir, m.Name); err != nil {
					t.Fatal(err)
				}
				for file, before := range preserved {
					after, err := os.ReadFile(filepath.Join(dir, file))
					if err != nil || !bytes.Equal(before, after) {
						t.Fatalf("reapply replaced node identity %s", file)
					}
				}
				env := readDeploymentEnv(dir)
				wantOrigins := "https://portal.region-a.dsse.example,https://portal.region-b.dsse.example,https://portal.region-c.dsse.example"
				if env["DSSE_STEPUP_PORTAL_ORIGINS"] != wantOrigins {
					t.Fatalf("signed Portal origin source is not one per Region: %q", env["DSSE_STEPUP_PORTAL_ORIGINS"])
				}
				compose := deploymentFileContents(t, dir, "docker-compose.yml")
				if env["DSSE_TOPOLOGY_PROFILE"] != p.Profile || env["DSSE_STEER_MUX_ONLY"] != "true" {
					t.Fatal("profile or mux-only gate lost in carry")
				}
				var aliases map[string]string
				if err := json.Unmarshal([]byte(env[planHostAliasesKey]), &aliases); err != nil {
					t.Fatal(err)
				}
				for _, peer := range p.machines() {
					if aliases[peer.Reachable] != peer.reachableAt() {
						t.Fatal("private peer resolution lost")
					}
				}
				for _, peerRegion := range p.Regions {
					wantDoor := peerRegion.controlPlane().reachableAt()
					if m.Holds.has("control-plane") && peerRegion.ID == r.ID {
						wantDoor = env["DSSE_FRONT_DOOR_A"]
					}
					if aliases[p.regionPortalName(peerRegion.ID)] != wantDoor {
						t.Fatal("shared Portal alias does not resolve to its owning Region doorway")
					}
				}
				targets, err := readPlanNodeAdminTargets(env)
				if err != nil || len(targets) != len(r.Machines) {
					t.Fatalf("owned admin surfaces: %v", err)
				}
				if m.Holds.has("control-plane") {
					for _, service := range []string{"dsse-store-a:", "dsse-postgres-a:", "dsse-control-plane-a:", "dsse-console:", "dsse-cp-unavailable:"} {
						if !strings.Contains(compose, "\n  "+service) {
							t.Errorf("missing %s", service)
						}
					}
					if strings.Contains(compose, "\n  dsse-edge-a:") {
						t.Fatal("CP also runs an Edge")
					}
					if !strings.Contains(compose, "./cp-quorum-key.pem:") {
						t.Fatal("CP quorum consumer identity not mounted")
					}
					for _, f := range []string{cpQuorumFile, cpQuorumKeyFile} {
						if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
							t.Fatal(err)
						}
					}
					var endpoints []string
					json.Unmarshal([]byte(env["DSSE_CP_QUORUM_ENDPOINTS"]), &endpoints)
					if len(endpoints) != 3 {
						t.Fatal("CP lacks three quorum endpoints")
					}
					front := deploymentFileContents(t, dir, "haproxy-edge.cfg")
					fleet := backendBlock(front, "edge_fleet")
					if strings.Contains(fleet, "balance source") || !strings.Contains(fleet, "balance leastconn") || strings.Contains(fleet, "dsse-edge-a") {
						t.Fatal("door does not balance only dedicated Edges")
					}
					if strings.Count(fleet, "    server ") != len(r.Machines)-1 {
						t.Fatal("front door must have exactly its Region's Edge fleet")
					}
					for _, edgeRegion := range p.Regions {
						for _, edge := range edgeRegion.Machines {
							if !edge.Holds.has("edges") {
								continue
							}
							included := strings.Contains(fleet, edge.reachableAt()+":8443")
							if included != (edgeRegion.ID == r.ID) {
								t.Fatalf("%s entrance Edge fleet has wrong Region membership for %s", r.ID, edge.Name)
							}
						}
					}
					for _, name := range []string{"cp_admin_plane", "cp_data_plane"} {
						block := backendBlock(front, name)
						if strings.Contains(block, ":443 ") || strings.Count(block, "    server ") != 3 || strings.Contains(block, "verify none") {
							t.Fatalf("%s does not authenticate direct CP backends", name)
						}
					}
					console := backendBlock(front, "console_plane")
					if !strings.Contains(console, "balance first") || !strings.Contains(console, "GET /ready") || strings.Count(console, "    server ") != 3 {
						t.Fatal("Console does not follow its active CP")
					}
					portal := backendBlock(front, "edge_region_portal")
					if strings.Count(portal, "    server ") != len(r.Machines)-1 || !strings.Contains(portal, "balance roundrobin") || strings.Contains(front, "edge_owned_portal_") {
						t.Fatal("shared Portal does not balance exactly the local Region Edge pool")
					}
					for _, portalRegion := range p.Regions {
						name := p.regionPortalName(portalRegion.ID)
						route := "use_backend edge_region_portal if { req.ssl_sni -i " + name + " }"
						reject := "tcp-request content reject if { req.ssl_sni -i " + name + " }"
						if portalRegion.ID == r.ID {
							if !strings.Contains(front, route) || strings.Contains(front, reject) {
								t.Fatalf("%s doorway does not serve only its own Portal SNI", r.ID)
							}
						} else if strings.Contains(front, route) || !strings.Contains(front, reject) {
							t.Fatalf("%s doorway accepts a foreign Portal SNI", r.ID)
						}
					}
					if strings.Index(front, "tcp-request content reject if { req.ssl_sni -i ") > strings.Index(front, "tcp-request content accept if { req_ssl_hello_type 1 }") {
						t.Fatal("foreign Portal rejection must run before ClientHello acceptance")
					}
					for _, edgeRegion := range p.Regions {
						for _, edge := range edgeRegion.Machines {
							if !edge.Holds.has("edges") {
								continue
							}
							included := strings.Contains(portal, edge.reachableAt()+":8443")
							if included != (edgeRegion.ID == r.ID) {
								t.Fatalf("%s entrance Portal pool has wrong Region membership for %s", r.ID, edge.Name)
							}
						}
					}
					checkThreeNodeHAProxySyntax(t, dir, len(r.Machines)-1)
				} else {
					for _, service := range []string{"dsse-store-a:", "dsse-postgres-a:", "dsse-control-plane-a:", "dsse-console:", "dsse-edge:"} {
						if strings.Contains(compose, "\n  "+service) {
							t.Fatalf("Edge carries %s", service)
						}
					}
					if !strings.Contains(compose, "\n  dsse-edge-a:") || !strings.Contains(compose, "${DSSE_EDGE_BIND:?") {
						t.Fatal("private Edge listeners missing")
					}
					if !strings.Contains(deploymentFileContents(t, dir, "start-edge.sh"), "export DSSE_STEER_MUX_ONLY=") {
						t.Fatal("direct Edge startup does not enforce mux-only routing")
					}
					for _, cpRegion := range p.Regions {
						trusted := strings.Split(env["DSSE_TRUSTED_FRONT_DOORS"], ",")
						included := false
						for _, address := range trusted {
							included = included || address == cpRegion.controlPlane().reachableAt()
						}
						if included != (cpRegion.ID == r.ID) {
							t.Fatal("Edge trusts a PROXY doorway outside its Region or omits its own")
						}
					}
					if env["DSSE_CLIENTLESS_BASE_URL"] != "https://"+p.edgePortalName(m) {
						t.Fatal("Edge has another owner's portal")
					}
					for _, f := range []string{cpQuorumKeyFile, storeClientKeyFile, databaseServerKeyFile} {
						if _, err := os.Stat(filepath.Join(dir, f)); !os.IsNotExist(err) {
							t.Errorf("Edge carries unrelated stateful identity %s", f)
						}
					}
					if env["DSSE_REGION_BIND_A"] != "" {
						t.Fatal("Edge accidentally has a public doorway bind")
					}
				}
				if _, err := exec.LookPath("docker"); err == nil {
					out, err := exec.Command("docker", "compose", "-f", filepath.Join(dir, "docker-compose.yml"), "--env-file", filepath.Join(dir, "deployment.env"), "config", "--quiet").CombinedOutput()
					if err != nil {
						t.Fatalf("invalid generated Compose: %v %s", err, out)
					}
				}
			})
		}
	}
}

func TestThreeRegionsMultiEdgeOrderAndVerificationReachTheRightHosts(t *testing.T) {
	p := threeRegionsMultiEdgePlan()
	steps := p.InstallOrder("/opt/dsse", "/opt/plan.json")
	for _, r := range p.Regions {
		for _, m := range r.Machines {
			if !m.Holds.has("edges") {
				continue
			}
			found := false
			for _, step := range steps {
				if step.Machine == m.Name && strings.Contains(step.Do, "-start-node") {
					found = true
					if !strings.Contains(step.Needs, "its own Region Portal name") || strings.Contains(step.Needs, "all three Portal names") {
						t.Fatalf("%s has wrong browser certificate instructions: %s", m.Name, step.Needs)
					}
				}
			}
			if !found {
				t.Fatalf("%s lacks a start-node instruction", m.Name)
			}
		}
	}
	lastPromotion, syncAt, firstEdge := -1, -1, len(steps)
	for i, s := range steps {
		if strings.Contains(s.Do, "member promote") {
			lastPromotion = i
		}
		if strings.Contains(s.Do, "synchronous_mode_strict=true") {
			syncAt = i
		}
		for _, r := range p.Regions {
			for _, m := range r.Machines {
				if m.Holds.has("edges") && strings.Contains(s.Do, "-machine "+m.Name) && i < firstEdge {
					firstEdge = i
				}
			}
		}
	}
	if lastPromotion < 0 || syncAt <= lastPromotion || firstEdge <= syncAt {
		t.Fatal("Edges can start before the three voters and synchronous database")
	}
	if strings.Contains(steps[3].Do, "dsse-edge-a") {
		t.Fatal("founder restart names an absent Edge")
	}
	if len(p.verifyEdges()) != 3 {
		t.Fatal("verification probes dedicated Edge addresses as public doorways")
	}
	admins := p.verifyEdgeAdmins()
	if len(admins) != 6 {
		t.Fatal("verification skipped an Edge")
	}
	for _, r := range p.Regions {
		for _, m := range r.Machines {
			if m.Holds.has("edges") {
				want := fmt.Sprintf("https://%s.admin.%s@%s", nodeAdminLabel(r.ID, m.Name, "edge-a"), p.Deployment, p.fromFounding(r.controlPlane(), r, 0))
				if !strings.Contains(strings.Join(admins, ","), want) {
					t.Fatalf("missing owned admin route %s", want)
				}
			}
		}
	}
}

func TestThreeRegionsMultiEdgeHostsShareTenantNamesAndKeepPrivateEdgesPrivate(t *testing.T) {
	p := threeRegionsMultiEdgePlan()
	ips := map[string]string{}
	for i, r := range p.Regions {
		ips[r.controlPlane().Name] = fmt.Sprintf("203.0.113.%d", i+1)
	}
	block, err := p.RenderClientHostsWithNodeIPs("203.0.113.1", ips, nil)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := parseClientHosts(block)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.validateClientHostEntries(entries, nil); err != nil {
		t.Fatal(err)
	}
	for _, m := range p.machines() {
		if strings.Contains(block, " "+m.Reachable+"\n") {
			t.Fatal("private node name exported to clients")
		}
	}
	for i, r := range p.Regions {
		if !strings.Contains(block, fmt.Sprintf("203.0.113.%d %s\n", i+1, p.regionPortalName(r.ID))) {
			t.Fatal("common Portal does not belong to its Region entry")
		}
	}
	if strings.Contains(block, " portal-") || strings.Count(block, " portal.") != 3 {
		t.Fatal("client names still depend on Edge count")
	}
	if _, err := p.RenderClientHostsWithNodeIPs("203.0.113.1", ips, []string{"tenant-a"}); err == nil {
		t.Fatal("per-tenant hostnames were accepted")
	}
	for i := range entries {
		if strings.HasPrefix(entries[i].Name, "agents.region-b.") {
			entries[i].IP = entries[0].IP
		}
	}
	if err := p.validateClientHostEntries(entries, nil); err == nil {
		t.Fatal("collapsed Region entries accepted")
	}
}
