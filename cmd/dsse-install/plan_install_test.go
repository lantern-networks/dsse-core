package main

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// plan_install_test.go — a deployment built from nothing but the description.
//
// ★★★ THIS IS THE WHOLE CLAIM, MEASURED (2026-08-28). Everything asserted here took a day to reach by hand on
// four machines, and every step of that day was a value typed onto a machine that the description already
// knew. If a plan cannot produce it, the plan is not the answer.

func writePlan(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "plan.json")
	body := `{
  "deployment": "dsse.example",
  "agent_publisher": "TEAMID1234",
  "regions": [
    { "id": "region-a", "founding": true, "holds_state": true, "machines": [
      { "name": "cp-a",   "holds": "control-plane", "addresses": ["10.20.1.1","10.20.1.2"], "reachable": "cp-a.dsse.example", "reachable_address": "203.0.113.1" },
      { "name": "edge-a", "holds": "edges",         "addresses": ["10.20.1.3","10.20.1.4"], "reachable": "edge-a.dsse.example", "reachable_address": "203.0.113.3" } ]},
    { "id": "region-b", "holds_state": true, "machines": [
      { "name": "cp-b",   "holds": "control-plane", "addresses": ["10.30.1.1","10.30.1.2"], "reachable": "cp-b.dsse.example", "reachable_address": "203.0.113.11" },
      { "name": "edge-b", "holds": "edges",         "addresses": ["10.30.1.3","10.30.1.4"], "reachable": "edge-b.dsse.example", "reachable_address": "203.0.113.13" } ]}
  ]
}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// installFromPlan is what the command line does, in one call, so the test measures the same path an operator
// takes rather than a private one.
func installFromPlan(t *testing.T, planPath, dir string) *Plan {
	t.Helper()
	plan, err := LoadPlan(planPath)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if err := run(dir, strings.Join(plan.CertificateNames(), ","), "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	if err := applyPlanToFoundingMachine(plan, dir); err != nil {
		t.Fatalf("apply: %v", err)
	}
	return plan
}

// ★★★ THE FOUNDING MACHINE IS A MACHINE TOO, and it is the one nobody thinks of. Every other machine gets its
// values when it is packed; this one is where the deployment was minted, so it kept the defaults — a doorway
// on a lab port, a consensus store on loopback, database members named the same as every other region's. A
// deployment whose FIRST region is the misconfigured one is the shape where nothing else can join it.
func TestTheFoundingMachineIsConfiguredByThePlanToo(t *testing.T) {
	work := t.TempDir()
	dir := filepath.Join(work, "region-a")
	plan := installFromPlan(t, writePlan(t, work), dir)

	env := deploymentFileContents(t, dir, "deployment.env")
	want := map[string]string{
		"DSSE_EDGE_REGION":      "region-a",
		"DSSE_REGION_BIND_A":    "10.20.1.1:",
		"DSSE_REGION_PORT":      "443",
		"DSSE_PG_A_NAME":        "dsse-pg-region-a-a",
		"DSSE_AGENT_PUBLISHER":  "TEAMID1234",
		"DSSE_ETCD_A_ADVERTISE": "https://cp-a.dsse.example:12379",
	}
	for key, value := range want {
		if !strings.Contains(env, key+"='"+value+"'") {
			t.Errorf("the founding machine was not given %s=%s:\n  %s", key, value, lineContaining(env, key))
		}
	}
	_ = plan
}

// ★★★ ITS DOORS NAME THE OTHER REGIONS. Written before the plan's values existed, and the writers leave a
// file that is already there alone — so a deployment installed from a plan had doors that knew only itself.
func TestTheFoundingMachinesDoorsNameTheOtherRegions(t *testing.T) {
	work := t.TempDir()
	dir := filepath.Join(work, "region-a")
	installFromPlan(t, writePlan(t, work), dir)

	// ★ REACHED AT THE PEER'S ADDRESS AND VERIFIED BY ITS NAME. These lines resolve nothing at run time.
	door := deploymentFileContents(t, dir, "haproxy-edge.cfg")
	for _, want := range []string{"203.0.113.11:443", "check-sni admin.region-b.dsse.example"} {
		if !strings.Contains(door, want) {
			t.Errorf("the region doorway does not reach the other region as %s, so this region cannot find "+
				"the leader when it is there", want)
		}
	}
	database := deploymentFileContents(t, dir, "haproxy-postgres.cfg")
	if !strings.Contains(database, "203.0.113.11:15433") {
		t.Errorf("the database door names no member in the other region, so this region stops entirely "+
			"whenever the primary is there:\n%s", database)
	}
}

// ★★★ THE CERTIFICATE CARRIES EVERY NAME THE DEPLOYMENT WILL EVER BE ASKED FOR. A name that resolves and does
// not verify is the same outage as one that does not resolve, and re-issuing later means restarting the
// nodes that present it.
func TestThePlannedDeploymentPresentsEveryNameItWillBeAskedFor(t *testing.T) {
	work := t.TempDir()
	dir := filepath.Join(work, "region-a")
	plan := installFromPlan(t, writePlan(t, work), dir)

	body, err := os.ReadFile(filepath.Join(dir, "transport.crt"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(body)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	carried := map[string]bool{}
	for _, n := range cert.DNSNames {
		carried[strings.ToLower(n)] = true
	}
	for _, r := range plan.Regions {
		for plane, name := range plan.PlaneNamesFor(r.ID) {
			if !carried[name] {
				t.Errorf("%s of %s (%s) is not in the certificate — the name resolves and nothing verifies",
					plane, r.ID, name)
			}
		}
	}
	for _, m := range plan.machines() {
		if m.Reachable != "" && !carried[strings.ToLower(m.Reachable)] {
			t.Errorf("%s is reached by the other regions as %s, which is not in the certificate", m.Name, m.Reachable)
		}
	}
}

// ★★★ AND EVERY MACHINE OF THE PLAN PACKS, each holding its own answers and none holding another's. This is
// the day's work in one assertion.
func TestEveryMachineOfThePlanPacksWithItsOwnAnswers(t *testing.T) {
	work := t.TempDir()
	dir := filepath.Join(work, "region-a")
	plan := installFromPlan(t, writePlan(t, work), dir)

	for _, region := range plan.Regions {
		for _, machine := range region.Machines {
			if region.Founding && machine.Holds.has("control-plane") {
				continue // this directory IS that machine
			}
			dest := filepath.Join(t.TempDir(), machine.Name+".tar.gz")
			if err := carryPlanMachine(plan, dir, dest, machine.Name); err != nil {
				t.Fatalf("%s: %v", machine.Name, err)
			}
			env := fileFromTarball(t, dest, "deployment.env")
			if !strings.Contains(env, "DSSE_EDGE_REGION='"+region.ID+"'") {
				t.Errorf("%s is in %s and was packed saying otherwise:\n  %s",
					machine.Name, region.ID, lineContaining(env, "DSSE_EDGE_REGION"))
			}
			// ★ ONLY A MACHINE THAT CARRIES A DOORWAY BINDS ONE (2026-09-02). A machine that runs only Edges
			// sits behind the region's front door and publishes no 443.
			if machine.Holds.has("control-plane") || !machine.Holds.has("edges") {
				if !strings.Contains(env, "DSSE_REGION_BIND_A='"+machine.Addresses[0]+":'") {
					t.Errorf("%s binds a door on an address that is not its own:\n  %s",
						machine.Name, lineContaining(env, "DSSE_REGION_BIND_A"))
				}
			}
			// ★ AND NOT ANOTHER MACHINE'S. The failure that made docker refuse to start was the lucky one; the
			// advertise values fail silently, by announcing this member at somebody else's address.
			for _, other := range plan.machines() {
				if other.Name == machine.Name {
					continue
				}
				for _, address := range other.Addresses {
					for _, line := range strings.Split(env, "\n") {
						key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
						if !ok || (!strings.Contains(key, "PUBLISH") && !strings.Contains(key, "BIND")) {
							continue
						}
						if strings.Contains(value, address) {
							t.Errorf("%s was packed with %s=%s, which is %s's address",
								machine.Name, key, value, other.Name)
						}
					}
				}
			}
		}
	}
}

// ★★★ THE FOUNDING MACHINE RUNS WHAT THE PLAN SAYS IT RUNS (2026-08-28, measured by shipping the minted
// directory to the machine the plan names). The founding install renders the shape it has always rendered —
// a region that holds state AND runs Edges — because nothing told it otherwise. The plan does. Shipped
// unchanged, the control-plane machine came up running an Edge fleet, which is the co-location every other
// part of this arrangement exists to end.
func TestTheFoundingMachineRunsOnlyWhatThePlanGivesIt(t *testing.T) {
	work := t.TempDir()
	dir := filepath.Join(work, "region-a")
	installFromPlan(t, writePlan(t, work), dir)

	// ★★ WHAT COUNTS AS "RUNNING AN EDGE" IS dsse-edge-a AND dsse-edge-b, AND NOTHING ELSE (2026-08-29, after
	// a false alarm cost half an hour on a live build). A control-plane machine's `docker ps` shows
	// dsse-edge-1 and dsse-edge-standby-1 and they are NOT Edges — composeRegionDoorwayWith names the region
	// DOORWAY that way, and it is haproxy, and it belongs here: it routes admin, authority and console by the
	// name in the ClientHello. A gate widened to "any service starting dsse-edge" forbids the door this
	// machine serves its own planes through.
	//
	// The reading is worth keeping: on a control-plane machine, dsse-edge* means the door, and an Edge process
	// is a container running the dsse:release image.
	compose := deploymentFileContents(t, dir, "docker-compose.yml")
	for _, edgeService := range []string{"\n  dsse-edge-a:", "\n  dsse-edge-b:"} {
		if strings.Contains(compose, edgeService) {
			t.Errorf("the founding CONTROL-PLANE machine defines %s — the plan says its Edges are on another "+
				"machine, and a node that does both is the co-location this deployment shape exists to end",
				strings.TrimSpace(edgeService))
		}
	}
	// ★ AND THE DOOR IS STILL HERE. Removing the Edges from a control-plane machine once took 443 with them,
	// so the machine offered the authority and had no door to it — see composeRegionDoorwayWith.
	if !strings.Contains(compose, "\n  dsse-edge:") {
		t.Error("the founding machine defines no region doorway — it would offer the authority on no port at all")
	}
	// ★ THE CONTROL: it still stands up the deployment's state, which is what founding means.
	for _, want := range []string{"dsse-control-plane-a:", "dsse-postgres-a:", "dsse-store-a:"} {
		if !strings.Contains(compose, want) {
			t.Errorf("the founding machine no longer stands up %s", want)
		}
	}
}

// ★★★ A MACHINE RUNS ITS OWN COMPONENT AND NOT ITS REGION'S (2026-08-28, measured: the Edge machine of the
// founding region came up running Postgres, etcd, ClickHouse and the archive, and no Edges at all). The two
// axes are not one — what the REGION holds is the control-plane machine's business; whether THIS MACHINE runs
// Edges is its own.
func TestEachMachineRunsItsOwnComponentAndNotItsRegions(t *testing.T) {
	work := t.TempDir()
	dir := filepath.Join(work, "region-a")
	plan := installFromPlan(t, writePlan(t, work), dir)

	state := []string{"dsse-postgres-a:", "dsse-store-a:", "dsse-clickhouse:", "dsse-archive:"}
	for _, region := range plan.Regions {
		for _, machine := range region.Machines {
			if region.Founding && machine.Holds.has("control-plane") {
				continue
			}
			// ★ A MACHINE THAT RUNS ONLY EDGES CARRIES NO DOORWAY (2026-09-02). It is behind the region's
			// front door — so there is no haproxy-edge.cfg in its tarball, and
			// asking for one is asking it to be a door again.
			if !machine.Holds.has("control-plane") && machine.Holds.has("edges") {
				continue
			}
			dest := filepath.Join(t.TempDir(), machine.Name+".tar.gz")
			if err := carryPlanMachine(plan, dir, dest, machine.Name); err != nil {
				t.Fatalf("%s: %v", machine.Name, err)
			}
			compose := fileFromTarball(t, dest, "docker-compose.yml")
			runsEdges := strings.Contains(compose, "\n  dsse-edge-a:")
			if machine.Holds.has("edges") {
				if !runsEdges {
					t.Errorf("%s holds the Edges and its compose defines none", machine.Name)
				}
				for _, s := range state {
					if strings.Contains(compose, "\n  "+s) {
						t.Errorf("%s runs Edges and was also given %s — a machine is ONE component", machine.Name, s)
					}
				}
				continue
			}
			if runsEdges {
				t.Errorf("%s holds the control plane and was also given the Edge processes", machine.Name)
			}
			if !strings.Contains(compose, "\n  dsse-control-plane-a:") {
				t.Errorf("%s holds the control plane and its compose defines none", machine.Name)
			}
		}
	}
}

// ★★★ EACH MACHINE'S DOORS ARE RENDERED FOR ITS OWN REGION (2026-08-28, measured on a deployment built from a
// plan). haproxy-edge.cfg lives in the minting directory, generated for the region that minted it — so every
// machine of every other region was packed with the founding region's doorway. It routed the founding
// region's plane names, named the founding region's peers, and sent this region's own names to a backend with
// no servers:
//
//	agents.region-b.dsse.lab -> region edge_fleet/<NOSRV>
//
// The name resolved, the certificate verified, and nothing served it.
func TestEachMachineCarriesADoorwayForItsOwnRegion(t *testing.T) {
	work := t.TempDir()
	dir := filepath.Join(work, "region-a")
	plan := installFromPlan(t, writePlan(t, work), dir)

	for _, region := range plan.Regions {
		for _, machine := range region.Machines {
			if region.Founding && machine.Holds.has("control-plane") {
				continue
			}
			// A machine that runs only Edges carries no doorway.
			if !machine.Holds.has("control-plane") && machine.Holds.has("edges") {
				continue
			}
			dest := filepath.Join(t.TempDir(), machine.Name+".tar.gz")
			if err := carryPlanMachine(plan, dir, dest, machine.Name); err != nil {
				t.Fatalf("%s: %v", machine.Name, err)
			}
			door := fileFromTarball(t, dest, "haproxy-edge.cfg")
			// It answers its OWN region's names …
			for _, plane := range []string{"admin", "authority", "agents"} {
				want := plane + "." + region.ID + "." + plan.Deployment
				if !strings.Contains(door, want) {
					t.Errorf("%s of %s does not answer %s — the name resolves and nothing serves it",
						machine.Name, region.ID, want)
				}
			}
			// … and reaches the OTHER regions, rather than naming its own as a peer.
			for _, other := range plan.Regions {
				if strings.EqualFold(other.ID, region.ID) {
					continue
				}
				if !strings.Contains(door, "authority."+other.ID+"."+plan.Deployment) {
					t.Errorf("%s of %s cannot reach %s's authority, so it has no route to the leader when it "+
						"is there", machine.Name, region.ID, other.ID)
				}
			}
			if strings.Contains(door, "cp-data-peer-1 authority."+region.ID+".") {
				t.Errorf("%s of %s names its OWN region as the peer to cross to", machine.Name, region.ID)
			}
		}
	}
}

// ★★★ EVERY DOOR ANSWERS EVERY REGION'S NAMES (2026-08-28, measured on a cross-region hop). The hop is layer
// 4 — the stream is passed through byte for byte, which is what keeps a device's client certificate intact —
// so the name arriving at the receiving door is the one the CLIENT asked for, not the peer's:
//
//	admin.region-b.dsse.lab -> cp_admin_plane/cp-peer-1 -> region-a's door -> edge_fleet/<NOSRV>
//
// A door that knew only its own region dropped every hop it was the target of. Rewriting the SNI would mean
// terminating TLS at the door, which this arrangement exists not to do.
func TestEveryDoorAnswersEveryRegionsNames(t *testing.T) {
	work := t.TempDir()
	dir := filepath.Join(work, "region-a")
	plan := installFromPlan(t, writePlan(t, work), dir)

	check := func(who, door string) {
		for _, r := range plan.Regions {
			for _, plane := range []string{"admin", "authority", "agents"} {
				name := plane + "." + r.ID + "." + plan.Deployment
				if !strings.Contains(door, "req.ssl_sni -i "+name) {
					t.Errorf("%s does not answer %s — a cross-region hop carrying that name ends in a backend "+
						"with no servers", who, name)
				}
			}
		}
	}
	check("the founding machine", deploymentFileContents(t, dir, "haproxy-edge.cfg"))
	for _, region := range plan.Regions {
		for _, machine := range region.Machines {
			if region.Founding && machine.Holds.has("control-plane") {
				continue
			}
			// A machine that runs only Edges carries no doorway.
			if !machine.Holds.has("control-plane") && machine.Holds.has("edges") {
				continue
			}
			dest := filepath.Join(t.TempDir(), machine.Name+".tar.gz")
			if err := carryPlanMachine(plan, dir, dest, machine.Name); err != nil {
				t.Fatalf("%s: %v", machine.Name, err)
			}
			check(machine.Name, fileFromTarball(t, dest, "haproxy-edge.cfg"))
		}
	}
}

// ★★★ AND THE PEERS ARE REACHED AT AN ADDRESS WHILE VERIFYING A NAME (2026-08-28, measured). These server
// lines carry no resolvers, deliberately — with a resolvers section haproxy will not hand one address to two
// servers in a backend — so a bare name is resolved once, at start-up, inside a container, by whatever that
// machine's resolver is. Given a name, a peer sat at "ECONNRESET, check duration: 0ms" while that very name
// answered "HTTP/1.0 200 OK" from inside the same container.
func TestCrossRegionPeersAreReachedAtAnAddress(t *testing.T) {
	work := t.TempDir()
	dir := filepath.Join(work, "region-a")
	_ = installFromPlan(t, writePlan(t, work), dir)

	door := deploymentFileContents(t, dir, "haproxy-edge.cfg")
	for _, line := range strings.Split(door, "\n") {
		if !strings.Contains(line, "cp-peer-") && !strings.Contains(line, "cp-data-peer-") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		target := fields[2]
		host, _, _ := strings.Cut(target, ":")
		if net.ParseIP(host) == nil {
			t.Errorf("a cross-region peer is reached by the NAME %q, which nothing resolves at run time: %s",
				host, strings.TrimSpace(line))
		}
		if !strings.Contains(line, "check-sni") {
			t.Errorf("a cross-region peer is reached at an address and verifies no name: %s", strings.TrimSpace(line))
		}
	}
	database := deploymentFileContents(t, dir, "haproxy-postgres.cfg")
	for _, line := range strings.Split(database, "\n") {
		if !strings.Contains(line, "pg-peer-") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		host, _, _ := strings.Cut(fields[2], ":")
		if net.ParseIP(host) == nil {
			t.Errorf("a database peer is reached by the NAME %q: %s", host, strings.TrimSpace(line))
		}
	}
}

// ★ AND A MULTI-REGION PLAN MUST SAY WHERE EACH MACHINE IS. Without the name nothing verifies; without the
// address the resolution happens inside a container at start-up and is not the plan's to decide.
func TestAMultiRegionPlanRequiresBothNameAndAddress(t *testing.T) {
	for _, missing := range []struct {
		what string
		drop func(*PlanMachine)
	}{
		{"reachable", func(m *PlanMachine) { m.Reachable = "" }},
		{"reachable_address", func(m *PlanMachine) { m.ReachableAddress = "" }},
	} {
		p := planOfRegions("region-a", "region-b")
		for i := range p.Regions[1].Machines {
			missing.drop(&p.Regions[1].Machines[i])
		}
		err := p.Validate()
		if err == nil {
			t.Errorf("a two-region plan with no %s was accepted", missing.what)
			continue
		}
		if !strings.Contains(err.Error(), missing.what) {
			t.Errorf("the refusal does not name %s: %v", missing.what, err)
		}
	}
	// ★ THE CONTROL: one region needs neither, because nothing crosses.
	one := planOfRegions("region-a")
	one.Regions[0].Machines[0].Reachable = ""
	one.Regions[0].Machines[0].ReachableAddress = ""
	if err := one.Validate(); err != nil {
		t.Errorf("a single-region plan was refused for values only a second region needs: %v", err)
	}
}
