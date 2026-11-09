package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// A region's doorway is not where its control plane lives. Measured on a three-region deployment
// (2026-11-06): stopping only region-a's front door, while region-a's control plane went on leading,
// left every other region's Console answering 502 at sign-in. Their doors reached the leader only
// THROUGH region-a's door, and leadership does not move while the leader is healthy. Devices and
// connectors failed over in seconds; administration stopped everywhere.
//
// A multi-region door must reach each other region's control plane at the control plane's own
// private listener, and keep the other region's doorway only as a fallback (a deployment upgraded
// one machine at a time has peers that do not publish the listener yet).

func doorBackend(t *testing.T, door, name string) string {
	t.Helper()
	start := strings.Index(door, "\nbackend "+name+"\n")
	if start < 0 {
		t.Fatalf("the door has no backend %s", name)
	}
	rest := door[start+1:]
	if end := strings.Index(rest[1:], "\nbackend "); end >= 0 {
		rest = rest[:end+1]
	}
	if end := strings.Index(rest[1:], "\nfrontend "); end >= 0 {
		rest = rest[:end+1]
	}
	return rest
}

func serverLines(backend, prefix string) []string {
	var out []string
	for _, line := range strings.Split(backend, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "server "+prefix) {
			out = append(out, strings.TrimSpace(line))
		}
	}
	return out
}

func TestTheAdminPlaneReachesAnotherRegionsLeaderWithoutItsDoor(t *testing.T) {
	work := t.TempDir()
	dir := filepath.Join(work, "region-a")
	installFromPlan(t, writePlan(t, work), dir)
	door := deploymentFileContents(t, dir, "haproxy-edge.cfg")

	admin := strings.Join(serverLines(doorBackend(t, door, "cp_admin_plane"), "cp-peer-"), "\n")
	if !strings.Contains(admin, "203.0.113.11:19543 ") || !strings.Contains(admin, "check-sni admin.region-b.dsse.example") {
		t.Fatalf("region-b's control plane is not reached at its own listener:\n%s", admin)
	}
	if strings.Contains(admin, ":443 ") || strings.Contains(admin, " backup") {
		t.Errorf("a doorway is mixed into the direct backend:\n%s", admin)
	}
	doors := strings.Join(serverLines(doorBackend(t, door, "cp_admin_doorways"), "cp-door-"), "\n")
	if !strings.Contains(doors, "203.0.113.11:443 ") {
		t.Fatalf("region-b's doorway is not kept as a way to the leader:\n%s", doors)
	}
}

// Found 2026-11-06: a doorway checked by the region's admin name answers from whichever control plane
// leads, so two updated regions saw each other's doorway as healthy and sent requests round between themselves
// while the leader was elsewhere. A doorway is checked by the peer's OWN node name, which its door routes to its
// own control plane only; and it is used only while no direct control plane answers.
func TestADoorwayIsUpOnlyWhileItsOwnRegionLeads(t *testing.T) {
	work := t.TempDir()
	dir := filepath.Join(work, "region-a")
	installFromPlan(t, writePlan(t, work), dir)
	door := deploymentFileContents(t, dir, "haproxy-edge.cfg")
	for _, backend := range []string{"cp_admin_doorways", "cp_data_doorways"} {
		lines := serverLines(doorBackend(t, door, backend), "cp-")
		if len(lines) == 0 {
			t.Fatalf("%s has no doorway", backend)
		}
		for _, line := range lines {
			if !strings.Contains(line, "check-sni region-b-control-plane-a.admin.dsse.example") {
				t.Errorf("%s checks a doorway by a name another region's control plane can answer: %s", backend, line)
			}
		}
	}
	admin := strings.Index(door, "use_backend cp_admin_doorways if")
	normal := strings.Index(door, "use_backend cp_admin_plane if")
	if admin < 0 || normal < 0 || admin > normal || !strings.Contains(door, "{ nbsrv(cp_admin_plane) eq 0 }") {
		t.Fatal("the doorways are not taken only while the direct admin backend has no server up")
	}
	if !strings.Contains(door, "use_backend cp_data_doorways  if") || !strings.Contains(door, "{ nbsrv(cp_data_plane) eq 0 }") {
		t.Fatal("the doorways are not taken only while the direct data backend has no server up")
	}
}

// Found 2026-11-06: the authority's direct peers were checked on the admin port only, so a closed
// 19545 stayed "up". The check now proves leadership on 19543 AND an answer from the data listener itself.
func TestTheDataPlaneReachesAnotherRegionsAuthorityWithoutItsDoor(t *testing.T) {
	work := t.TempDir()
	dir := filepath.Join(work, "region-a")
	installFromPlan(t, writePlan(t, work), dir)
	door := deploymentFileContents(t, dir, "haproxy-edge.cfg")
	backend := doorBackend(t, door, "cp_data_plane")

	data := strings.Join(serverLines(backend, "cp-data-peer-"), "\n")
	if !strings.Contains(data, "203.0.113.11:19545 ") || strings.Contains(data, ":443 ") || strings.Contains(data, " backup") {
		t.Fatalf("region-b's authority is not reached at its own data listener only:\n%s", data)
	}
	for _, want := range []string{"http-check connect port 19543 ssl", "uri /leader", "http-check connect ssl sni", "uri /healthz"} {
		if !strings.Contains(backend, want) {
			t.Errorf("the authority's check lacks %q, so a closed data listener behind a healthy admin one reads as up:\n%s", want, backend)
		}
	}
	if !strings.Contains(strings.Join(serverLines(backend, "cp-a "), "\n"), "10.20.1.1:19545 ") {
		t.Errorf("this machine's own control plane is not reached at its published data listener, which the check needs")
	}
	if doors := strings.Join(serverLines(doorBackend(t, door, "cp_data_doorways"), "cp-data-door-"), "\n"); !strings.Contains(doors, "203.0.113.11:443 ") {
		t.Errorf("region-b's doorway is not kept for the authority:\n%s", doors)
	}
}

func TestAMultiRegionControlPlanePublishesItsListenersOnlyOnItsOwnAddress(t *testing.T) {
	work := t.TempDir()
	dir := filepath.Join(work, "region-a")
	plan := installFromPlan(t, writePlan(t, work), dir)

	env := readDeploymentEnv(dir)
	if got := env["DSSE_CP_A_BIND"]; got != "10.20.1.1:" {
		t.Errorf("the founding control plane binds its peer listeners to %q, want its own address 10.20.1.1", got)
	}
	compose := deploymentFileContents(t, dir, "docker-compose.yml")
	for _, want := range []string{
		`"${DSSE_CP_A_BIND:?set DSSE_CP_A_BIND to the Node private address}${DSSE_CP_A_ADMIN_PORT:-19543}:9443"`,
		`"${DSSE_CP_A_BIND:?set DSSE_CP_A_BIND to the Node private address}${DSSE_CP_A_DATA_PORT:-19545}:8443"`,
	} {
		if !strings.Contains(compose, want) {
			t.Errorf("the control plane does not publish %s, so the other regions have nothing to reach", want)
		}
	}
	// A machine that does not hold the control plane publishes nothing for it.
	edgeEnv, err := plan.MachineEnvironment("edge-a")
	if err != nil {
		t.Fatal(err)
	}
	if edgeEnv["DSSE_CP_A_BIND"] != "" {
		t.Errorf("an Edge-only machine was given a control-plane bind address: %q", edgeEnv["DSSE_CP_A_BIND"])
	}
}

func TestASingleRegionPlanPublishesNoControlPlaneListener(t *testing.T) {
	work := t.TempDir()
	dir := filepath.Join(work, "region-a")
	installFromPlan(t, "../../docs/plans/single-region.json", dir)
	if got := readDeploymentEnv(dir)["DSSE_CP_A_BIND"]; got != "" {
		t.Errorf("a one-machine deployment publishes its control plane's listeners at %q; nothing needs them", got)
	}
}

// The shipped three-region example, carried to every machine the way -order says: each region's door, rendered
// on its own machine from what the carry gave it, reaches both other control planes directly and keeps both
// doorways as backups.
func TestEveryRegionOfTheThreeRegionExampleReachesTheOthersDirectly(t *testing.T) {
	p, err := LoadPlan("../../docs/plans/three-regions.json")
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	source := filepath.Join(work, "source")
	installFromPlan(t, "../../docs/plans/three-regions.json", source)
	dirs := map[string]string{p.foundingRegion().controlPlane().Name: source}
	for _, name := range p.MachineNames() {
		if _, done := dirs[name]; done {
			continue
		}
		archive := filepath.Join(work, name+".tgz")
		if err := carryPlanMachine(p, source, archive, name); err != nil {
			t.Fatal(err)
		}
		dir := unpackCarry(t, archive)
		if err := applyPlanToThisMachine(p, dir, name); err != nil {
			t.Fatal(err)
		}
		dirs[name] = dir
	}
	addresses := map[string]string{"node-a": "10.20.1.10", "node-b": "10.20.2.10", "node-c": "10.20.3.10"}
	for machine, dir := range dirs {
		door := deploymentFileContents(t, dir, "haproxy-edge.cfg")
		admin := strings.Join(append(serverLines(doorBackend(t, door, "cp_admin_plane"), "cp-peer-"),
			serverLines(doorBackend(t, door, "cp_admin_doorways"), "cp-door-")...), "\n")
		data := strings.Join(append(serverLines(doorBackend(t, door, "cp_data_plane"), "cp-data-peer-"),
			serverLines(doorBackend(t, door, "cp_data_doorways"), "cp-data-door-")...), "\n")
		for other, at := range addresses {
			if other == machine {
				if strings.Contains(admin, at+":") {
					t.Errorf("%s's door lists its own address as a peer:\n%s", machine, admin)
				}
				continue
			}
			for _, want := range []string{at + ":19543 ", at + ":443 "} {
				if !strings.Contains(admin+" ", want) {
					t.Errorf("%s's admin plane does not reach %s as %q:\n%s", machine, other, want, admin)
				}
			}
			for _, want := range []string{at + ":19545 ", at + ":443 "} {
				if !strings.Contains(data+" ", want) {
					t.Errorf("%s's data plane does not reach %s as %q:\n%s", machine, other, want, data)
				}
			}
		}
		if got := readDeploymentEnv(dir)["DSSE_CP_A_BIND"]; got != addresses[machine]+":" {
			t.Errorf("%s binds its control plane's peer listeners to %q, want %s:", machine, got, addresses[machine])
		}
	}
}
