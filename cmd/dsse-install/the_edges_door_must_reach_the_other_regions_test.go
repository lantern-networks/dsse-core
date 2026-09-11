package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ★★★ THE FAILURE THIS PREVENTS, MEASURED (2026-08-27): "the door the Edges use never routed to a leader on
// network dsse_default", on a healthy deployment whose leader was simply in the other region.
func TestTheEdgesDoorCanFindALeaderInAnotherRegion(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "the-deployment.example", "Example", 3, false); err != nil {
		t.Fatalf("mint: %v", err)
	}
	// With no other region configured, the door says so rather than looking incomplete.
	first := readDoor(t, dir)
	if !strings.Contains(first, "no other region is configured") {
		t.Fatal("a one-region deployment's door should say that is what it is")
	}

	// Now the deployment learns about another region's control planes.
	env := filepath.Join(dir, "deployment.env")
	body, _ := os.ReadFile(env)
	if err := os.WriteFile(env, append(body,
		[]byte("\nDSSE_CP_PEERS='https://cp.region-b.example:9443, cp2.region-b.example:9443'\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "haproxy-edge.cfg")); err != nil {
		t.Fatal(err)
	}
	if err := writeRegionFrontDoorConfig(dir, planeNamesFor("the-deployment.example")); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	door := readDoor(t, dir)
	for _, want := range []string{"cp.region-b.example:9443", "cp2.region-b.example:9443"} {
		if !strings.Contains(door, want) {
			t.Fatalf("the Edges' door cannot reach %s, so a leader there is unreachable from this region", want)
		}
	}
	// ★ The scheme is stripped: an operator copying an address out of printed output must not have to.
	if strings.Contains(door, "https://cp.region-b.example") {
		t.Fatal("a URL was written where haproxy expects host:port")
	}
	// ★ AND THE LEADER CHECK IS UNCHANGED. Adding peers must not turn this into a door that spreads traffic
	// across control planes; exactly one of them answers 200 and that is still what routes.
	if strings.Count(door, "option httpchk GET /leader") < 2 {
		t.Fatal("the leader check disappeared from a control-plane backend")
	}
}

func readDoor(t *testing.T, dir string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "haproxy-edge.cfg"))
	if err != nil {
		t.Fatalf("read the Edges' door: %v", err)
	}
	return string(raw)
}

// ★★★ THE EDGES ARE ON OTHER MACHINES (2026-08-27, measured on the first per-component deployment). The region
// doorway routes agents.<host> to the Edge fleet, and its backend named compose service names — which resolve
// only on the network that defines them.
func TestTheDoorwayCanReachEdgesOnOtherMachines(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.lab", "Example", 3, false); err != nil {
		t.Fatalf("mint: %v", err)
	}
	// The default is still the one-host reference, which is a real deployment that must keep working.
	if !strings.Contains(readDoor(t, dir), "dsse-edge-a:8443") {
		t.Fatal("a deployment that names no Edge hosts should keep the compose names it has always had")
	}

	env := filepath.Join(dir, "deployment.env")
	body, _ := os.ReadFile(env)
	if err := os.WriteFile(env, append(body,
		[]byte("\nDSSE_EDGE_BACKENDS='edge-a.dsse.lab:8443, edge-b.dsse.lab:8443'\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "haproxy-edge.cfg")); err != nil {
		t.Fatal(err)
	}
	if err := writeRegionFrontDoorConfig(dir, planeNamesFor("dsse.lab")); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	door := readDoor(t, dir)
	for _, want := range []string{"edge-a.dsse.lab:8443", "edge-b.dsse.lab:8443"} {
		if !strings.Contains(door, want) {
			t.Fatalf("the doorway cannot reach %s, so agents.<host> reaches no Edge at all", want)
		}
	}
	if strings.Contains(door, "dsse-edge-a:8443") {
		t.Fatal("a compose service name survived beside the real hosts; the doorway would health-check a name " +
			"that resolves nowhere and report the fleet as half down")
	}
	// ★ send-proxy has to survive. Without it every device in the region arrives from the doorway's address:
	// one rate-limit bucket for the fleet, and a device list saying every machine is in the same place.
	if !strings.Contains(door, "send-proxy") {
		t.Fatal("send-proxy was lost, so the Edges would stop seeing each device's own address")
	}
}
