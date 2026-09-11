package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ★★★ THE AUTHORITY'S DOOR COULD NOT CROSS A REGION UNDER ANY SUPPORTED CONFIGURATION (2026-08-27, measured
// on a two-region deployment whose leader was in the other one).
//
// The mechanism written for it the same morning wanted host:dataport:adminport — a control plane's own
// published DATA port. No deployment publishes one, and compose.go says why in the comment beside the ports
// it does publish: "publishing one node's own port would hand somebody an address that is right only until a
// failover". So the test that proved the config renders was appending an address by hand that a deployment
// could not produce, and the live one was sitting at:
//
//	region cp_data_plane/<NOSRV>
//	tenant_transport_material first fetch failed (… "https://authority.<host>/tenant-edge-material": EOF)
//	★ audit ship: FAILING — Post "https://authority.<host>/audit-ingest": EOF
//
// Every organization's material and every record the Edges held stopped at the door.
//
// The other region has a doorway, on 443, that already routes this name to whichever of ITS control planes
// leads. That is the address — no node, nothing to publish, and the same port the whole product folds to.
func TestTheAuthorityCrossesThroughTheOtherRegionsDoorway(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	// What an operator is told to set once every region exists — and nothing else.
	appendEnv(t, dir, "DSSE_EDGE_REGION", "region-a")
	appendEnv(t, dir, "DSSE_REGION_ENDPOINTS",
		"region-a=https://a.dsse.example;region-b=https://b.dsse.example")
	if err := os.Remove(filepath.Join(dir, "haproxy-edge.cfg")); err != nil {
		t.Fatal(err)
	}
	if err := writeRegionFrontDoorConfig(dir, planeNamesFor("dsse.example")); err != nil {
		t.Fatal(err)
	}
	data := backendBlock(readFileForTest(t, filepath.Join(dir, "haproxy-edge.cfg")), "cp_data_plane")

	// ★★★ THE PEER IS NAMED authority.<region>.<host>, NOT THE ENDPOINT (2026-08-28, corrected on the first
	// deployment with a machine per component). DSSE_REGION_ENDPOINTS is the map DEVICES are handed, so each
	// entry is that region's AGENT plane — on the Edge machine. The authority is on the control plane's
	// machine, behind a different doorway. On a region that was one machine the two were the same address and
	// this was invisible; here it sent every cross-region write to a door that does not serve it.
	if !strings.Contains(data, "authority.region-b.dsse.example:443") {
		t.Errorf("the authority's door does not reach the other region's AUTHORITY, so an Edge here cannot "+
			"ship what it recorded or fetch any organization's material whenever leadership is elsewhere:\n%s", data)
	}
	// ★★★ AND THE CHECK ASKS FOR THE ADMIN NAME, NOT THE AUTHORITY'S. The authority's surface requires a
	// client certificate — that is what it is for — so a health check holding none never finishes the
	// handshake and the peer sits at "Layer4 timeout" while answering every probe correctly. Measured. The
	// admin name reaches the same region's admin plane through the same doorway and answers GET /leader
	// without one; it is the same question, and it is the idiom the local pair already uses.
	if !strings.Contains(data, "check-sni admin.region-b.dsse.example") {
		t.Errorf("the peer doorway's health check does not ask for the peer's admin name, so it can never "+
			"complete a handshake and the region reads as down while it is leading:\n%s", data)
	}
	if strings.Contains(data, "check-sni authority.region-b.dsse.example") {
		t.Errorf("the health check asks for the authority plane, which will not answer one without a client "+
			"certificate:\n%s", data)
	}
	// ★ AND THE DATA PATH SETS NO SNI OF ITS OWN. It is passed through: the name the client sent is the name
	// that must arrive, or the peer doorway routes somebody else's traffic to this plane.
	if strings.Contains(data, "sni str(") {
		t.Errorf("the peer's data path rewrites the SNI instead of passing the client's through:\n%s", data)
	}
	// ★★ AND NOT THIS REGION. A door that lists itself health-checks its own NOSRV backend forever, and if it
	// ever passed it would forward to itself.
	if strings.Contains(data, "a.dsse.example") {
		t.Errorf("the door lists its OWN region as a peer:\n%s", data)
	}
}

// ★★ THE CONTROL: ONE REGION STILL SAYS SO. Setting no endpoints is the ordinary case and must read as
// finished, not as something missing.
func TestOneRegionStillSaysItHoldsItsAuthorityInOnePlace(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	data := backendBlock(readFileForTest(t, filepath.Join(dir, "haproxy-edge.cfg")), "cp_data_plane")
	if !strings.Contains(data, "this deployment holds its authority in one region") {
		t.Errorf("a single-region deployment's authority door does not say why it names no peers:\n%s", data)
	}
}

// ★★★ AND THE ADDRESS THE OLD MECHANISM WANTED IS ONE THESE SHAPES NEVER PRODUCE. This is the assertion the
// test it replaced could not make: that one appended DSSE_CP_DATA_PEERS by hand and so proved the renderer,
// not the deployment.
//
// ★ THE ONE SHAPE THAT DOES PUBLISH IT IS THE ONE WITH NO DOORWAY. A standby control plane's region has no
// front door carrying the authority's names, and when leadership moves there every other region still has to
// be able to write to it — so its own data port is published on purpose, and the explicit per-node form stays
// for exactly that. Every shape that HAS a doorway does not, which is why the doorway is the address.
func TestOnlyTheShapeWithNoDoorwayPublishesAControlPlanesDataPort(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	for _, shape := range []machineShape{
		{holds: regionShapeStateBearing, edges: true},
		{holds: regionShapeStateBearing},
		{holds: regionShapeStateBearingJoin},
	} {
		if body := composeForShape(t, dir, shape); strings.Contains(body, ":8443\"") &&
			strings.Contains(body, "DSSE_CP_A_DATA_PORT") {
			t.Errorf("a control plane's own data port is published on shape %+v, which has a doorway — the "+
				"per-node address exists after all and this test is the thing that is wrong", shape)
		}
	}
	standby := composeForShape(t, dir, machineShape{holds: regionShapeStandbyCP})
	if !strings.Contains(standby, "DSSE_CP_A_DATA_PORT") {
		t.Error("a standby control plane no longer publishes its data port — nothing can write to it when " +
			"leadership moves there, and the explicit peer form beside this has nothing left to name")
	}
}

// ★★ AND A RENDERING THAT PUBLISHES ITS DOORWAY SOMEWHERE ELSE IS BELIEVED. DSSE_REGION_ENDPOINTS is "the
// address each region answers on" — the same value handed to every device — so a lab that folds its doorway
// onto another port says so there. Assuming 443 would health-check a port nothing listens on and mark a
// region that IS leading permanently down.
func TestAPeerDoorwayKeepsThePortItsEndpointDeclares(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	appendEnv(t, dir, "DSSE_EDGE_REGION", "region-a")
	appendEnv(t, dir, "DSSE_REGION_ENDPOINTS",
		"region-a=https://a.dsse.example;region-b=https://b.dsse.example:36443")
	if err := os.Remove(filepath.Join(dir, "haproxy-edge.cfg")); err != nil {
		t.Fatal(err)
	}
	if err := writeRegionFrontDoorConfig(dir, planeNamesFor("dsse.example")); err != nil {
		t.Fatal(err)
	}
	data := backendBlock(readFileForTest(t, filepath.Join(dir, "haproxy-edge.cfg")), "cp_data_plane")
	// ★ The endpoint's PORT is still believed. A rendering that publishes its doorway elsewhere says so in
	// this list, and assuming 443 would health-check a port nothing listens on.
	if !strings.Contains(data, "authority.region-b.dsse.example:36443") {
		t.Errorf("the declared port was dropped and 443 assumed:\n%s", data)
	}
}
