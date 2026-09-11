package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ★★★ TWO DOORS DO THE SAME JOB AND ONLY ONE WAS TAUGHT TO LOOK OUTSIDE THE REGION (2026-08-31, measured on
// the first three-region deployment).
//
// An Edge reaches the control plane through the internal door — DSSE_CONTROL_PLANE points at it — and that
// door held only its own region's control planes. In a region that JOINS, those are warm standbys and answer
// /leader with 503, so the backend was empty and the Edge had nowhere to go. Its enrolments sat in the outbox
// ("enrolment_report_outbox: delivered=0 still_pending=2") while every screen showed a healthy region, and
// admin actions against those devices answered 404 from a control plane that had never heard of them.
//
// The region's front door on 443 already followed leadership across regions. Same job, two doors, one taught.
func TestTheDoorAnEdgeUsesReachesTheOtherRegions(t *testing.T) {
	dir := t.TempDir()
	// The peers a joining region is given, in the form the plan writes them.
	if err := os.WriteFile(filepath.Join(dir, "deployment.env"), []byte(
		"DSSE_CP_PEERS='https://admin.tokyo-east.example@203.0.113.1:443'\n"+
			"DSSE_CP_DATA_PEERS='https://authority.tokyo-east.example@203.0.113.1:443'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeFrontDoorConfig(dir); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "haproxy.cfg"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(body)

	admin := section(got, "cp_admin_backend")
	if !strings.Contains(admin, "cp-peer-1") {
		t.Error("the door an Edge pulls its configuration through has no route to another region's control " +
			"plane: in a region that joins, its own are standbys and the backend is empty")
	}
	data := section(got, "cp_data_backend")
	if !strings.Contains(data, "cp-data-peer-1") {
		t.Error("the door an Edge SHIPS through has no route to another region's authority, so what it " +
			"recorded and the enrolments it holds stay in its outbox")
	}
}

// ★ AND A DEPLOYMENT IN ONE REGION SAYS SO, rather than rendering servers it cannot resolve.
func TestOneRegionsDoorNamesNoPeers(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "deployment.env"), []byte("DSSE_CP_PEERS=''\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeFrontDoorConfig(dir); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(filepath.Join(dir, "haproxy.cfg"))
	if strings.Contains(string(body), "cp-peer-1") {
		t.Error("a single-region deployment renders a peer server it has no address for")
	}
}

// section returns one backend's body.
//
// ★ A DECLARATION, NOT A MENTION (2026-08-31; this test's first run reported a peer that was rendered as
// missing). "backend cp_admin_backend" is also a substring of "default_backend cp_admin_backend" a few lines
// above it, so matching the name found the mention, and everything after it up to the real declaration is
// empty. Anchor on the line.
func section(body, name string) string {
	header := "\nbackend " + name + "\n"
	i := strings.Index(body, header)
	if i < 0 {
		return ""
	}
	rest := body[i+len(header):]
	if j := strings.Index(rest, "\nbackend "); j >= 0 {
		return rest[:j]
	}
	if j := strings.Index(rest, "\nfrontend "); j >= 0 {
		return rest[:j]
	}
	return rest
}

// ★★★ A CARRIED MACHINE GETS ITS OWN DOORS, NOT THE PACKING MACHINE'S (2026-08-31, measured).
//
// The carry removed and re-rendered two of the three doors this installer generates. The third —
// haproxy.cfg, the control plane's own, which is what an Edge pulls its configuration through — was copied
// from the machine doing the packing. That was invisible for as long as the two were identical, and became a
// region whose Edge could not reach the leader the moment they differed by a peer list.
//
// So the check is not "is haproxy.cfg present" but "does it describe THIS machine": packed for a region with
// peers, it must name them.
func TestACarriedMachineGetsItsOwnControlPlaneDoor(t *testing.T) {
	packing := t.TempDir()
	// The packing machine's own door, with no peers — the shape a founding region has before anyone joins.
	if err := os.WriteFile(filepath.Join(packing, "deployment.env"), []byte("DSSE_CP_PEERS=''\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeFrontDoorConfig(packing); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(packing, "haproxy.cfg"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(before), "cp-peer-1") {
		t.Fatal("the packing machine already names a peer; this test cannot tell a copy from a rendering")
	}

	// Now the same directory is staged for a machine whose values DO name peers.
	staged := t.TempDir()
	if err := os.WriteFile(filepath.Join(staged, "haproxy.cfg"), before, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staged, "deployment.env"), []byte(
		"DSSE_CP_PEERS='https://admin.tokyo-east.example@203.0.113.1:443'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// What the carry does to that file.
	if err := os.Remove(filepath.Join(staged, "haproxy.cfg")); err != nil {
		t.Fatal(err)
	}
	if err := writeFrontDoorConfig(staged); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(staged, "haproxy.cfg"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(section(string(after), "cp_admin_backend"), "cp-peer-1") {
		t.Error("the carried machine's control-plane door does not name the peers its own environment gives " +
			"it, so it is the packing machine's door wearing this machine's name")
	}
}

// ★★★ THE FORWARDED REQUEST CARRIES A NAME, NOT ONLY THE HEALTH CHECK (2026-08-31, measured).
//
// Every mouth of this deployment is 443 and the planes are separated by NAME, so a door forwarding to another
// region has to say which plane it wants. The admin peers did. The data peers named a plane only in their
// check, and the traffic went out carrying whatever name the client had sent — a container alias no front
// door routes — so it landed on the other region's DEFAULT backend, its Edge fleet, and came back 404. An
// Edge's enrolments sat in its outbox while the authority answered "no such route" about a route it serves.
//
// The two names differ on purpose: leadership is a property of the node and is asked on the admin plane,
// while what is being forwarded belongs to the data plane. Both have to be said.
func TestForwardedDataTrafficNamesTheDataPlane(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "deployment.env"), []byte(
		"DSSE_CP_DATA_PEERS='https://authority.tokyo-east.example@203.0.113.1:443'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := peerControlPlaneDataServers(dir)
	if !strings.Contains(got, "check-sni admin.tokyo-east.example") {
		t.Error("the health check does not ask the admin plane, where leadership is answered")
	}
	if !strings.Contains(got, "sni str(authority.tokyo-east.example)") {
		t.Errorf("the forwarded traffic does not name the data plane, so it arrives at the other region's "+
			"door under whatever name the client sent and falls to its default backend:\n%s", got)
	}
}
