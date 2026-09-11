package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// ★★★ ONE FLEET, ONE FILE, THREE DOCUMENTS (2026-08-20, measured on a four-Edge lab). Each Edge read the
// shared store once at boot and never again, so the file sat at serial 144 while region-a served 138 and
// region-b served 142, and watching for three minutes showed no convergence.
//
// The refusal that stops a node writing the fleet backwards then made it visible: an administrator adding a
// trust anchor through the node that was behind got 400 forever, because nothing re-read the file. Whether the
// Console's button worked depended on which Edge answered.
//
// Both halves are asserted here, and the FIRST half is the guard: without the adoption this test fails on the
// error string the lab actually returned.
func TestANodeThatIsBehindAdoptsTheFleetInsteadOfRefusingForever(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trust.json")
	seed := string(testCertPEM(t, "fleet-anchor"))
	resign := func(string, int64) (func(), error) { return func() {}, nil }

	nodeA, err := openTransportTrustStore(path, seed, 10, resign)
	if err != nil {
		t.Fatal(err)
	}
	nodeB, err := openTransportTrustStore(path, seed, 10, resign)
	if err != nil {
		t.Fatal(err)
	}

	// The fleet moves: node B distributes twice while node A is not looking.
	for _, announcement := range [][]string{{"tenant_x=aa"}, {"tenant_x=aa", "tenant_y=bb"}} {
		if _, moved, err := nodeB.AdvanceForAnnouncement(announcement, "test"); err != nil || !moved {
			t.Fatalf("node B could not distribute (moved=%v err=%v)", moved, err)
		}
	}
	_, fleetSerial := nodeB.Current()
	if _, held := nodeA.Current(); held >= fleetSerial {
		t.Fatalf("the fleet did not actually move ahead of node A (held=%d fleet=%d)", held, fleetSerial)
	}

	// An administrator adds an anchor on the node that is behind. Before the adoption this answered
	// "the shared trust store is at serial N and this node holds M" and would answer it forever.
	added, serial, err := nodeA.Add(string(testCertPEM(t, "added-on-the-node-that-was-behind")))
	if err != nil {
		t.Fatalf("the node that was behind could not accept an anchor: %v", err)
	}
	if serial != fleetSerial+1 {
		t.Fatalf("the addition landed at serial %d, not one past the fleet's %d", serial, fleetSerial)
	}
	if added.Subject.CommonName != "added-on-the-node-that-was-behind" {
		t.Fatalf("unexpected certificate: %s", added.Subject.CommonName)
	}

	// Adopting carries the fleet's ANNOUNCEMENT too, not just its serial — a node that took the number and
	// kept its own announcement would re-advance on its next pass and start the flap over again.
	if _, moved, err := nodeA.AdvanceForAnnouncement([]string{"tenant_x=aa", "tenant_y=bb"}, "test"); err != nil || moved {
		t.Fatalf("the adopted node re-announced what the fleet already said (moved=%v err=%v)", moved, err)
	}

	// And the fleet's anchor is still there: adopting must not drop what node B distributed.
	names := []string{}
	for _, c := range nodeA.Anchors() {
		names = append(names, c.Subject.CommonName)
	}
	if !strings.Contains(strings.Join(names, ","), "fleet-anchor") {
		t.Fatalf("adopting lost the fleet's own anchor: %v", names)
	}
}

// Unreadable is not changed, and an empty set is never adopted: a node whose peer wrote something it cannot
// read must keep serving what it has rather than falling to nothing.
func TestAdoptingRefusesAnEmptyOrUnreadableFleetView(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trust.json")
	seed := string(testCertPEM(t, "mine"))
	node, err := openTransportTrustStore(path, seed, 3, func(string, int64) (func(), error) {
		return func() {}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, blob := range []string{
		`{"schema_version":"transport_trust_store.v1","serial":99,"anchors_pem":""}`,
		`{not json`,
	} {
		if err := writeFileForTest(path, blob); err != nil {
			t.Fatal(err)
		}
		node.mu.Lock()
		node.adoptNewerFromDiskLocked()
		held := node.serial
		node.mu.Unlock()
		if held != 3 {
			t.Fatalf("a node adopted a view it could not use (serial=%d, blob=%q)", held, blob)
		}
	}
}
