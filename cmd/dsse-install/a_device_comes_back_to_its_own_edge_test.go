package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func renderFrontDoorForTest(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := writeRegionFrontDoorConfig(dir, planeNamesFor("hikari.lab")); err != nil {
		t.Fatalf("render region front door: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "haproxy-edge.cfg"))
	if err != nil {
		t.Fatalf("read front door: %v", err)
	}
	return string(raw)
}

// ★★★ MEASURED ON A REAL MAC, 2026-08-29, against a region with two Edges behind its front door.
//
// The agent's runtime-copy path opens a SESSION — a live TCP connection to the destination, held in ONE Edge
// process's memory — and then sends each exchange as a separate request on a NEW connection. The generated
// front door balanced those with leastconn, so the follow-ups landed on the other Edge, which had never heard
// of the session:
//
//	handleNewFlow edge_round_trip_error_category=session_not_found   (14 of 19 flows)
//	curl https://example.com -> 000
//
// It cannot be fixed by sharing state — a session IS an open socket to somewhere else. The door has to send
// the device back to the node holding it.
func TestTheAgentPlaneSendsADeviceBackToTheEdgeHoldingItsSession(t *testing.T) {
	cfg := renderFrontDoorForTest(t)
	backend := backendBlock(cfg, "edge_fleet")
	if strings.Contains(backend, "balance leastconn") {
		t.Fatal("the agent plane balances by connection count, so a device's session follow-ups reach an Edge " +
			"that never opened the session and half of every steered flow dies with session_not_found")
	}
	if !strings.Contains(backend, "balance source") {
		t.Fatalf("the agent plane has no source affinity:\n%s", backend)
	}
	if !strings.Contains(backend, "hash-type consistent") {
		t.Fatal("without a consistent hash, adding or removing one Edge re-hashes the whole region and every " +
			"device in it loses its open sessions at once")
	}
	// The reason it must NOT be balanced is the same reason it must still carry the device's address.
	if !strings.Contains(backend, "send-proxy") {
		t.Fatal("the agent plane stopped carrying the device's own address")
	}
}

// The control-plane backends are a different question and must NOT be pinned by source: they are stateless to
// the caller and pinning them would send a whole site to one control plane.
func TestTheControlPlaneIsNotPinnedBySource(t *testing.T) {
	cfg := renderFrontDoorForTest(t)
	for _, name := range []string{"cp_admin_plane"} {
		if strings.Contains(backendBlock(cfg, name), "balance source") {
			t.Fatalf("%s was pinned by source — a whole site would land on one control plane", name)
		}
	}
}
