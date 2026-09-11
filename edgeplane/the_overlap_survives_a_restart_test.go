package edgeplane

import (
	"os"
	"strings"
	"testing"
)

// ★★★ THE OVERLAP DISAPPEARED ACROSS A RESTART, AND A RESTART IS HOW OPERATORS DO IT (2026-08-21, measured on
// the reference deployment while migrating an organization's interception authority).
//
// Replacing an issuing authority keeps the OUTGOING root announced, so a device that has not adopted the new
// one yet still verifies. That record lived in memory and was written only when the replacement happened on a
// LIVE engine. What an operator actually does is replace the files and recreate the node — and a restarted
// engine has no memory of what it was signing under before, while the same-named files have been overwritten.
// So the announcement went straight from the old root to the new one with no overlap at all. Nothing broke
// only because adoption had been measured first; a device that had missed the distribution would have lost
// every site at that moment, with the safety net described to the other endpoint not actually running.
func TestTheAnnouncedOverlapSurvivesAFileReplacementAndRestart(t *testing.T) {
	dir := t.TempDir()
	const tenant = "tenant_probe"
	const oldRoot = "1111111111111111111111111111111111111111111111111111111111111111"
	const newRoot = "2222222222222222222222222222222222222222222222222222222222222222"

	// The node comes up on the old material and announces it.
	if retiring := recordAnnouncedRoot(dir, tenant, oldRoot); len(retiring) != 0 {
		t.Fatalf("a first load has nothing to retire, got %v", retiring)
	}

	// The operator replaces the files and recreates the node. THIS is the case the in-memory version could not
	// see: a different process, different material, and no certificate for what came before.
	retiring := recordAnnouncedRoot(dir, tenant, newRoot)
	if len(retiring) != 1 || retiring[0] != oldRoot {
		t.Fatalf("★ the previous root is not being announced after a file replacement and restart: %v — a "+
			"device that had not adopted the new root loses every site at that moment, and the overlap that "+
			"was supposed to protect it is not running", retiring)
	}

	// ★ AND IT SURVIVES THE NEXT RESTART TOO, or the overlap lasts exactly one boot.
	again := recordAnnouncedRoot(dir, tenant, newRoot)
	if len(again) != 1 || again[0] != oldRoot {
		t.Fatalf("the overlap did not survive a second start-up: %v", again)
	}

	// A withdrawal is durable in the same way — otherwise a retired root comes back on the next boot, which is
	// the flap this deployment spent a day chasing.
	if err := forgetRetiringRoot(dir, tenant, oldRoot); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if after := recordAnnouncedRoot(dir, tenant, newRoot); len(after) != 0 {
		t.Fatalf("a withdrawn root came back after a restart: %v", after)
	}

	// The record sits beside the issuer bundles it describes, so an operator moving those files moves it too.
	if _, err := os.Stat(announcedRootsPath(dir, tenant)); err != nil {
		t.Fatalf("the record is not beside the material: %v", err)
	}
	raw, _ := os.ReadFile(announcedRootsPath(dir, tenant))
	if !strings.Contains(string(raw), newRoot) {
		t.Fatalf("the record does not name the root in force: %s", raw)
	}

	// ★ A NODE WITH NO DIRECTORY RECORDS NOTHING rather than panicking — an in-memory deployment still runs.
	if got := recordAnnouncedRoot("", tenant, newRoot); got != nil {
		t.Fatalf("a node with nowhere to write returned %v instead of nothing", got)
	}
}
