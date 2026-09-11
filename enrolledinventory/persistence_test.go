package enrolledinventory

import "testing"

// Admin runtime changes to the Enrolled Inventory must survive an Edge restart — especially a REVOCATION
// (disable) of a statically-seeded device, which must NOT be silently re-admitted by the static re-seed on
// the next boot. Before W7 these were in-memory only.
func TestEnrolledInventorySurvivesRestart(t *testing.T) {
	path := t.TempDir() + "/enrolled_inventory.json"
	const now = "2026-01-01T00:00:00Z"

	l1 := NewLedger()
	l1.SeedFromStatic(map[string]struct{}{"dev-seed": {}}, now) // statically allowed
	l1.SetStatePath(path)                                       // no durable file yet → keeps the seed
	if _, err := l1.Enroll("dev-runtime", "t1", "console", now); err != nil {
		t.Fatal(err)
	}
	if _, ok := l1.SetEnabled("dev-seed", false, now); !ok { // revoke the seeded device via the Console path
		t.Fatal("disable should succeed")
	}

	// Restart: a fresh ledger re-applies the static seed (dev-seed enabled), then loads the durable store,
	// which is authoritative.
	l2 := NewLedger()
	l2.SeedFromStatic(map[string]struct{}{"dev-seed": {}}, now)
	l2.SetStatePath(path)

	if !l2.IsAdmitted("dev-runtime") {
		t.Fatal("a runtime-enrolled device must survive the restart")
	}
	if l2.IsAdmitted("dev-seed") {
		t.Fatal("a revoked (disabled) device must STAY revoked across restart — the static re-seed must not re-admit it")
	}
}

func TestEnrolledInventoryNoStorePathIsInMemoryOnly(t *testing.T) {
	l := NewLedger()
	// No SetStatePath → persistLocked is a no-op (no panic, no file).
	if _, err := l.Enroll("d", "t", "", "now"); err != nil {
		t.Fatal(err)
	}
	if !l.IsAdmitted("d") {
		t.Fatal("enroll still works in-memory")
	}
}
