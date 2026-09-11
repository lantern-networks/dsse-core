package revocation

import (
	"path/filepath"
	"testing"
)

// TestCrossRegionRevocationPropagatesWithoutLoop is the federation invariant: an ORIGIN revocation in peer A is
// pushed to peer B and denies on B's edges, but B does NOT re-push it (no-loop), and it stays out of B's ORIGIN set.
func TestCrossRegionRevocationPropagatesWithoutLoop(t *testing.T) {
	regionA := NewAdmissionRevocations()
	regionB := NewAdmissionRevocations()

	// A's origin revocations propagate to B (the mesh push). B's would propagate to a counter (to prove no-loop).
	regionA.SetMeshReporter(func(identity, reason string) { regionB.RevokeFromMesh(identity, reason) })
	bPushes := 0
	regionB.SetMeshReporter(func(identity, reason string) { bPushes++ })

	regionA.Revoke("dev-roamer", "admin_kill")

	// B denies the device (the cross-region invariant: revoked in A => denied in B).
	if _, ok := regionB.IsRevoked("dev-roamer"); !ok {
		t.Fatal("device revoked in region A must be denied in region B after the mesh push")
	}
	// No-loop: B received it via the mesh, so B must NOT re-push.
	if bPushes != 0 {
		t.Fatalf("region B re-pushed a mesh-received item %d time(s) — must be 0 (no-loop)", bPushes)
	}
	// B serves it to ITS edges (feed), but it is NOT one of B's ORIGIN revocations.
	if _, ok := regionB.FeedSnapshot()["dev-roamer"]; !ok {
		t.Fatal("B's edge feed must include the cross-region revocation")
	}
	if _, ok := regionB.Snapshot()["dev-roamer"]; ok {
		t.Fatal("a mesh-received item must NOT appear in B's ORIGIN snapshot (else B would re-push it)")
	}
}

// TestRevokeFromMeshIsMonotonic proves re-delivering the same item is a no-op (idempotent), and the generation
// only advances on a real change so edges do not needlessly re-pull.
func TestRevokeFromMeshIsMonotonic(t *testing.T) {
	o := NewAdmissionRevocations()
	if !o.RevokeFromMesh("dev1", "kill") {
		t.Fatal("first mesh revocation should report changed")
	}
	g := o.ConfigGeneration()
	if o.RevokeFromMesh("dev1", "kill") {
		t.Fatal("re-delivering the same item must be a no-op")
	}
	if o.ConfigGeneration() != g {
		t.Fatalf("no-op mesh delivery bumped generation %d -> %d", g, o.ConfigGeneration())
	}
}

// TestCrossRegionRevocationSurvivesRestart proves "persisted, so a CP restart never un-revokes": the
// federation-received layer round-trips through the durable store.
func TestCrossRegionRevocationSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rev_state.json")

	first := NewAdmissionRevocations()
	first.SetStatePath(path)
	first.RevokeFromMesh("dev-roamer", "peer_kill")

	// A "restart": a fresh overlay loading the same store must still deny the cross-region revocation.
	restarted := NewAdmissionRevocations()
	restarted.SetStatePath(path)
	if _, ok := restarted.IsRevoked("dev-roamer"); !ok {
		t.Fatal("a CP restart must NOT un-revoke a cross-region revocation (fail-open) — it must persist")
	}
}
