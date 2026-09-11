package revocation

import (
	"path/filepath"
	"sync"
	"testing"
)

// Slice 3b node→CP propagation: a NEW node-local revocation fires the reporter (so this node's W-2
// auto-revocation ships up to the control plane); an idempotent re-revoke does NOT; ReplaceSynced (the
// CP-distributed layer) never fires it (no report loop).
func TestAdmissionRevocationsReporterFiresOnNewLocalRevocationOnly(t *testing.T) {
	a := NewAdmissionRevocations()
	var mu sync.Mutex
	reported := []string{}
	a.SetReporter(func(id, reason string) { mu.Lock(); reported = append(reported, id); mu.Unlock() })

	a.Revoke("dev-1", "agent_dark")
	a.Revoke("dev-1", "agent_dark") // idempotent — same reason, no new report
	a.Revoke("dev-2", "agent_dark")
	a.ReplaceSynced(map[string]string{"dev-3": "admin_kill_switch"}) // CP-distributed — must NOT report

	mu.Lock()
	defer mu.Unlock()
	if len(reported) != 2 || reported[0] != "dev-1" || reported[1] != "dev-2" {
		t.Fatalf("reporter should fire once per NEW node-local revocation only, got %v", reported)
	}
}

// Phase 3 shared revocation overlay: the overlay has a node-LOCAL layer (this Edge's admin/auto revocations)
// and a CP-distributed SYNCED layer. IsRevoked denies on EITHER (a CP revoke bites everywhere); ReplaceSynced
// swaps the synced layer without touching node-local; the feed (Snapshot) is the node-local set only.
func TestAdmissionRevocationsSharedSyncedLayer(t *testing.T) {
	a := NewAdmissionRevocations()
	a.Revoke("dev-local", "agent_dark")
	if a.ConfigGeneration() == 0 {
		t.Fatalf("Revoke must advance the generation (feed version)")
	}
	if _, ok := a.IsRevoked("dev-local"); !ok {
		t.Fatalf("node-local revoke should deny")
	}

	a.ReplaceSynced(map[string]string{"DEV-CP": "admin_kill_switch"}) // normalized to lowercase
	if _, ok := a.IsRevoked("dev-cp"); !ok {
		t.Fatalf("a CP-distributed (synced) revoke must deny — the shared-revocation invariant")
	}
	if _, ok := a.IsRevoked("dev-local"); !ok {
		t.Fatalf("node-local revoke must SURVIVE ReplaceSynced")
	}

	// The feed the CP ships is the node-local set only (NOT the synced layer — that would loop CP revocations).
	snap := a.Snapshot()
	if _, ok := snap["dev-local"]; !ok {
		t.Fatalf("Snapshot (feed) should include node-local")
	}
	if _, ok := snap["dev-cp"]; ok {
		t.Fatalf("Snapshot (feed) must NOT include the synced layer")
	}

	// An empty ReplaceSynced clears the synced layer (a legitimate CP restore) but not node-local.
	a.ReplaceSynced(map[string]string{})
	if _, ok := a.IsRevoked("dev-cp"); ok {
		t.Fatalf("synced layer should clear on an empty ReplaceSynced")
	}
	if _, ok := a.IsRevoked("dev-local"); !ok {
		t.Fatalf("node-local must remain after the synced layer clears")
	}
}

// A revocation MUST survive a control-plane restart (an in-memory-only set would silently un-revoke everyone
// on the next pull — a fail-OPEN kill-switch). Persistence makes the CP's set durable.
func TestAdmissionRevocationsPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rev.json")
	a := NewAdmissionRevocations()
	a.SetStatePath(path)
	a.Revoke("dev-1", "admin_kill_switch")

	restored := NewAdmissionRevocations() // simulate a restart
	restored.SetStatePath(path)
	if _, ok := restored.IsRevoked("dev-1"); !ok {
		t.Fatalf("a revocation must survive a restart via the durable store")
	}
	// A restore persists too: after clearing, a fresh load is empty.
	a.Restore("dev-1")
	reloaded := NewAdmissionRevocations()
	reloaded.SetStatePath(path)
	if _, ok := reloaded.IsRevoked("dev-1"); ok {
		t.Fatalf("a restore must persist (not resurrect on reload)")
	}
}

func TestAdmissionRevocations_RevokeRestore(t *testing.T) {
	a := NewAdmissionRevocations()
	if _, ok := a.IsRevoked("mac-dev-1"); ok {
		t.Fatal("nothing should be revoked initially")
	}
	a.Revoke("Mac-Dev-1", "agent_dark") // case-insensitive
	reason, ok := a.IsRevoked("mac-dev-1")
	if !ok || reason != "agent_dark" {
		t.Fatalf("expected revoked with reason agent_dark, got ok=%v reason=%q", ok, reason)
	}
	a.Restore("mac-dev-1") // re-enroll / re-attest clears it
	if _, ok := a.IsRevoked("mac-dev-1"); ok {
		t.Fatal("restore must clear the revocation")
	}
}

func TestAdmissionRevocations_EmptyIdentityIgnored(t *testing.T) {
	a := NewAdmissionRevocations()
	a.Revoke("   ", "x")
	if len(a.List()) != 0 {
		t.Fatalf("empty identity must never be revoked, got %v", a.List())
	}
}

func TestAdmissionRevocations_NilSafe(t *testing.T) {
	var a *AdmissionRevocations
	if _, ok := a.IsRevoked("x"); ok {
		t.Fatal("nil overlay must report not-revoked (admission unaffected when W-2 disabled)")
	}
}

func TestAdmitDecision_RevocationWinsOverEnrolment(t *testing.T) {
	enrolled := map[string]struct{}{"mac-dev-1": {}, "win-dev-1": {}}
	revoked := map[string]struct{}{"mac-dev-1": {}}

	// Enrolled + revoked -> DENIED (the point of W-2: still in the file, but auto-revoked).
	if admit, reason := admitDecision(enrolled, revoked, true, "mac-dev-1"); admit || reason != "revoked" {
		t.Errorf("revoked-but-enrolled must be denied(revoked), got admit=%v reason=%q", admit, reason)
	}
	// Enrolled + not revoked -> admitted.
	if admit, _ := admitDecision(enrolled, revoked, true, "win-dev-1"); !admit {
		t.Error("enrolled, non-revoked identity should be admitted")
	}
	// Not enrolled -> denied(not_enrolled).
	if admit, reason := admitDecision(enrolled, revoked, true, "rogue"); admit || reason != "not_enrolled" {
		t.Errorf("unenrolled identity must be denied(not_enrolled), got admit=%v reason=%q", admit, reason)
	}
	// No identity -> denied(no_identity).
	if admit, reason := admitDecision(enrolled, revoked, true, "  "); admit || reason != "no_identity" {
		t.Errorf("empty identity must be denied(no_identity), got admit=%v reason=%q", admit, reason)
	}
}

func TestAdmitDecision_RevocationAppliesEvenWhenEnrolmentNotRequired(t *testing.T) {
	// With requireEnrolled=false the static gate is open, but an explicit auto-revocation must still deny.
	revoked := map[string]struct{}{"mac-dev-1": {}}
	if admit, reason := admitDecision(nil, revoked, false, "mac-dev-1"); admit || reason != "revoked" {
		t.Errorf("revocation must apply even when enrolment is not required, got admit=%v reason=%q", admit, reason)
	}
	// A non-revoked identity passes when enrolment is not required.
	if admit, _ := admitDecision(nil, revoked, false, "other"); !admit {
		t.Error("non-revoked identity should pass when enrolment is not required")
	}
}

// TestSyncedCountAndEmptyReplace documents the layer the sync guard (review finding #5) relies on: SyncedCount
// reflects the CP-distributed layer, and ReplaceSynced itself is a pure setter (an empty set DOES clear it) — so
// the lockout-safe "keep on empty" policy lives in the sync caller, not here.
func TestSyncedCountAndEmptyReplace(t *testing.T) {
	a := NewAdmissionRevocations()
	if a.SyncedCount() != 0 {
		t.Fatalf("fresh SyncedCount = %d, want 0", a.SyncedCount())
	}
	a.ReplaceSynced(map[string]string{"dev-1": "kill", "dev-2": "kill"})
	if a.SyncedCount() != 2 {
		t.Fatalf("SyncedCount after replace = %d, want 2", a.SyncedCount())
	}
	if _, ok := a.IsRevoked("dev-1"); !ok {
		t.Fatal("dev-1 must be revoked via the synced layer")
	}
	// Low-level ReplaceSynced is a pure setter: empty clears (the guard against this lives in revocation_sync).
	a.ReplaceSynced(map[string]string{})
	if a.SyncedCount() != 0 {
		t.Fatalf("ReplaceSynced(empty) should clear the synced layer at the low level, got %d", a.SyncedCount())
	}
}
