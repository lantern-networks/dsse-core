package agentupdate

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// TestReconcileClosesACompletedAttempt is the defect this file exists for.
//
// Execute launches the installer detached and returns while the journal says `executing`, and the process is
// then replaced by that installer. Nothing closed the record, so the next pass would find an interrupted
// attempt — and `executing` also satisfies NeedsNetworkRecovery, so the successful update would announce
// "this box's NETWORK must be checked". On the happy path. Every time.
func TestReconcileClosesACompletedAttempt(t *testing.T) {
	now := time.Date(2026, 8, 9, 3, 0, 0, 0, time.UTC)
	j := NewJournal()
	j.Begin("0.2.0", "0.1.0", now)
	j.Enter(PhaseExecuting, now)

	changed, note := Reconcile(j, "0.2.0", nil, now)
	if !changed {
		t.Fatalf("a landed update was not closed out: %q", note)
	}
	if interrupted, phase := j.Interrupted(); interrupted {
		t.Fatalf("journal still reads as interrupted in phase %q", phase)
	}
	if j.NeedsNetworkRecovery() {
		t.Fatal("a successful update still asks for a network check")
	}
	if !strings.Contains(note, "0.2.0") {
		t.Fatalf("note does not name the version: %q", note)
	}
}

// TestReconcileLeavesAnAttemptThatDidNotLand: the installer may have failed, or never run. The record stays
// open so Run reports it — with the network warning, which is TRUE here.
// TestReconcileLeavesAnAttemptThatDidNotLand: the installer may have failed, or never run. The record stays
// open so Run reports it — with the network warning, which is TRUE here.
func TestReconcileLeavesAnAttemptThatDidNotLand(t *testing.T) {
	now := time.Now().UTC()
	j := NewJournal()
	j.Begin("0.2.0", "0.1.0", now)
	j.Enter(PhaseExecuting, now)

	changed, note := Reconcile(j, "0.1.0", nil, now)
	if changed {
		t.Fatal("an attempt that did not land was marked successful")
	}
	if interrupted, _ := j.Interrupted(); !interrupted {
		t.Fatal("the open attempt was closed anyway")
	}
	if !strings.Contains(note, "did not land") {
		t.Fatalf("note does not explain: %q", note)
	}
}

// TestReconcileWillNotGuessWhenTheVersionIsUnreadable is the case that matters most for safety: a box whose
// agent is not running after an install is exactly the box that may have been left without a network.
// Treating an unreadable version as "probably fine" would suppress the warning on the devices that need it.
// TestReconcileWillNotGuessWhenTheVersionIsUnreadable is the case that matters most for safety: a box whose
// agent is not running after an install is exactly the box that may have been left without a network.
// Treating an unreadable version as "probably fine" would suppress the warning on the devices that need it.
func TestReconcileWillNotGuessWhenTheVersionIsUnreadable(t *testing.T) {
	now := time.Now().UTC()
	j := NewJournal()
	j.Begin("0.2.0", "0.1.0", now)
	j.Enter(PhaseDisarmed, now)

	changed, note := Reconcile(j, "", errors.New("no agent process is running"), now)
	if changed {
		t.Fatal("an unreadable running version was treated as success")
	}
	if !j.NeedsNetworkRecovery() {
		t.Fatal("the network warning was cleared for a box whose agent cannot be read")
	}
	if !strings.Contains(note, "stays open") {
		t.Fatalf("note does not say the attempt stays open: %q", note)
	}
}

// TestReconcileIsQuietWhenNothingIsOutstanding: most ticks on most devices have nothing to close, and a note
// on every one of those would bury the ones that matter.
// TestReconcileIsQuietWhenNothingIsOutstanding: most ticks on most devices have nothing to close, and a note
// on every one of those would bury the ones that matter.
func TestReconcileIsQuietWhenNothingIsOutstanding(t *testing.T) {
	j := NewJournal()
	changed, note := Reconcile(j, "0.1.0", nil, time.Now())
	if changed || note != "" {
		t.Fatalf("idle journal produced changed=%v note=%q", changed, note)
	}
	if changed, note := Reconcile(nil, "0.1.0", nil, time.Now()); changed || note != "" {
		t.Fatalf("nil journal produced changed=%v note=%q", changed, note)
	}
}

// --- Tick -------------------------------------------------------------------------------------------------

// ★ READ OFF A LIVE MAC'S JOURNAL, 2026-08-11. The manifest offered "0.2.1"; the device reported
// "0.2.1+20260811035942", because an agent's version is its short version plus its build stamp. Compared as
// strings those never match, so a successful update stayed open, was declared interrupted, and told the
// operator that a perfectly healthy box's NETWORK must be checked. The install grace added that morning did
// not fix this — it delayed it by ten minutes.
func TestReconcileConfirmsAnUpdateWhoseBuildMetadataDiffers(t *testing.T) {
	now := time.Date(2026, 8, 11, 4, 9, 25, 0, time.UTC)
	j := NewJournal()
	j.Begin("0.2.1", "0.2.0+20260811013215", now) // exactly what the device wrote
	j.Enter(PhaseExecuting, now)

	changed, note := Reconcile(j, "0.2.1+20260811035942", nil, now.Add(2*time.Minute))
	if !changed {
		t.Fatalf("the update LANDED and was not recognised: %q", note)
	}
	if j.Phase != PhaseCompleted {
		t.Fatalf("phase = %q, want %q", j.Phase, PhaseCompleted)
	}
	if j.NeedsNetworkRecovery() {
		t.Fatal("a successful update still asks for this box's network to be checked")
	}

	// And the negative half must survive: a DIFFERENT version is still not the target.
	j2 := NewJournal()
	j2.Begin("0.2.1", "0.2.0", now)
	j2.Enter(PhaseExecuting, now)
	if changed, _ := Reconcile(j2, "0.2.0+20260811013215", nil, now); changed {
		t.Fatal("an attempt that did not land must stay open — ignoring build metadata must not ignore the version")
	}
}

// The poison map is written in two dialects: RecordFailure keys it by the manifest's version, a rollback by
// what the device was running. A lookup that misses the second lets a just-rolled-back device take the bad
// build again on its next tick.
func TestPoisonIsFoundAcrossBuildMetadata(t *testing.T) {
	j := NewJournal()
	j.Refuse("0.2.1+20260811035942", "rolled back")

	if poisoned, _ := j.IsPoisoned("0.2.1"); !poisoned {
		t.Fatal("a version refused with its build stamp must still be refused when the manifest offers it without one")
	}
	if poisoned, _ := j.IsPoisoned("0.2.2"); poisoned {
		t.Fatal("a different version must not be caught by the same match")
	}
}
