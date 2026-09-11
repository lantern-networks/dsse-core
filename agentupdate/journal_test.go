package agentupdate

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var jNow = time.Date(2026, 8, 9, 3, 0, 0, 0, time.UTC)

// ★ The whole reason the journal is written BEFORE each transition. A record of what FINISHED cannot tell
// "never started" from "started and died", and those need opposite responses.
func TestAnAttemptThatDiedMidFlightIsDetectable(t *testing.T) {
	for _, p := range []Phase{PhaseSnapshotted, PhaseDisarmed, PhaseExecuting, PhaseObserving} {
		j := NewJournal()
		j.Begin("0.2.0", "0.1.0", jNow)
		j.Enter(p, jNow)
		got, at := j.Interrupted()
		if !got {
			t.Errorf("phase %s must read as interrupted", p)
		}
		if at != p {
			t.Errorf("interrupted phase = %s, want %s", at, p)
		}
	}
	for _, p := range []Phase{PhaseIdle, PhaseCompleted, PhaseFailed, PhaseRolledBack, PhasePendingReboot, PhaseUnrecoverable} {
		j := NewJournal()
		j.Enter(p, jNow)
		if got, _ := j.Interrupted(); got {
			t.Errorf("phase %s is terminal and must not read as interrupted", p)
		}
	}
}

// Not every interruption is equally urgent. A box stuck at `disarmed` or `executing` may have no working
// network, and that has to be checked before anything else is attempted on it.
func TestOnlyTheDangerousPhasesDemandANetworkCheckFirst(t *testing.T) {
	for p, want := range map[Phase]bool{
		PhaseDisarmed:    true,
		PhaseExecuting:   true,
		PhaseSnapshotted: false, // restore material captured, nothing touched yet
		PhaseObserving:   false, // the installer already returned
		PhaseCompleted:   false,
	} {
		j := NewJournal()
		j.Enter(p, jNow)
		if got := j.NeedsNetworkRecovery(); got != want {
			t.Errorf("phase %s: NeedsNetworkRecovery = %v, want %v", p, got, want)
		}
	}
}

// ★ With a maintenance window, an update that fails every time is a machine for breaking a fleet at the same
// hour every night. The ceiling turns that into a stated refusal.
func TestAVersionThatKeepsFailingIsGivenUpOn(t *testing.T) {
	j := NewJournal()
	j.Begin("0.2.0", "0.1.0", jNow)

	if poisoned := j.RecordFailure("installer exited 1603", 3, jNow); poisoned {
		t.Fatal("one failure must not poison")
	}
	if poisoned := j.RecordFailure("installer exited 1603", 3, jNow); poisoned {
		t.Fatal("two failures must not poison")
	}
	if poisoned := j.RecordFailure("installer exited 1603", 3, jNow); !poisoned {
		t.Fatal("the third failure must poison")
	}

	is, why := j.IsPoisoned("0.2.0")
	if !is {
		t.Fatal("0.2.0 must be poisoned")
	}
	// The reason has to survive: three crashes and one unrecoverable install need different responses.
	for _, want := range []string{"failed 3 times", "1603"} {
		if !strings.Contains(why, want) {
			t.Errorf("poison reason must carry %q, got %q", want, why)
		}
	}
	// Poisoning is per VERSION. Naming a different target is what clears the block — and is the ONLY thing
	// that does, deliberately: a remote un-poison would just be a button for forcing a known-bad build back.
	if is, _ := j.IsPoisoned("0.2.1"); is {
		t.Fatal("a different version must not be poisoned")
	}
}

// Consecutive failures are what the ceiling counts. Without a reset, a device that failed twice months ago is
// one bad night away from being poisoned.
func TestASuccessResetsTheFailureCount(t *testing.T) {
	j := NewJournal()
	j.Begin("0.2.0", "0.1.0", jNow)
	j.RecordFailure("x", 3, jNow)
	j.RecordFailure("x", 3, jNow)
	j.RecordSuccess(jNow)

	if j.Phase != PhaseCompleted {
		t.Fatalf("phase = %s, want completed", j.Phase)
	}
	if n := j.Failures["0.2.0"]; n != 0 {
		t.Fatalf("failure count = %d after a success, want 0", n)
	}
	// And two more failures must not immediately poison, since the count really did reset.
	j.RecordFailure("x", 3, jNow)
	if poisoned := j.RecordFailure("x", 3, jNow); poisoned {
		t.Fatal("the count did not reset: poisoned after 2 post-success failures")
	}
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "update-journal.json")
	j := NewJournal()
	j.Begin("0.2.0", "0.1.0", jNow)
	j.Enter(PhaseExecuting, jNow)
	j.RecordWait(WaitOnBattery, jNow)
	j.RestoreMaterial = []string{`C:\ProgramData\DSSE\rollback\DsseAgent-0.1.0.msi`}
	if err := j.Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}
	// 0600: the journal names versions and paths on this device; it does not need to be world-readable.
	//
	// Unix only, and NOT because the property stops mattering on Windows. Windows has no POSIX permission
	// bits: os.Chmod there toggles only the read-only attribute and Stat reports 0666, so this assertion can
	// never pass on the platform this journal is actually written on. Asserting it where it is meaningful
	// still catches the regression worth catching — a journal accidentally written world-readable. The
	// Windows-side protection is an ACL, which Save does not set; that gap is real and is recorded in the
	// handoff rather than hidden by a green test.
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(path); err != nil {
			t.Fatal(err)
		} else if fi.Mode().Perm() != 0o600 {
			t.Errorf("journal mode = %04o, want 0600", fi.Mode().Perm())
		}
	}

	got, err := LoadJournal(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.TargetVersion != "0.2.0" || got.FromVersion != "0.1.0" || got.Phase != PhaseExecuting {
		t.Fatalf("round trip lost state: %+v", got)
	}
	if got.LastWaitReason != WaitOnBattery || len(got.RestoreMaterial) != 1 {
		t.Fatalf("round trip lost the wait reason or restore material: %+v", got)
	}
	if interrupted, _ := got.Interrupted(); !interrupted {
		t.Fatal("a journal saved mid-execute must load as interrupted")
	}
}

// Save must not leave a torn file behind. A half-written journal is unparseable at exactly the moment it
// matters, and unparseable is indistinguishable from "this device never attempted anything".
func TestSaveLeavesNoPartialFileBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "update-journal.json")
	j := NewJournal()
	j.Begin("0.2.0", "0.1.0", jNow)
	for i := 0; i < 5; i++ {
		if err := j.Save(path); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		// Any leftover, whatever the shared package names its temporary file. The count check below is the
		// real assertion; this one names the file so a failure says what it found.
		if strings.Contains(e.Name(), ".tmp") {
			t.Errorf("a temp file survived: %s", e.Name())
		}
	}
	if len(entries) != 1 {
		t.Errorf("expected exactly the journal, got %d entries", len(entries))
	}
}

// ★ Missing and corrupt are NOT the same. Missing is the normal state of a device that has never updated;
// corrupt would silently discard the record of an interrupted update — the one moment the file matters.
func TestMissingIsFineAndCorruptIsAnError(t *testing.T) {
	dir := t.TempDir()

	fresh, err := LoadJournal(filepath.Join(dir, "absent.json"))
	if err != nil {
		t.Fatalf("a missing journal must not be an error: %v", err)
	}
	if interrupted, _ := fresh.Interrupted(); interrupted {
		t.Fatal("a device that never updated has nothing interrupted")
	}

	bad := filepath.Join(dir, "corrupt.json")
	if err := os.WriteFile(bad, []byte(`{"schema":"dsse_agent_update_journal.v1","phase":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadJournal(bad); err == nil {
		t.Fatal("a corrupt journal must be an error, not an empty one")
	} else if !strings.Contains(err.Error(), "cannot be ruled out") {
		t.Errorf("the error must say what is now unknown, got %q", err)
	}

	wrong := filepath.Join(dir, "wrong-schema.json")
	if err := os.WriteFile(wrong, []byte(`{"schema":"something.else","phase":"idle"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadJournal(wrong); err == nil {
		t.Fatal("an unknown schema must be an error rather than being read with this version's meanings")
	}
}

// ★ A JOURNAL WRITTEN BY AN OLDER BUILD MUST STILL LOAD (2026-08-12, eleventh review). `pending_report`
// shipped as a STRING and became an object under the SAME schema version — so a device that had recorded
// `"pending_report":"installed"` could not unmarshal its journal at all, and this updater treats an unreadable
// journal as "attempt nothing". That device would have been permanently unable to update until somebody
// deleted the file by hand.
func TestAJournalFromAnOlderBuildStillLoads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "journal.json")
	legacy := `{"schema":"dsse_agent_update_journal.v1","target_version":"0.2.9","phase":"completed",` +
		`"updated_at":"2026-08-12T00:00:00Z","pending_report":"installed"}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}

	j, err := LoadJournal(path)
	if err != nil {
		t.Fatalf("an older build's journal did not load: %v — that device can never update again", err)
	}
	if j.PendingReport == nil || j.PendingReport.Status != ReportInstalled {
		t.Fatalf("the pending outcome was lost in the migration: %#v", j.PendingReport)
	}
	// And it round-trips into the new shape, so the next write is the object.
	if err := j.Save(path); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), `"status": "installed"`) {
		t.Fatalf("the rewritten journal did not carry the object form: %s", raw)
	}
	reloaded, err := LoadJournal(path)
	if err != nil || reloaded.PendingReport == nil || reloaded.PendingReport.Status != ReportInstalled {
		t.Fatalf("the new shape did not reload: %v %#v", err, reloaded.PendingReport)
	}
}

// ★ AN UPGRADE MUST NOT RE-REPORT THE WHOLE FLEET (2026-08-12, thirteenth review). ReportedOutcome is new, so
// every journal an older build wrote lacks it — and reading that absence as "never reported" would have every
// device re-send its last outcome, with a new id, on its first pass after the upgrade. The success rate and
// the audit trail would both double in one afternoon.
func TestAJournalFromABuildWithoutReportedOutcomeIsNotReReported(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "journal.json")
	// What the older build left after a successful update: terminal, nothing pending, no ReportedOutcome.
	legacy := `{"schema":"dsse_agent_update_journal.v1","target_version":"0.2.9","from_version":"0.2.8",` +
		`"phase":"completed","updated_at":"2026-08-12T00:00:00Z"}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}

	j, err := LoadJournal(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if j.OwesOutcomeReport() {
		t.Fatalf("an outcome the previous build already reported was marked as owed — every device in the " +
			"fleet would re-send its last outcome after the upgrade")
	}

	// The other case is genuinely owed and must NOT be adopted: terminal AND still holding a pending report.
	owed := `{"schema":"dsse_agent_update_journal.v1","target_version":"0.2.9","phase":"completed",` +
		`"updated_at":"2026-08-12T00:00:00Z","pending_report":"installed"}`
	if err := os.WriteFile(path, []byte(owed), 0o600); err != nil {
		t.Fatal(err)
	}
	j2, err := LoadJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if j2.PendingReport == nil {
		t.Fatalf("a pending outcome was dropped by the adoption")
	}
}

// ★ TWO FAILURES OF ONE VERSION ARE TWO EVENTS. Not every terminal failure increments the failure counter —
// an interrupted attempt and a rollback that could not be launched do not — so the fingerprint needs something
// that moves on every terminal transition.
func TestASecondFailureOfTheSameVersionIsItsOwnEvent(t *testing.T) {
	now := time.Now().UTC()
	j := NewJournal()
	j.Begin("0.2.9", "0.2.8", now)
	j.Enter(PhaseFailed, now)
	first := j.OutcomeFingerprint()
	j.MarkOutcomeReported()
	if j.OwesOutcomeReport() {
		t.Fatalf("a reported failure still reads as owed")
	}

	// The device tries again and fails the same way, without the counter moving.
	j.Enter(PhaseVerified, now)
	j.Enter(PhaseFailed, now)
	if j.OutcomeFingerprint() == first {
		t.Fatalf("the second failure produced the same fingerprint as the first: it would never be reported")
	}
	if !j.OwesOutcomeReport() {
		t.Fatalf("the second failure was treated as already reported")
	}
}
