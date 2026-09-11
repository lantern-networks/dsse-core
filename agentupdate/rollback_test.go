package agentupdate

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// rollbackPlatform is a device that updated 0.2.0 -> 0.2.1 and still holds the package for 0.2.0.
func rollbackPlatform() *fakePlatform {
	return &fakePlatform{
		running: "0.2.1",
		cond:    at("03:00", time.Hour),
		held:    map[string]string{"0.2.0": "/Library/Application Support/Dsse/rollback/dsse-agent-0.2.0.pkg"},
	}
}

// updatedJournal is what the journal looks like after that update landed.
func updatedJournal() *Journal {
	j := NewJournal()
	j.Begin("0.2.1", "0.2.0", jNow)
	j.RecordSuccess(jNow)
	return j
}

func rollbackCfg() Config { return Config{MaxAttempts: 3, Platform: PlatformDarwin, Arch: ArchARM64} }

// The ordinary case: no version named, so the journal answers — and the package the device actually holds is
// what gets installed.
func TestRollbackGoesToTheVersionTheJournalCameFrom(t *testing.T) {
	p, rec, j := rollbackPlatform(), &recorder{}, updatedJournal()

	out, err := Rollback(j, RollbackRequest{}, rollbackCfg(), p, rec.save, jNow.Add(time.Hour))
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if out.Action != ActionRollingBack {
		t.Fatalf("action = %s (%s), want rolling_back", out.Action, out.Reason)
	}
	if p.rolledBackTo != "0.2.0" || p.rolledBackPkg != p.held["0.2.0"] {
		t.Fatalf("installed %q for %q, want the stored 0.2.0 package", p.rolledBackPkg, p.rolledBackTo)
	}
	if j.Phase != PhaseRollingBack {
		t.Fatalf("phase = %q, want %q", j.Phase, PhaseRollingBack)
	}
	if !j.IsRollback() {
		t.Error("the journal must record that this attempt is a rollback: every other field reads the same as an update")
	}
	// The phase was persisted BEFORE the installer was launched, like every other step in this design.
	var seq []string
	for _, ph := range rec.phases {
		seq = append(seq, string(ph))
	}
	if last := strings.Join(seq, ","); !strings.Contains(last, string(PhaseRollingBack)) {
		t.Fatalf("journal sequence %q never recorded %q before the installer ran", last, PhaseRollingBack)
	}
}

// ★ THE ONE THAT MAKES A ROLLBACK STICK. Without it the device rolls back and the next ordinary tick installs
// the version it just escaped.
func TestRollbackRefusesTheVersionItLeaves(t *testing.T) {
	p, j := rollbackPlatform(), updatedJournal()
	if _, err := Rollback(j, RollbackRequest{}, rollbackCfg(), p, func(*Journal) error { return nil }, jNow); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	poisoned, why := j.IsPoisoned("0.2.1")
	if !poisoned {
		t.Fatal("0.2.1 must be refused on this device after being rolled back from — otherwise the next tick reinstalls it")
	}
	if !strings.Contains(why, "rolled back") {
		t.Errorf("the reason an operator reads later must say what happened, got %q", why)
	}

	// And the next ordinary pass must actually honour it. The pass reconciles first, exactly as the updater
	// daemon does — the rollback landed while the process that started it was being replaced.
	if changed, _ := Reconcile(j, "0.2.0", nil, jNow.Add(time.Minute)); !changed {
		t.Fatal("the landed rollback must reconcile before anything else is judged")
	}
	up := readyPlatform()
	up.running = "0.2.0"
	m := goodManifest()
	m.Version = "0.2.1"
	m.MinFromVersion = ""
	out, err := Run(j, m, runCfg(), up, func(*Journal) error { return nil }, jNow.Add(2*InstallGrace))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if out.Action != ActionRefused || !strings.Contains(out.Reason, "poisoned") {
		t.Fatalf("after a rollback the next pass gave %s (%s), want a refusal naming the poison", out.Action, out.Reason)
	}
}

// Nothing may be touched when the version asked for is not on this device — and the refusal must be useful.
func TestRollbackRefusesWhenThisDeviceHoldsNoPackage(t *testing.T) {
	p, j := rollbackPlatform(), updatedJournal()
	p.held = nil

	out, err := Rollback(j, RollbackRequest{}, rollbackCfg(), p, func(*Journal) error {
		t.Error("nothing may be written when the rollback never starts: the device is unchanged")
		return nil
	}, jNow)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if out.Action != ActionRefused {
		t.Fatalf("action = %s, want refused", out.Action)
	}
	if strings.Contains(strings.Join(p.calls, ","), "rollback") {
		t.Fatal("no installer may be launched without a package")
	}
	if j.Phase == PhaseRollingBack {
		t.Fatal("a rollback that never started must not leave the journal saying one is running")
	}
}

// ★ The rollback path does NOT require a readable running version, and this is the opposite of Run. A box
// whose agent is broken is the box a rollback exists for.
func TestRollbackProceedsWhenTheRunningVersionCannotBeRead(t *testing.T) {
	p, j := rollbackPlatform(), updatedJournal()
	p.running, p.runningErr = "", ErrAgentNotRunning

	out, err := Rollback(j, RollbackRequest{}, rollbackCfg(), p, func(*Journal) error { return nil }, jNow)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if out.Action != ActionRollingBack {
		t.Fatalf("action = %s (%s), want rolling_back — refusing here withholds the mechanism at the moment it "+
			"exists for", out.Action, out.Reason)
	}
	if !strings.Contains(out.Reason, "could NOT be established") {
		t.Errorf("what could not be established must be said out loud, got %q", out.Reason)
	}
	// Nothing may be poisoned on a guess: the version being left was never established.
	if len(j.Poisoned) != 0 {
		t.Errorf("no version may be refused when it is unknown what this device was running, got %v", j.Poisoned)
	}
}

// ★ Measured on win-dev-1, 2026-08-11: a rollback landed on a box whose agent could not start, and the journal
// came back with poisoned=[]. The two rules above are each right and leave a hole between them — a rollback
// poisons the version it leaves, and an unreadable running version does not refuse — so on the box the whole
// mechanism EXISTS FOR, nothing is refused and the next ordinary tick can put the bad build straight back.
//
// The caller's weaker answer (on Windows, what the MSI recorded as installed) closes it. It is used ONLY to
// name what is being left, never as a stand-in for the running version.
func TestRollbackRefusesTheInstalledVersionWhenTheRunningOneCannotBeRead(t *testing.T) {
	p, j := rollbackPlatform(), updatedJournal()
	p.running, p.runningErr = "", ErrAgentNotRunning

	out, err := Rollback(j, RollbackRequest{LeavingVersion: "0.2.1"}, rollbackCfg(), p,
		func(*Journal) error { return nil }, jNow)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if out.Action != ActionRollingBack {
		t.Fatalf("action = %s (%s), want rolling_back", out.Action, out.Reason)
	}
	if poisoned, _ := j.IsPoisoned("0.2.1"); !poisoned {
		t.Fatal("the build being left was named by the caller and still was not refused — this box would take " +
			"it again on the next tick, which is the whole failure a rollback is supposed to end")
	}
	if j.FromVersion != "0.2.1" {
		t.Errorf("from_version = %q, want the version being left: a later --rollback reads it", j.FromVersion)
	}
	// The weaker source must be visible. An operator who reads "0.2.1 is refused" has to be able to tell
	// whether anything confirmed the box was on it.
	if !strings.Contains(out.Reason, "INSTALLED") {
		t.Errorf("the reason must say the refusal rests on what is installed rather than what is running, got %q", out.Reason)
	}
}

// And when neither answer is available, the consequence is stated rather than left as silence: the rollback
// still lands, and nothing stops the build it escaped from coming back.
func TestRollbackSaysNothingWasRefusedWhenNeitherVersionIsKnown(t *testing.T) {
	p, j := rollbackPlatform(), updatedJournal()
	p.running, p.runningErr = "", ErrAgentNotRunning

	out, err := Rollback(j, RollbackRequest{}, rollbackCfg(), p, func(*Journal) error { return nil }, jNow)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if len(j.Poisoned) != 0 {
		t.Fatalf("nothing may be refused on a guess, got %v", j.Poisoned)
	}
	if !strings.Contains(out.Reason, "NOTHING HAS BEEN REFUSED") {
		t.Errorf("the operator must be told that this rollback will not stay rolled back on its own, got %q", out.Reason)
	}
}

// Two installers on one box is how a machine ends up with neither version.
func TestRollbackWaitsWhileAnInstallerMayStillBeRunning(t *testing.T) {
	p, j := rollbackPlatform(), NewJournal()
	j.Begin("0.2.1", "0.2.0", jNow)
	j.Enter(PhaseExecuting, jNow)

	out, _ := Rollback(j, RollbackRequest{}, rollbackCfg(), p, func(*Journal) error { return nil }, jNow.Add(time.Minute))
	if out.Action != ActionRefused {
		t.Fatalf("action = %s (%s), want refused inside the install grace", out.Action, out.Reason)
	}
	if strings.Contains(strings.Join(p.calls, ","), "rollback") {
		t.Fatal("no second installer may be launched while the first may still be running")
	}

	// Past the grace it proceeds: an attempt that stopped part way is exactly what a rollback is for.
	out, _ = Rollback(j, RollbackRequest{}, rollbackCfg(), p, func(*Journal) error { return nil },
		jNow.Add(InstallGrace+time.Minute))
	if out.Action != ActionRollingBack {
		t.Fatalf("action = %s (%s), want rolling_back once the installer can no longer be running", out.Action, out.Reason)
	}
}

// A rollback of a rollback would be a re-install of the build that was just abandoned.
func TestRollbackWillNotWalkForwardIntoTheVersionItJustLeft(t *testing.T) {
	p, j := rollbackPlatform(), updatedJournal()
	if _, err := Rollback(j, RollbackRequest{}, rollbackCfg(), p, func(*Journal) error { return nil }, jNow); err != nil {
		t.Fatalf("first rollback: %v", err)
	}
	// The device is now on 0.2.0 and the journal records a rollback whose from_version is 0.2.1.
	p.running = "0.2.0"
	p.held["0.2.1"] = "/tmp/dsse-agent-0.2.1.pkg"

	out, _ := Rollback(j, RollbackRequest{}, rollbackCfg(), p, func(*Journal) error { return nil }, jNow.Add(2*InstallGrace))
	if out.Action != ActionRefused {
		t.Fatalf("action = %s (%s), want refused", out.Action, out.Reason)
	}
	if !strings.Contains(out.Reason, "ALREADY abandoned") {
		t.Errorf("the refusal must explain that from_version is the abandoned build, got %q", out.Reason)
	}
}

// An explicitly named version is bounded by what this device holds, which is what keeps the downgrade override
// from being a way to push any build onto a machine.
func TestRollbackToANamedVersionMustStillBeHeld(t *testing.T) {
	p, j := rollbackPlatform(), updatedJournal()

	out, _ := Rollback(j, RollbackRequest{ToVersion: "0.0.1"}, rollbackCfg(), p, func(*Journal) error { return nil }, jNow)
	if out.Action != ActionRefused {
		t.Fatalf("action = %s (%s), want refused for a version this device does not hold", out.Action, out.Reason)
	}

	p.held["0.1.0"] = "/tmp/dsse-agent-0.1.0.pkg"
	out, _ = Rollback(j, RollbackRequest{ToVersion: "0.1.0"}, rollbackCfg(), p, func(*Journal) error { return nil }, jNow)
	if out.Action != ActionRollingBack || p.rolledBackTo != "0.1.0" {
		t.Fatalf("action = %s (%s), installed %q — an operator naming a held version must be obeyed",
			out.Action, out.Reason, p.rolledBackTo)
	}
}

// A rollback that could not be launched must not poison the only version this device has left to go back to.
func TestAFailedRollbackDoesNotPoisonTheVersionItWasRestoring(t *testing.T) {
	p, j := rollbackPlatform(), updatedJournal()
	p.rollbackErr = errors.New("installer would not start")

	out, err := Rollback(j, RollbackRequest{}, rollbackCfg(), p, func(*Journal) error { return nil }, jNow)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if out.Action != ActionRefused {
		t.Fatalf("action = %s, want refused", out.Action)
	}
	if poisoned, why := j.IsPoisoned("0.2.0"); poisoned {
		t.Fatalf("the version being restored must never be poisoned by a failed rollback (%s) — that locks the "+
			"operator out of the recovery path with the recovery path", why)
	}
	if j.Phase != PhaseFailed {
		t.Errorf("phase = %q, want %q", j.Phase, PhaseFailed)
	}
}

// A rehearsal must change nothing — the same rule the update path learned by leaving a device looking
// mid-update because somebody tested.
func TestARollbackRehearsalChangesNothing(t *testing.T) {
	p, j := rollbackPlatform(), updatedJournal()
	cfg := rollbackCfg()
	cfg.DryRun = true

	out, err := Rollback(j, RollbackRequest{}, cfg, p, func(*Journal) error {
		t.Error("a rehearsal must not write the journal")
		return nil
	}, jNow)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if out.Action != ActionWouldRollBack {
		t.Fatalf("action = %s (%s), want would_roll_back", out.Action, out.Reason)
	}
	if strings.Contains(strings.Join(p.calls, ","), "rollback") {
		t.Fatal("a rehearsal must not launch an installer")
	}
	if j.Phase != PhaseCompleted || j.IsRollback() || len(j.Poisoned) != 0 {
		t.Fatalf("the caller's journal was moved by a rehearsal: phase=%q rollback=%v poisoned=%v",
			j.Phase, j.IsRollback(), j.Poisoned)
	}
}

// Steering comes down first where the posture permits it — the direction of travel does not change what an
// armed redirect does to a box with no agent.
func TestRollbackDisarmsFirstWherePosturePermits(t *testing.T) {
	p, j := rollbackPlatform(), updatedJournal()
	p.disarmWant = true

	if _, err := Rollback(j, RollbackRequest{}, rollbackCfg(), p, func(*Journal) error { return nil }, jNow); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if got := strings.Join(p.calls, ","); !strings.Contains(got, "disarm,rollback") {
		t.Fatalf("call order = %q, want the disarm before the installer", got)
	}

	// And an unconfirmed disarm stops it, exactly as it stops an update.
	p2, j2 := rollbackPlatform(), updatedJournal()
	p2.disarmWant, p2.disarmErr = true, errors.New("driver still reports a redirect policy in force")
	out, _ := Rollback(j2, RollbackRequest{}, rollbackCfg(), p2, func(*Journal) error { return nil }, jNow)
	if out.Action != ActionRefused || strings.Contains(strings.Join(p2.calls, ","), "rollback") {
		t.Fatalf("action = %s, calls = %v — an installer must not run against a box whose redirect may be armed",
			out.Action, p2.calls)
	}
}

// The next pass is what establishes that the rollback LANDED, and it must say so in its own words.
func TestReconcileClosesARollbackAsRolledBackNotCompleted(t *testing.T) {
	p, j := rollbackPlatform(), updatedJournal()
	if _, err := Rollback(j, RollbackRequest{}, rollbackCfg(), p, func(*Journal) error { return nil }, jNow); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	// Still on the new version: nothing landed yet.
	changed, note := Reconcile(j, "0.2.1", nil, jNow.Add(time.Minute))
	if changed || !strings.Contains(note, "did not land") {
		t.Fatalf("changed=%v note=%q, want an open rollback", changed, note)
	}
	if !strings.Contains(note, "rollback") {
		t.Errorf("the note must say this is a rollback, not an update, got %q", note)
	}

	changed, note = Reconcile(j, "0.2.0", nil, jNow.Add(2*time.Minute))
	if !changed {
		t.Fatal("the rollback landed and must be recorded")
	}
	if j.Phase != PhaseRolledBack {
		t.Fatalf("phase = %q, want %q — a fleet walked backwards must not read as one that took the release",
			j.Phase, PhaseRolledBack)
	}
	if !strings.Contains(note, "ROLLED BACK") {
		t.Errorf("note = %q, want it to say what happened", note)
	}
}

// ★ A ROLLBACK MUST NOT ERASE WHAT THE FLEET IS STILL OWED (2026-08-13, twenty-ninth review). BeginRollback
// puts the phase back to Verified and zeroes the outcome fingerprint, so a terminal failure that had not
// reached the outbox vanished — and the failure that prompted the rollback is precisely the one the fleet
// never heard about.
func TestARollbackKeepsAnOwedOutcome(t *testing.T) {
	j := NewJournal()
	j.Begin("0.2.9", "0.2.4", time.Now().UTC())
	j.Enter(PhaseFailed, time.Now().UTC())
	j.LastFailureReason = "the installer exited non-zero"
	if !j.OwesOutcomeReport() {
		t.Fatal("the fixture does not owe an outcome")
	}

	_, err := Rollback(j, RollbackRequest{ToVersion: "0.2.4"}, Config{Platform: PlatformDarwin, Arch: "arm64"},
		&fakePlatform{running: "0.2.9", held: map[string]string{"0.2.4": "/tmp/x.pkg"}},
		func(*Journal) error { return nil }, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	if j.PendingReport == nil {
		t.Fatal("the owed failure was dropped by the rollback: the fleet never learns why the operator rolled back")
	}
	if j.PendingReport.Status != ReportFailed {
		t.Fatalf("the pending outcome is %q, want the failure that was owed", j.PendingReport.Status)
	}
}

// And rolling back to the version already running is still a no-op, even when one side carries build metadata.
func TestARollbackToTheRunningVersionDoesNothingDespiteBuildMetadata(t *testing.T) {
	j := NewJournal()
	j.Begin("0.2.9", "0.2.1", time.Now().UTC())

	out, err := Rollback(j, RollbackRequest{ToVersion: "0.2.1"}, Config{Platform: PlatformDarwin, Arch: "arm64"},
		&fakePlatform{running: "0.2.1+stamp", held: map[string]string{"0.2.1": "/tmp/x.pkg"}},
		func(*Journal) error { return nil }, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if out.Action != ActionNone {
		t.Fatalf("action = %q: a build-metadata difference made this device roll back onto itself, and the "+
			"rollback then REFUSES the version it is running — every later manifest offering it is rejected",
			out.Action)
	}
	if poisoned, why := j.IsPoisoned("0.2.1"); poisoned {
		t.Fatalf("the version this device is running was poisoned by a rollback to it: %s", why)
	}
}

// ★★ AN INTERRUPTED ROLLBACK MUST NOT POISON THE VERSION IT WAS RESTORING (2026-08-13, thirtieth review #7).
// The twenty-ninth review added a branch that records an interrupted attempt as a failure so the fleet hears
// about it. RecordFailure counts against j.TargetVersion — which after BeginRollback is the RESTORE TARGET,
// not the build being escaped. So on an unstable box, re-entering --rollback three times counted three
// failures against the known-good version and poisoned it: the device then refuses the only build it was
// trying to get back to, and the guard written for exactly that outcome sits sixty lines below, reached by
// another road.
func TestAnInterruptedRollbackDoesNotPoisonTheRestoreTarget(t *testing.T) {
	stale := time.Now().UTC().Add(-4 * time.Hour)
	j := NewJournal()
	// The state a rollback that died mid-install leaves: target is where it was restoring TO.
	j.Begin("0.2.4", "0.2.9", stale)
	j.AttemptKind = KindRollback
	j.Enter(PhaseExecuting, stale)

	for attempt := 1; attempt <= 4; attempt++ {
		_, err := Rollback(j, RollbackRequest{ToVersion: "0.2.4"}, Config{Platform: PlatformDarwin, Arch: "arm64"},
			&fakePlatform{running: "0.2.9", held: map[string]string{"0.2.4": "/tmp/x.pkg"}},
			func(*Journal) error { return nil }, time.Now().UTC())
		if err != nil {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
		if poisoned, why := j.IsPoisoned("0.2.4"); poisoned {
			t.Fatalf("attempt %d poisoned the restore target (%s) — the device now refuses the only build it was "+
				"trying to get back to", attempt, why)
		}
		// Put it back into the interrupted state for the next re-entry.
		j.Begin("0.2.4", "0.2.9", stale)
		j.AttemptKind = KindRollback
		j.Enter(PhaseExecuting, stale)
	}
}

// The forward case must keep counting: an interrupted UPDATE is a failure of the version being installed, and
// three of them are what poison exists for.
func TestAnInterruptedForwardUpdateStillCountsAgainstItsTarget(t *testing.T) {
	stale := time.Now().UTC().Add(-4 * time.Hour)
	j := NewJournal()
	j.Begin("0.3.0", "0.2.9", stale)
	j.Enter(PhaseExecuting, stale)

	_, err := Rollback(j, RollbackRequest{ToVersion: "0.2.9"}, Config{Platform: PlatformDarwin, Arch: "arm64"},
		&fakePlatform{running: "0.3.0", held: map[string]string{"0.2.9": "/tmp/x.pkg"}},
		func(*Journal) error { return nil }, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if j.Failures["0.3.0"] != 1 {
		t.Fatalf("the interrupted forward attempt was not counted against 0.3.0: %v", j.Failures)
	}
}
