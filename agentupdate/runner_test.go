package agentupdate

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// fakePlatform records the ORDER of calls, because the order is what this file is testing.
type fakePlatform struct {
	running    string
	runningErr error
	cond       DeviceConditions
	material   []string
	captureErr error
	disarmWant bool
	disarmErr  error
	rearmErr   error
	execErr    error
	calls      []string

	// held is the rollback store this fake stands in for: version -> package path.
	held          map[string]string
	rollbackErr   error
	rolledBackTo  string
	rolledBackPkg string
}

func (f *fakePlatform) RunningVersion() (string, error) { return f.running, f.runningErr }
func (f *fakePlatform) Conditions(time.Time) DeviceConditions {
	return f.cond
}
func (f *fakePlatform) CaptureRestoreMaterial(Manifest) ([]string, error) {
	f.calls = append(f.calls, "capture")
	return f.material, f.captureErr
}
func (f *fakePlatform) RestoreMaterialFor(version string) (string, error) {
	f.calls = append(f.calls, "lookup:"+version)
	if p, ok := f.held[version]; ok {
		return p, nil
	}
	return "", fmt.Errorf("no installer package stored for %s", version)
}
func (f *fakePlatform) ExecuteRollback(pkg, toVersion string) error {
	f.calls = append(f.calls, "rollback")
	f.rolledBackPkg, f.rolledBackTo = pkg, toVersion
	return f.rollbackErr
}
func (f *fakePlatform) Rearm() error {
	f.calls = append(f.calls, "rearm")
	return f.rearmErr
}
func (f *fakePlatform) DisarmBeforeUpdate() bool { return f.disarmWant }
func (f *fakePlatform) Disarm() error            { f.calls = append(f.calls, "disarm"); return f.disarmErr }
func (f *fakePlatform) Execute(Manifest) error {
	f.calls = append(f.calls, "execute")
	return f.execErr
}

func readyPlatform() *fakePlatform {
	return &fakePlatform{
		running:    "0.1.0",
		cond:       at("03:00", time.Hour),
		material:   []string{`C:\ProgramData\DSSE\rollback\DsseAgent-0.1.0.msi`},
		disarmWant: true,
	}
}

// runCfg is a WINDOWS endpoint, which is why SteeringSurvivesAgent is true here: the WFP redirect is held in
// the kernel and outlives the agent, so an interrupted attempt on this platform really does mean the network
// must be checked. The macOS half of that distinction has its own test below.
func runCfg() Config {
	return Config{Window: nightWindow(), MaxAttempts: 3, Platform: PlatformWindows, Arch: ArchAMD64,
		SteeringSurvivesAgent: true}
}

// journal writes are captured so the test can assert what was persisted BEFORE each action.
type recorder struct{ phases []Phase }

func (r *recorder) save(j *Journal) error { r.phases = append(r.phases, j.Phase); return nil }

// ★ The two orderings that carry the safety. Restore material is secured before anything is touched, and
// steering comes down before the installer is handed control.
func TestTheOrderIsCaptureThenDisarmThenExecute(t *testing.T) {
	p, rec, j := readyPlatform(), &recorder{}, NewJournal()
	out, err := Run(j, goodManifest(), runCfg(), p, rec.save, jNow)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if out.Action != ActionExecuting {
		t.Fatalf("action = %s (%s), want executing", out.Action, out.Reason)
	}
	if got := strings.Join(p.calls, ","); got != "capture,disarm,execute" {
		t.Fatalf("call order = %q, want capture,disarm,execute", got)
	}
	// And each phase was journalled BEFORE the action it names, so a death between any two lines is legible.
	joined := ""
	for _, ph := range rec.phases {
		joined += string(ph) + ","
	}
	for _, want := range []string{"snapshotted,", "disarmed,", "executing,"} {
		if !strings.Contains(joined, want) {
			t.Errorf("journal never recorded %s (sequence: %s)", want, joined)
		}
	}
	if strings.Index(joined, "disarmed") > strings.Index(joined, "executing") {
		t.Error("disarm must be journalled before execute")
	}
}

// ★ An update that cannot be rolled back is the same as having no rollback. The moment to find that out is
// before the installer runs.
func TestNoRestoreMaterialAbortsBeforeTouchingAnything(t *testing.T) {
	p := readyPlatform()
	p.captureErr = errors.New("no MSI for 0.1.0 in the rollback store")
	rec, j := &recorder{}, NewJournal()

	out, err := Run(j, goodManifest(), runCfg(), p, rec.save, jNow)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if out.Action != ActionRefused {
		t.Fatalf("action = %s, want refused", out.Action)
	}
	if strings.Contains(strings.Join(p.calls, ","), "disarm") || strings.Contains(strings.Join(p.calls, ","), "execute") {
		t.Fatalf("nothing may be touched after a failed capture, got calls %v", p.calls)
	}
	if !strings.Contains(out.Reason, "nothing to roll back") {
		t.Errorf("the reason must say why, got %q", out.Reason)
	}
}

// ★ Handing the installer a box whose redirect may still be armed is the black hole. An unconfirmed disarm
// must stop the update, not be hoped past.
func TestAnUnconfirmedDisarmStopsTheUpdate(t *testing.T) {
	p := readyPlatform()
	p.disarmErr = errors.New("driver still reports a redirect policy in force")
	rec, j := &recorder{}, NewJournal()

	out, _ := Run(j, goodManifest(), runCfg(), p, rec.save, jNow)
	if out.Action != ActionRefused {
		t.Fatalf("action = %s, want refused", out.Action)
	}
	if strings.Contains(strings.Join(p.calls, ","), "execute") {
		t.Fatal("the installer must not run when steering could not be confirmed down")
	}
	if !strings.Contains(out.Reason, "refusing every connection") {
		t.Errorf("the reason must name the consequence, got %q", out.Reason)
	}
}

// A fail-closed endpoint must not have its steering taken down by the updater: that would break the posture
// the operator chose.
func TestAFailClosedEndpointIsNotDisarmed(t *testing.T) {
	p := readyPlatform()
	p.disarmWant = false
	out, _ := Run(NewJournal(), goodManifest(), runCfg(), p, (&recorder{}).save, jNow)

	if out.Action != ActionExecuting {
		t.Fatalf("action = %s, want executing", out.Action)
	}
	if got := strings.Join(p.calls, ","); got != "capture,execute" {
		t.Fatalf("call order = %q, want capture,execute with no disarm", got)
	}
}

func TestTheGateHoldsBeforeAnythingIsTouched(t *testing.T) {
	p := readyPlatform()
	p.cond = at("14:00", time.Hour) // working day
	j := NewJournal()

	out, _ := Run(j, goodManifest(), runCfg(), p, (&recorder{}).save, jNow)
	if out.Action != ActionWaiting {
		t.Fatalf("action = %s, want waiting", out.Action)
	}
	if len(p.calls) != 0 {
		t.Fatalf("nothing may be touched while waiting, got %v", p.calls)
	}
	// The wait reason is persisted, so "why is this device still on the old build" is answerable now rather
	// than at the next tick.
	if j.LastWaitReason != WaitOutOfWindow {
		t.Fatalf("journal wait reason = %q, want %q", j.LastWaitReason, WaitOutOfWindow)
	}
}

// ★ An interrupted attempt outranks a new one. Layering another install onto a box in an unknown state is
// how a bad situation becomes an unrecoverable one.
func TestAnInterruptedAttemptIsHandledBeforeAnyNewOne(t *testing.T) {
	p, j := readyPlatform(), NewJournal()
	j.Begin("0.2.0", "0.1.0", jNow)
	j.Enter(PhaseExecuting, jNow) // died mid-install

	// ★ Past the grace, deliberately. An attempt is only "interrupted" once the installer could no longer be
	// running (InstallGrace) — before that it is the ordinary middle of an install, and treating it as a
	// failure is what put `failed` and a false network alarm on a Mac that had just updated successfully.
	// This test is about the ORDER (an interrupted attempt outranks a new one), which the clock does not change.
	out, err := Run(j, goodManifest(), runCfg(), p, (&recorder{}).save, jNow.Add(InstallGrace+time.Minute))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if out.Action != ActionResumed {
		t.Fatalf("action = %s, want resumed", out.Action)
	}
	if len(p.calls) != 0 {
		t.Fatalf("no new attempt may start on an unfinished box, got %v", p.calls)
	}
	// And the dangerous phases must say the network needs checking first.
	if !strings.Contains(out.Reason, "NETWORK must be checked") {
		t.Errorf("an interrupted execute must flag the network, got %q", out.Reason)
	}
}

func TestAPoisonedVersionIsRefusedWithoutTouchingTheDevice(t *testing.T) {
	p, j := readyPlatform(), NewJournal()
	j.Begin("0.2.0", "0.1.0", jNow)
	j.RecordFailure("x", 1, jNow) // maxAttempts=1 poisons immediately
	j.Enter(PhaseIdle, jNow)      // clear the interrupted state so poisoning is what is under test

	out, _ := Run(j, goodManifest(), runCfg(), p, (&recorder{}).save, jNow)
	if out.Action != ActionRefused {
		t.Fatalf("action = %s, want refused", out.Action)
	}
	if len(p.calls) != 0 {
		t.Fatalf("a poisoned version must not touch the device, got %v", p.calls)
	}
	if !strings.Contains(out.Reason, "Name a different version") {
		t.Errorf("the refusal must say how to clear it, got %q", out.Reason)
	}
}

func TestANonApplicableManifestDoesNothing(t *testing.T) {
	p := readyPlatform()
	p.running = "0.3.0" // newer than the manifest publishes
	out, _ := Run(NewJournal(), goodManifest(), runCfg(), p, (&recorder{}).save, jNow)
	if out.Action != ActionNone {
		t.Fatalf("action = %s, want none", out.Action)
	}
	if len(p.calls) != 0 {
		t.Fatalf("nothing to do means nothing touched, got %v", p.calls)
	}
}

// ★ A step that could not be recorded must not be taken. The journal is the only thing standing between an
// interrupted update and an unexplainable box, so proceeding without it defeats the point.
func TestAFailedJournalWriteStopsTheUpdate(t *testing.T) {
	p := readyPlatform()
	failAt := PhaseSnapshotted
	save := func(j *Journal) error {
		if j.Phase == failAt {
			return errors.New("disk full")
		}
		return nil
	}
	out, err := Run(NewJournal(), goodManifest(), runCfg(), p, save, jNow)
	if err == nil {
		t.Fatalf("an unrecordable step must be an error, got outcome %+v", out)
	}
	if strings.Contains(strings.Join(p.calls, ","), "execute") {
		t.Fatal("the installer ran despite the journal write failing")
	}
}

// --- the running version, when there is no running agent -------------------------------------------------
//
// ★ Raised from win-dev-1 while implementing the Windows half: the spec said RunningVersion must be "the code
// EXECUTING, not what is on disk" and did not say what to do when nothing is executing. Every available answer
// is wrong except refusing, so the interface names a sentinel for it and this is where the behaviour is
// pinned.

func TestADeadAgentRefusesTheUpdateRatherThanGuessing(t *testing.T) {
	p, rec, j := readyPlatform(), &recorder{}, NewJournal()
	p.runningErr = ErrAgentNotRunning

	out, err := Run(j, goodManifest(), runCfg(), p, rec.save, jNow)
	if err != nil {
		t.Fatalf("a dead agent is a normal state, not a runner fault: %v", err)
	}
	if out.Action != ActionRefused {
		t.Fatalf("action = %s (%s), want refused", out.Action, out.Reason)
	}
	// Nothing may have been touched: no restore material captured, no disarm, and above all no installer.
	if len(p.calls) != 0 {
		t.Fatalf("an unassessable device must be left alone entirely, got %v", p.calls)
	}
}

// ★ The failure this must not cause. Counting a dead agent as an attempt would poison a perfectly good version
// after MaxAttempts, and it would STAY poisoned once the agent came back — sending an operator after a release
// that was never the problem.
func TestADeadAgentDoesNotPoisonTheVersion(t *testing.T) {
	p, rec, j := readyPlatform(), &recorder{}, NewJournal()
	p.runningErr = ErrAgentNotRunning
	m := goodManifest()

	for i := 0; i < 5; i++ { // more than MaxAttempts
		if _, err := Run(j, m, runCfg(), p, rec.save, jNow); err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if poisoned, why := j.IsPoisoned(m.Version); poisoned {
		t.Fatalf("%s was poisoned by an agent outage: %s", m.Version, why)
	}
	if len(j.PoisonedVersions()) != 0 {
		t.Fatalf("nothing may be poisoned by this path, got %v", j.PoisonedVersions())
	}
}

// The skip is only acceptable because it is reported. A refusal whose reason does not say what happened is
// how a device silently drops out of a rollout.
func TestTheRefusalSaysWhyTheDeviceCouldNotBeAssessed(t *testing.T) {
	p, rec, j := readyPlatform(), &recorder{}, NewJournal()
	p.runningErr = ErrAgentNotRunning
	out, _ := Run(j, goodManifest(), runCfg(), p, rec.save, jNow)
	for _, want := range []string{"cannot be established", "min_from_version"} {
		if !strings.Contains(out.Reason, want) {
			t.Errorf("the reason must name %q so the skip is diagnosable, got %q", want, out.Reason)
		}
	}
}

// A genuine fault reading the version is still a fault: it must NOT be quietly turned into "no agent".
// Collapsing the two would make a broken updater look like a dead agent on every box it ran on.
func TestAFaultReadingTheVersionIsStillAnError(t *testing.T) {
	p, rec, j := readyPlatform(), &recorder{}, NewJournal()
	p.runningErr = errors.New("registry access denied")
	if _, err := Run(j, goodManifest(), runCfg(), p, rec.save, jNow); err == nil {
		t.Fatal("an I/O fault must surface as an error, not as a refusal")
	}
}

// --- the plan's two facts ---------------------------------------------------------------------------------

// ★ FREEZE IS THE WITHDRAWAL MECHANISM. A release found bad after it shipped is stopped by this, not by
// un-publishing the manifest — a device that already holds one would never hear about the withdrawal, and on
// the Edge an absent manifest is indistinguishable from a misconfigured path.
func TestAFrozenPlanHoldsADeviceThatIsOtherwiseReadyToInstall(t *testing.T) {
	p, rec, j := readyPlatform(), &recorder{}, NewJournal()
	cfg := runCfg()
	cfg.Frozen = true

	out, err := Run(j, goodManifest(), cfg, p, rec.save, jNow)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if out.Action != ActionWaiting {
		t.Fatalf("action = %s (%s), want waiting", out.Action, out.Reason)
	}
	if len(p.calls) != 0 {
		t.Fatalf("a frozen fleet must have nothing done to it, got %v", p.calls)
	}
}

// The freeze must not be something a device can shrug off by reporting itself unfrozen: it is the operator's
// decision, not an observation.
func TestADeviceCannotUnfreezeItself(t *testing.T) {
	p, rec, j := readyPlatform(), &recorder{}, NewJournal()
	p.cond.Frozen = false
	cfg := runCfg()
	cfg.Frozen = true

	out, _ := Run(j, goodManifest(), cfg, p, rec.save, jNow)
	if out.Action != ActionWaiting {
		t.Fatalf("action = %s; the plan's freeze must outrank what the device says about itself", out.Action)
	}
}

// EligibleSince comes from the control plane because it is the only party that can compute it — the release
// time, the device's groups and the wave schedule are needed together. A device whose wave has not opened
// waits, and it waits for a REASON that names the wave rather than the window.
func TestAWaveThatHasNotOpenedHoldsTheDevice(t *testing.T) {
	p, rec, j := readyPlatform(), &recorder{}, NewJournal()
	cfg := runCfg()
	cfg.EligibleSince = jNow.Add(48 * time.Hour)

	out, err := Run(j, goodManifest(), cfg, p, rec.save, jNow)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if out.Action != ActionWaiting {
		t.Fatalf("action = %s (%s), want waiting", out.Action, out.Reason)
	}
	if !strings.Contains(out.Reason, "wave") {
		t.Fatalf("the reason must name the wave, or an operator looks at the maintenance window: %q", out.Reason)
	}
	if len(p.calls) != 0 {
		t.Fatalf("a device before its wave must have nothing done to it, got %v", p.calls)
	}
}

// ★ And the wave that HAS opened must not then be re-derived from the journal. The fallback exists for
// deployments with no plan, and if it overrode the plan a device would measure its deadline from the wrong
// instant — the one it happened to first hear about the release.
func TestTheControlPlanesWaveOutranksTheJournalFallback(t *testing.T) {
	p, rec := readyPlatform(), &recorder{}
	j := NewJournal()
	j.Begin(goodManifest().Version, "0.1.0", jNow.Add(-30*24*time.Hour)) // "eligible" for a month, per the journal
	cfg := runCfg()
	cfg.EligibleSince = jNow.Add(24 * time.Hour) // but the wave opens tomorrow

	out, _ := Run(j, goodManifest(), cfg, p, rec.save, jNow)
	if out.Action != ActionWaiting {
		t.Fatalf("action = %s (%s); the journal's older instant overrode the wave", out.Action, out.Reason)
	}
}

// ★ A DRY RUN MUST REACH THE LAUNCH AND STOP THERE — not branch around the sequencing, and not touch anything.
//
// The rehearsal used to skip STAGING (the download and the digest check) and still call through to here, so it
// exercised neither of the two things most likely to be wrong before a maintenance window, and an open window
// would have reached the launch with nothing staged. These pin the corrected contract: same path, one step
// short, nothing launched, nothing recorded, steering left up.
// ★ The distinction has to survive in the LOG, not just in the source. Comparing the two constants to each
// other is the assertion; comparing out.Action to a constant is not — if the two constants ever carry the same
// string, every test above still passes and a rehearsal reads in the journal exactly like an install that ran.
func TestARehearsalIsNotSpelledLikeAnInstall(t *testing.T) {
	if ActionWouldExecute == ActionExecuting {
		t.Fatalf("ActionWouldExecute and ActionExecuting are both %q — a log reader cannot tell a dry run from "+
			"an install that happened, which is the only reason the action exists", ActionWouldExecute)
	}
}

func TestDryRunStopsAtTheLaunchAndChangesNothing(t *testing.T) {
	p := readyPlatform()
	j := NewJournal()
	cfg := runCfg()
	cfg.DryRun = true

	out, err := Run(j, goodManifest(), cfg, p, func(*Journal) error { return nil }, jNow)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Action != ActionWouldExecute {
		t.Fatalf("action = %q (%s), want %q — a rehearsal that reached the launch must say so distinctly, so "+
			"that \"we tested it\" and \"it ran\" never read the same in a log", out.Action, out.Reason, ActionWouldExecute)
	}
	for _, c := range p.calls {
		if c == "execute" {
			t.Error("the installer was launched during a dry run")
		}
		if c == "disarm" {
			t.Error("steering was taken down during a dry run — a rehearsal must not drop the tunnel")
		}
	}
	if j.Phase == PhaseExecuting {
		t.Error("the journal entered `executing` during a dry run: a later pass would reconcile a rehearsal as " +
			"an interrupted install and demand this box's network be checked")
	}
}

// The same pass WITHOUT the flag must still run, or the test above passes for the wrong reason.
func TestWithoutDryRunTheInstallerIsLaunched(t *testing.T) {
	p := readyPlatform()
	out, err := Run(NewJournal(), goodManifest(), runCfg(), p, func(*Journal) error { return nil }, jNow)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	launched := false
	for _, c := range p.calls {
		if c == "execute" {
			launched = true
		}
	}
	if out.Action != ActionExecuting || !launched {
		t.Fatalf("action = %q (%s), launched = %v; want %q and true", out.Action, out.Reason, launched, ActionExecuting)
	}
}

// ★★ A REHEARSAL MUST NOT COUNT AS A FAILED ATTEMPT — three of them used to poison the release.
//
// Windows implemented --dry-run by wrapping the Platform so Disarm and Execute return errors. Structurally
// appealing: nothing downstream has to remember a flag. But Run treats a Disarm or Execute error as a failed
// attempt — it records the failure, counts it against MaxAttempts, and on the third marks the version
// POISONED, meaning the device will not attempt it again.
//
// So three rehearsals of a release made the device refuse that release permanently. And since the disarm is
// only reached once the gate is OPEN, it happened exactly when someone tested during the maintenance window —
// the case worth testing. The safest thing an operator can do was the thing that blocked the rollout.
//
// Both halves are asserted: the rehearsal leaves the journal clean, and a Platform that refuses really does
// poison — so this cannot pass by the mechanism simply having been removed.
func TestARehearsalDoesNotPoisonTheVersion(t *testing.T) {
	cfg := runCfg()
	cfg.DryRun = true
	// A fresh journal per pass, because that is what a real pass does: it LOADS the journal from disk. If the
	// rehearsal never saves, every pass starts from the same clean state — which is the property under test.
	saves := 0
	var j *Journal
	for i := 0; i < 5; i++ {
		j = NewJournal()
		out, err := Run(j, goodManifest(), cfg, readyPlatform(), func(*Journal) error { saves++; return nil }, jNow)
		if err != nil {
			t.Fatalf("pass %d: %v", i, err)
		}
		if out.Action != ActionWouldExecute {
			t.Fatalf("pass %d: action = %q (%s)", i, out.Action, out.Reason)
		}
	}
	if poisoned, why := j.IsPoisoned(goodManifest().Version); poisoned {
		t.Errorf("five rehearsals poisoned the version (%s) — testing an update must never be what stops it", why)
	}
	if len(j.Failures) != 0 {
		t.Errorf("a rehearsal recorded %d failure(s): %v", len(j.Failures), j.Failures)
	}
	// ★ And nothing was written at all. Without this the test passes on a rehearsal that leaves the journal in
	// `snapshotted`, so the NEXT pass reports `resumed` — a device that looks mid-update because someone tested.
	if saves != 0 {
		t.Errorf("a rehearsal wrote the journal %d time(s); it must persist nothing", saves)
	}
	if j.Phase == PhaseSnapshotted || j.Phase == PhaseExecuting {
		t.Errorf("a rehearsal left the journal in phase %q", j.Phase)
	}
}

// The other half: a Platform whose destructive methods refuse DOES poison, which is why the flag replaced it.
// If this ever stops being true the test above is passing for a reason that no longer exists.
func TestARefusingPlatformStillPoisons(t *testing.T) {
	j := NewJournal()
	for i := 0; i < 3; i++ {
		if _, err := Run(j, goodManifest(), runCfg(), &refusingPlatform{readyPlatform()},
			func(*Journal) error { return nil }, jNow); err != nil {
			t.Fatalf("pass %d: %v", i, err)
		}
	}
	if poisoned, _ := j.IsPoisoned(goodManifest().Version); !poisoned {
		t.Error("a Platform that refuses to disarm no longer poisons after MaxAttempts — if that changed " +
			"deliberately, the reasoning on Config.DryRun needs revisiting")
	}
}

type refusingPlatform struct{ *fakePlatform }

func (refusingPlatform) Disarm() error { return errRefused }

var errRefused = errors.New("dry run: not taking steering down")

// NOTE (2026-08-11): a test lived here asserting that a FAILING rehearsal does not write the caller's journal,
// using a capture error to produce the failure. It is gone because it became vacuous: capture failure no longer
// counts as an attempt (a device with no stored package is "cannot be assessed", not "this release is bad" —
// see the fix that followed the Windows measurement), so the rehearsal never reaches a path that records
// anything, and the test passed with a deliberately shallow clone. A test whose comment claims a guarantee it
// no longer provides is worse than no test.
//
// The property it was reaching for is covered directly and better by TestCloneDoesNotShareItsMaps, and the
// rehearsal side by TestARehearsalDoesNotPoisonTheVersion, which asserts the journal is never written at all.

// ★ TestMissingRestoreMaterialNeverPoisonsTheVersion pins the fix for a defect MEASURED on win-dev-1
// (2026-08-11), not one reasoned about.
//
// This branch used to call RecordFailure, so three ORDINARY passes on a device holding no installer package
// poisoned the version permanently. Nobody had to rehearse anything: the updater ticks every 30 minutes, so a
// freshly-imaged box was ninety minutes away from never being able to install that release. On the box, three
// real passes wrote `poisoned: {9.9.9: ...}` and then placing the missing package changed nothing at all.
//
// The rule was already written for the dead-agent case: poisoning means "this version fails HERE", and this is
// "this device is not ready to attempt ANY version yet". This one is the weaker of the two — a dead agent may
// never come back, while missing restore material is repaired by the next install that stores a package. The
// one condition guaranteed to fix itself was the only one being counted.
func TestMissingRestoreMaterialNeverPoisonsTheVersion(t *testing.T) {
	p, rec, j := readyPlatform(), &recorder{}, NewJournal()
	p.captureErr = errors.New("no installer package stored for 0.1.0")
	m := goodManifest()

	for i := 0; i < 5; i++ { // more than MaxAttempts, the count that used to poison at 3
		out, err := Run(j, m, runCfg(), p, rec.save, jNow)
		if err != nil {
			t.Fatalf("pass %d: %v", i, err)
		}
		if out.Action != ActionRefused {
			t.Fatalf("pass %d: action = %s, want refused", i, out.Action)
		}
	}
	if poisoned, why := j.IsPoisoned(m.Version); poisoned {
		t.Fatalf("a device with no rollback package poisoned %s: %s — it would refuse that release forever, "+
			"including after an install stored the package the refusal asked for", m.Version, why)
	}
	if got := j.Failures[m.Version]; got != 0 {
		t.Fatalf("failures = %d, want 0: a precondition that is not yet met is not an attempt at the version", got)
	}
	// And the device must not be left LOOKING like a broken update, which is where an operator gets sent.
	if j.Phase == PhaseFailed {
		t.Fatalf("phase = %s: a device that never attempted anything must not read as one whose update failed", j.Phase)
	}
}

// The recovery half, which is the part that made the old behaviour permanent rather than merely wrong: once
// the missing package exists, the very next pass must proceed. Measured on the box in the broken version, where
// it did not.
func TestTheDeviceRecoversAsSoonAsRestoreMaterialAppears(t *testing.T) {
	p, rec, j := readyPlatform(), &recorder{}, NewJournal()
	p.captureErr = errors.New("no installer package stored for 0.1.0")
	m := goodManifest()

	for i := 0; i < 5; i++ {
		if _, err := Run(j, m, runCfg(), p, rec.save, jNow); err != nil {
			t.Fatalf("pass %d: %v", i, err)
		}
	}
	p.captureErr = nil // an install has since stored a package — exactly what the refusal told the operator

	out, err := Run(j, m, runCfg(), p, rec.save, jNow)
	if err != nil {
		t.Fatalf("recovery pass: %v", err)
	}
	if out.Action != ActionExecuting {
		t.Fatalf("action = %s (%s), want executing: the precondition is met and nothing about the release ever "+
			"failed, so the device must proceed", out.Action, out.Reason)
	}
}

// ★ The counting that MUST survive: a version whose installer keeps failing is exactly what poisoning is for,
// and this test is here so the fix above cannot be mistaken for "stop counting failures".
func TestAFailingInstallerStillPoisonsTheVersion(t *testing.T) {
	p, rec, j := readyPlatform(), &recorder{}, NewJournal()
	p.execErr = errors.New("msiexec returned 1603")
	m := goodManifest()

	for i := 0; i < 5; i++ {
		if _, err := Run(j, m, runCfg(), p, rec.save, jNow); err != nil {
			t.Fatalf("pass %d: %v", i, err)
		}
		j.Enter(PhaseIdle, jNow) // clear the interrupted state so the NEXT pass is a fresh attempt
	}
	if poisoned, _ := j.IsPoisoned(m.Version); !poisoned {
		t.Fatalf("an installer that fails every time did not poison %s — poisoning has stopped doing the one "+
			"thing it exists for", m.Version)
	}
}

// ★ TestCloneDoesNotShareItsMaps pins the deep copy DIRECTLY, on the data structure, because pinning it
// through Run stopped working.
//
// The property matters for one reason: Run replaces the caller's journal with a clone for a rehearsal, so if
// the clone shared a map, anything the rehearsal recorded would be written through into the caller's journal —
// a rehearsal quietly poisoning a release, which is the whole class this file keeps fighting.
//
// It was asserted through a FAILING rehearsal until the fix that stopped rehearsals from being able to fail in
// a counted way (capture no longer counts; disarm and execute are never reached under DryRun). That left the
// old test passing whatever clone() did — a mutation removing the map copy went straight through it, which is
// how this was found. Asserting the property where it lives cannot be undone by a change somewhere else.
func TestCloneDoesNotShareItsMaps(t *testing.T) {
	j := NewJournal()
	j.TargetVersion = "9.9.9"
	j.Failures = map[string]int{"9.9.9": 1}
	j.Poisoned = map[string]string{"8.8.8": "an earlier release"}

	c := j.clone()
	c.Failures["9.9.9"] = 99
	c.Failures["7.7.7"] = 1
	c.Poisoned["9.9.9"] = "written on the clone"
	delete(c.Poisoned, "8.8.8")

	if got := j.Failures["9.9.9"]; got != 1 {
		t.Errorf("failures written on the clone reached the original (%d, want 1): a rehearsal would count "+
			"against the caller's version", got)
	}
	if _, added := j.Failures["7.7.7"]; added {
		t.Error("a key added to the clone appeared in the original's failure map")
	}
	if _, added := j.Poisoned["9.9.9"]; added {
		t.Error("a version poisoned on the clone was poisoned on the original — a rehearsal blocking a release")
	}
	if _, kept := j.Poisoned["8.8.8"]; !kept {
		t.Error("a delete on the clone removed an entry from the original's poison list")
	}
}

// ★★ A SUCCESSFUL UPDATE WAS BEING RECORDED AS FAILED, with a false network alarm attached.
//
// Measured on the live Mac after 0.2.0 → 0.2.1 landed. Execute hands the package over detached; the installer
// restarts the updater daemon, whose first pass runs immediately by design; ten seconds later the extension
// had not yet rewritten runtime_version.json, so Reconcile left the attempt open and this branch declared it
// interrupted, wrote PhaseFailed, and — NeedsNetworkRecovery being true for PhaseExecuting — told the operator
// to check the network of a machine that was working perfectly. The journal then kept `failed` forever,
// because nothing revisits a finished target.
func TestAnAttemptTooYoungToJudgeIsNotCalledInterrupted(t *testing.T) {
	j := NewJournal()
	j.Begin("0.2.1", "0.2.0", jNow)
	j.Enter(PhaseExecuting, jNow)

	saves := 0
	out, err := Run(j, goodManifest(), runCfg(), readyPlatform(),
		func(*Journal) error { saves++; return nil }, jNow.Add(10*time.Second))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Action != ActionInProgress {
		t.Fatalf("action = %q (%s), want %q — an installer handed over ten seconds ago has not failed",
			out.Action, out.Reason, ActionInProgress)
	}
	if j.Phase == PhaseFailed {
		t.Error("a successful update in progress was written as `failed`; nothing revisits a finished target, " +
			"so that record is permanent")
	}
	if saves != 0 {
		t.Errorf("the ordinary middle of an install wrote the journal %d time(s)", saves)
	}
}

// And the opposite must still hold: an attempt that really did stop is still called interrupted, still says
// the network needs checking, and still records it. Without this the fix above is indistinguishable from
// deleting the branch.
func TestAnOldInterruptedAttemptIsStillReported(t *testing.T) {
	j := NewJournal()
	j.Begin("0.2.1", "0.2.0", jNow)
	j.Enter(PhaseExecuting, jNow)

	out, err := Run(j, goodManifest(), runCfg(), readyPlatform(),
		func(*Journal) error { return nil }, jNow.Add(InstallGrace+time.Minute))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Action != ActionResumed {
		t.Fatalf("action = %q (%s), want %q", out.Action, out.Reason, ActionResumed)
	}
	if !strings.Contains(out.Reason, "NETWORK") {
		t.Errorf("an attempt interrupted in `executing` must still say the network needs checking: %s", out.Reason)
	}
	if j.Phase != PhaseFailed {
		t.Errorf("phase = %q, want %q", j.Phase, PhaseFailed)
	}
}

// A journal that cannot say when its install began gets no benefit of the doubt: the grace is measured, and
// an unmeasurable one is not a grace.
//
// ★ BOTH anchors are cleared, and that is the point of the update on 2026-08-14. The grace used to be measured
// from attempt_started_at alone, so clearing that one expressed "unmeasurable". It no longer does: an install
// stamps InFlightSince when it takes the machine, which is a BETTER answer to "could the installer still be
// running" than the attempt time ever was. The invariant is unchanged — no usable anchor, no grace — while
// what counts as an anchor has moved to the thing actually being timed.
func TestAnAttemptWithNoStartTimeGetsNoGrace(t *testing.T) {
	j := NewJournal()
	j.Begin("0.2.1", "0.2.0", jNow)
	j.Enter(PhaseExecuting, jNow)
	j.AttemptStartedAt, j.InFlightSince = "", ""

	out, err := Run(j, goodManifest(), runCfg(), readyPlatform(), func(*Journal) error { return nil },
		jNow.Add(10*time.Second))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Action != ActionResumed {
		t.Fatalf("action = %q, want %q", out.Action, ActionResumed)
	}
}

// And the install stamp is sufficient ON ITS OWN. A journal that knows when the machine was taken can answer
// "could the installer still be running" without the attempt time, which is the case the fix exists for: the
// attempt time is old precisely because the device waited before installing.
func TestAnInstallStampAloneEarnsTheGrace(t *testing.T) {
	j := NewJournal()
	j.Begin("0.2.1", "0.2.0", jNow)
	j.Enter(PhaseExecuting, jNow)
	j.AttemptStartedAt = ""

	out, err := Run(j, goodManifest(), runCfg(), readyPlatform(), func(*Journal) error { return nil },
		jNow.Add(10*time.Second))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Action != ActionInProgress {
		t.Fatalf("action = %q, want %q — the install began ten seconds ago and the journal says so",
			out.Action, ActionInProgress)
	}
}

// ★ The same interrupted phase means different things on the two platforms, so it must not produce the same
// instruction. The network sentence is for the Windows black hole — a kernel redirect that outlives the agent.
// On macOS nothing survives a stopped provider, and sending an operator to check a network that was never
// touched teaches them to skip the sentence on the platform where it is true.
func TestTheNetworkWarningIsOnlyForPlatformsWhoseSteeringOutlivesTheAgent(t *testing.T) {
	newJournal := func() *Journal {
		j := NewJournal()
		j.Begin("0.2.0", "0.1.0", jNow)
		j.Enter(PhaseExecuting, jNow)
		return j
	}
	late := jNow.Add(InstallGrace + time.Minute)

	win := runCfg()
	win.SteeringSurvivesAgent = true
	out, _ := Run(newJournal(), goodManifest(), win, readyPlatform(), func(*Journal) error { return nil }, late)
	if !strings.Contains(out.Reason, "NETWORK must be checked") {
		t.Fatalf("Windows must still be told to check the network: %q", out.Reason)
	}

	mac := runCfg()
	mac.SteeringSurvivesAgent = false
	out, _ = Run(newJournal(), goodManifest(), mac, readyPlatform(), func(*Journal) error { return nil }, late)
	if strings.Contains(out.Reason, "NETWORK must be checked") {
		t.Fatalf("macOS must NOT be sent to check a network nothing touched: %q", out.Reason)
	}
	if !strings.Contains(out.Reason, "RUNNING version") {
		t.Errorf("it must say what to establish instead, got %q", out.Reason)
	}
}

// An interrupted ROLLBACK must not be reported as an interrupted update: the operator reading it is in the
// middle of the incident that caused the rollback.
func TestAnInterruptedRollbackSaysItWasARollback(t *testing.T) {
	j := NewJournal()
	j.BeginRollback("0.2.2", "0.2.3", jNow)
	j.Enter(PhaseRollingBack, jNow)

	out, _ := Run(j, goodManifest(), runCfg(), readyPlatform(), func(*Journal) error { return nil },
		jNow.Add(InstallGrace+time.Minute))
	if out.Action != ActionResumed {
		t.Fatalf("action = %s, want resumed", out.Action)
	}
	if !strings.Contains(out.Reason, "a rollback to 0.2.2") {
		t.Errorf("the report must name it as a rollback, got %q", out.Reason)
	}
}

// ★ DISARMING IS NOT FREE. Steering comes down before the installer on a fail-open endpoint, which is right —
// the alternative is the black hole. But when the launch itself fails, nothing else in the system is going to
// put the control back: the installer never ran, so no new agent starts and re-applies. The device would sit
// on its native network, and the report would say "update failed" while the true state is "unprotected".
func TestAFailedLaunchPutsSteeringBack(t *testing.T) {
	p := readyPlatform() // disarmWant: true
	p.execErr = errors.New("msiexec is not on PATH")

	out, err := Run(NewJournal(), goodManifest(), runCfg(), p, func(*Journal) error { return nil }, jNow)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if out.Action != ActionRefused {
		t.Fatalf("action = %s, want refused", out.Action)
	}
	if got := strings.Join(p.calls, ","); !strings.Contains(got, "disarm,execute,rearm") {
		t.Fatalf("call order = %q — the control must be put back after a launch that never happened", got)
	}
	if !strings.Contains(out.Reason, "has been put back") {
		t.Errorf("the operator must be told the control was restored, got %q", out.Reason)
	}
}

// ★ And the case that must be impossible to miss: it could NOT be put back. That device is unprotected and no
// later tick fixes it by itself, so this is the one sentence in the whole path that has to shout.
func TestASteeringRestorationThatFailsIsReportedAsAnEmergency(t *testing.T) {
	p := readyPlatform()
	p.execErr = errors.New("the staged package no longer verifies")
	p.rearmErr = errors.New("the driver does not report an armed redirect")

	j := NewJournal()
	out, _ := Run(j, goodManifest(), runCfg(), p, func(*Journal) error { return nil }, jNow)
	if !strings.Contains(out.Reason, "STEERING WAS TAKEN DOWN") || !strings.Contains(out.Reason, "control OFF") {
		t.Fatalf("an unprotected endpoint must be named as one, got %q", out.Reason)
	}
	// ★ And it outlives the process: the journal is what a later reader has. This assertion is the reason
	// LastFailureReason exists — the account used to be discarded until the THIRD failure, because only the
	// poison ceiling wrote a reason down, and the first failure is the one that leaves a box unprotected.
	if !strings.Contains(j.LastFailureReason, "could NOT be restored") {
		t.Errorf("the journal must carry why this device is unprotected, got %q", j.LastFailureReason)
	}
}

// A platform that never disarms must not be told its steering was restored.
func TestAPlatformThatNeverDisarmsIsNotToldItsSteeringWasPutBack(t *testing.T) {
	p := readyPlatform()
	p.disarmWant = false
	p.execErr = errors.New("installer missing")

	out, _ := Run(NewJournal(), goodManifest(), runCfg(), p, func(*Journal) error { return nil }, jNow)
	if strings.Contains(strings.Join(p.calls, ","), "rearm") {
		t.Fatal("nothing may be restored on a platform that never took it down")
	}
	if !strings.Contains(out.Reason, "never taken down") {
		t.Errorf("the report must say the protection did not change, got %q", out.Reason)
	}
}

// ★ THE FIX THAT WAS NOT A FIX (2026-08-11, from the second review). Withholding a wave by clearing
// EligibleSince changed nothing: Run replaces a zero wave start with the attempt's own start time — by design,
// so a device with no schedule is not stuck forever — and the install proceeded at the next maintenance
// window. The plan's inability to authorise this release was a log line.
//
// This asserts the only thing that matters: the installer is NOT called.
func TestAPlanThatCannotAuthoriseActuallyStopsTheInstall(t *testing.T) {
	p := readyPlatform()
	cfg := runCfg()
	cfg.PlanHold = "this plan's wave was computed for 0.2.0 and this device is being offered 0.3.0"
	cfg.EligibleSince = time.Time{} // exactly as the withholding path leaves it

	j := NewJournal()
	out, err := Run(j, goodManifest(), cfg, p, func(*Journal) error { return nil }, jNow)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if out.Action != ActionWaiting {
		t.Fatalf("action = %s (%s), want waiting", out.Action, out.Reason)
	}
	if strings.Contains(strings.Join(p.calls, ","), "execute") {
		t.Fatal("★ the installer ran on a device whose plan could not authorise the release")
	}
	if j.LastWaitReason != WaitPlanHold {
		t.Errorf("wait reason = %q, want %q", j.LastWaitReason, WaitPlanHold)
	}
	if !strings.Contains(out.Reason, "0.3.0") {
		t.Errorf("the operator must be told which release could not be authorised, got %q", out.Reason)
	}
}

// ★ A JOURNAL WRITE THAT FAILS MUST NOT LEAVE A DEVICE UNPROTECTED (second review). Between the disarm and
// the launch there is a save; when it failed, the old code returned an error with the control off and nothing
// intending to restore it. A device would be unprotected because a FILE could not be written.
func TestAJournalFailureAfterDisarmStillRestoresSteering(t *testing.T) {
	p := readyPlatform() // disarms
	writes := 0
	save := func(*Journal) error {
		writes++
		if writes >= 4 { // begin, snapshotted, disarmed, then the executing write fails
			return errors.New("read-only filesystem")
		}
		return nil
	}

	_, err := Run(NewJournal(), goodManifest(), runCfg(), p, save, jNow)
	if err == nil {
		t.Fatal("a journal that cannot be written must abort the update")
	}
	got := strings.Join(p.calls, ",")
	if !strings.Contains(got, "disarm") {
		t.Fatalf("the test did not reach the disarm: %q", got)
	}
	if !strings.Contains(got, "rearm") {
		t.Fatalf("★ steering stayed down after a failed journal write: %q", got)
	}
	if strings.Contains(got, "execute") {
		t.Fatal("nothing may be launched once the record could not be kept")
	}
}

// ★ AN UNPROTECTED ENDPOINT MUST NOT BE REPORTED AS A DISK PROBLEM (third review). When the journal write
// failed AND the restoration then failed too, the caller was told "the journal could not be written" — which
// sends somebody to look at a filesystem while the machine sits on its native network with the control off.
func TestAFailedRearmReachesTheCallerNotJustTheJournal(t *testing.T) {
	p := readyPlatform()
	p.rearmErr = errors.New("the driver does not report an armed redirect")
	writes := 0
	save := func(*Journal) error {
		writes++
		if writes >= 4 { // begin, snapshotted, disarmed, then the executing write fails
			return errors.New("read-only filesystem")
		}
		return nil
	}

	out, err := Run(NewJournal(), goodManifest(), runCfg(), p, save, jNow)
	if err == nil {
		t.Fatal("this must be an error")
	}
	if !strings.Contains(err.Error(), "COULD NOT BE RESTORED") {
		t.Fatalf("★ the error names only the lesser problem: %v", err)
	}
	if !strings.Contains(err.Error(), "could not be recorded either") {
		t.Errorf("the failed journal write is part of the state and must survive too: %v", err)
	}
	if out.Action != ActionRefused || !strings.Contains(out.Reason, "control OFF") {
		t.Errorf("the outcome must say it as well: %s / %s", out.Action, out.Reason)
	}
}

// ★★ THE GRACE IS MEASURED FROM THE INSTALL, NOT FROM THE ATTEMPT (2026-08-14, measured on win-dev-1).
//
// An attempt is recorded as soon as it is applicable and may then WAIT — for a window, a wave, or a blocker to
// clear — and Begin is deliberately skipped for a continuing attempt so the deadline clock keeps running. On
// that box the attempt was recorded at 09:17 and refused (nothing to roll back to); the blocker was fixed and
// the SAME attempt executed at 09:53. Anchored to attempt_started_at, the ten-minute grace had been spent
// thirty-six minutes before the installer was handed anything: the update succeeded, the returning updater
// found `executing`, wrote PhaseFailed, and told the operator to check the network of a healthy box.
func TestTheInstallGraceStartsWhenTheMachineIsTouchedNotWhenTheAttemptWasRecorded(t *testing.T) {
	p, j := readyPlatform(), NewJournal()
	// Recorded long ago, and waiting ever since.
	j.Begin("0.2.0", "0.1.0", jNow)
	// The installer is handed over now, thirty-six minutes later.
	handover := jNow.Add(36 * time.Minute)
	j.Enter(PhaseExecuting, handover)

	// The updater is replaced by its own install and comes back seconds later, before the agent has restarted.
	out, err := Run(j, goodManifest(), runCfg(), p, (&recorder{}).save, handover.Add(10*time.Second))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if out.Action != ActionInProgress {
		t.Fatalf("action = %s (%s), want in_progress — the installer was handed over ten seconds ago",
			out.Action, out.Reason)
	}
	if j.Phase != PhaseExecuting {
		t.Fatalf("phase = %q, want executing left untouched: writing a failure here is what put `failed` on a "+
			"successful update", j.Phase)
	}
	if strings.Contains(out.Reason, "NETWORK must be checked") {
		t.Errorf("a box mid-install must not be reported as needing its network checked: %q", out.Reason)
	}
}

// And the grace still ends. An install that really did die must be called interrupted, measured from the
// handover — otherwise the fix above would simply move the blind spot.
func TestAnInstallThatDiedIsStillCalledInterrupted(t *testing.T) {
	p, j := readyPlatform(), NewJournal()
	j.Begin("0.2.0", "0.1.0", jNow)
	handover := jNow.Add(36 * time.Minute)
	j.Enter(PhaseExecuting, handover)

	out, err := Run(j, goodManifest(), runCfg(), p, (&recorder{}).save, handover.Add(InstallGrace+time.Minute))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if out.Action != ActionResumed {
		t.Fatalf("action = %s, want resumed once the grace from the handover has passed", out.Action)
	}
	if !strings.Contains(out.Reason, "NETWORK must be checked") {
		t.Errorf("a genuinely interrupted execute must still flag the network, got %q", out.Reason)
	}
}

// A journal written before InFlightSince existed keeps the old anchor rather than losing the grace entirely.
// Denying it would turn every install in flight at the moment of rollout into a false interruption.
func TestAJournalWithoutAnInFlightStampFallsBackToTheAttemptTime(t *testing.T) {
	p, j := readyPlatform(), NewJournal()
	j.Begin("0.2.0", "0.1.0", jNow)
	j.Phase = PhaseExecuting // set directly: no Enter, so nothing stamps InFlightSince
	j.InFlightSince = ""

	out, err := Run(j, goodManifest(), runCfg(), p, (&recorder{}).save, jNow.Add(time.Minute))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if out.Action != ActionInProgress {
		t.Fatalf("action = %s, want in_progress from the attempt time when no install stamp exists", out.Action)
	}
}

// ★ FromVersion must describe the device the installer is actually replacing. It is what the fleet is told the
// update came from, and it is how the restore material is keyed — on win-dev-1 the journal said 0.1.9 while the
// package captured to roll back to was 0.1.10, so the record and the bytes disagreed about where a rollback
// would land.
func TestAContinuingAttemptRefreshesTheVersionItIsUpgradingFrom(t *testing.T) {
	p, j := readyPlatform(), NewJournal()
	j.Begin("0.2.0", "0.1.0", jNow)
	j.Phase = PhaseVerified
	// The operator installed a newer build by hand while this attempt sat waiting.
	p.running = "0.1.5"

	if _, err := Run(j, goodManifest(), runCfg(), p, (&recorder{}).save, jNow.Add(time.Hour)); err != nil {
		t.Fatalf("run: %v", err)
	}
	if j.FromVersion != "0.1.5" {
		t.Fatalf("from_version = %q, want 0.1.5 — the attempt is replacing what is running now, not what was "+
			"running when it was first recorded", j.FromVersion)
	}
	// The attempt itself has NOT restarted: the deadline clock it has already earned must survive.
	if got := j.AttemptStartedAt; got != jNow.UTC().Format(time.RFC3339) {
		t.Fatalf("attempt_started_at = %q, want it left at the original %q — refreshing the version must not "+
			"reset the eligibility this attempt has earned", got, jNow.UTC().Format(time.RFC3339))
	}
}
