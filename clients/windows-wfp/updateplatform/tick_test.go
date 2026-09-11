package updateplatform

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentupdate"
)

// --- fakes ------------------------------------------------------------------------------------------------

type fakePlatform struct {
	running     string
	runningErr  error
	conds       agentupdate.DeviceConditions
	material    []string
	materialErr error
	disarmFirst bool
	disarmErr   error
	rearmErr    error
	executed    []string
	execErr     error
}

func (f *fakePlatform) RunningVersion() (string, error) { return f.running, f.runningErr }
func (f *fakePlatform) Conditions(now time.Time) agentupdate.DeviceConditions {
	c := f.conds
	c.LocalNow = now
	return c
}
func (f *fakePlatform) CaptureRestoreMaterial(m agentupdate.Manifest) ([]string, error) {
	if f.materialErr != nil {
		return nil, f.materialErr
	}
	if f.material == nil {
		return []string{"rollback.msi"}, nil
	}
	return f.material, nil
}

// The rollback half of the interface. This file tests the tick, which never rolls back — but the interface is
// deliberately not optional (a platform that cannot roll back must fail to compile, not be discovered during
// an incident), so the fake answers honestly rather than pretending.
func (f *fakePlatform) RestoreMaterialFor(version string) (string, error) {
	if f.materialErr != nil {
		return "", f.materialErr
	}
	return "rollback-" + version + ".msi", nil
}
func (f *fakePlatform) ExecuteRollback(pkg, toVersion string) error {
	f.executed = append(f.executed, "rollback:"+toVersion)
	return f.execErr
}
func (f *fakePlatform) Rearm() error             { f.executed = append(f.executed, "rearm"); return f.rearmErr }
func (f *fakePlatform) DisarmBeforeUpdate() bool { return f.disarmFirst }
func (f *fakePlatform) Disarm() error            { return f.disarmErr }
func (f *fakePlatform) Execute(m agentupdate.Manifest) error {
	if f.execErr != nil {
		return f.execErr
	}
	f.executed = append(f.executed, m.Version)
	return nil
}

type fakeSource struct {
	m   agentupdate.Manifest
	err error
}

func (s fakeSource) Fetch(ctx context.Context, now time.Time) (agentupdate.Manifest, error) {
	return s.m, s.err
}

// --- Tick -------------------------------------------------------------------------------------------------

func tickManifest(t *testing.T, body []byte, url string) agentupdate.Manifest {
	t.Helper()
	sum := sha256.Sum256(body)
	return agentupdate.Manifest{
		Schema:         agentupdate.SchemaVersion,
		Version:        "0.2.0",
		Platform:       agentupdate.PlatformWindows,
		Arch:           agentupdate.ArchAMD64,
		Channel:        "stable",
		Delivery:       agentupdate.DeliveryDSSE,
		ArtifactKind:   agentupdate.ArtifactKindMSI,
		ArtifactURL:    url,
		ArtifactSHA256: hex.EncodeToString(sum[:]),
		ArtifactSize:   int64(len(body)),
		ReleasedAt:     time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
		NotAfter:       time.Now().UTC().Add(720 * time.Hour).Format(time.RFC3339),
	}
}

// TestTickReconcilesBeforeRunSeesTheJournal is the ordering assertion. Without it a successful update is
// reported on the next pass as an interrupted attempt that needs its network checked.
func TestTickReconcilesBeforeRunSeesTheJournal(t *testing.T) {
	stagedInto(t)
	now := time.Now().UTC()
	body := []byte("installer payload")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(body) }))
	defer srv.Close()

	// The state a box is in immediately after a successful install: journal mid-flight at 0.2.0, and the agent
	// is now running 0.2.0.
	j := agentupdate.NewJournal()
	j.Begin("0.2.0", "0.1.0", now.Add(-time.Hour))
	j.Enter(agentupdate.PhaseExecuting, now.Add(-time.Hour))

	var saved *agentupdate.Journal
	res, err := Tick(context.Background(), TickDeps{
		Source:      fakeSource{m: tickManifest(t, body, srv.URL)},
		Platform:    &fakePlatform{running: "0.2.0"},
		Config:      agentupdate.Config{Platform: agentupdate.PlatformWindows, Arch: agentupdate.ArchAMD64, MaxAttempts: 3},
		JournalPath: filepath.Join(t.TempDir(), "journal.json"),
		HTTP:        srv.Client(),
		Load:        func(string) (*agentupdate.Journal, error) { return j, nil },
		Save:        func(jj *agentupdate.Journal, _ string) error { saved = jj; return nil },
	}, now)
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if !res.Reconciled {
		t.Fatalf("Tick did not close the completed attempt (notes=%v)", res.Notes)
	}
	if saved == nil {
		t.Fatal("the closed attempt was never persisted")
	}
	if res.Outcome.Action == agentupdate.ActionResumed {
		t.Fatalf("a successful update was reported as an interrupted attempt: %s", res.Outcome.Reason)
	}
	if strings.Contains(res.Outcome.Reason, "NETWORK") {
		t.Fatalf("the happy path emitted a network-recovery warning: %s", res.Outcome.Reason)
	}
}

// TestTickIsQuietWithNoManifest: most ticks on most devices produce this, and it must not read as a failure.
func TestTickIsQuietWithNoManifest(t *testing.T) {
	stagedInto(t)
	res, err := Tick(context.Background(), TickDeps{
		Source:      fakeSource{err: ErrNoManifest},
		Platform:    &fakePlatform{running: "0.1.0"},
		Config:      agentupdate.Config{Platform: agentupdate.PlatformWindows, Arch: agentupdate.ArchAMD64},
		JournalPath: filepath.Join(t.TempDir(), "journal.json"),
		Load:        func(string) (*agentupdate.Journal, error) { return agentupdate.NewJournal(), nil },
		Save:        func(*agentupdate.Journal, string) error { return nil },
	}, time.Now().UTC())
	if err != nil {
		t.Fatalf("a device with nothing to do returned an error: %v", err)
	}
	if res.Outcome.Action != agentupdate.ActionNone {
		t.Fatalf("Action = %q, want %q", res.Outcome.Action, agentupdate.ActionNone)
	}
}

// TestTickStillEvaluatesWhenStagingFails: reporting "could not stage" while silently skipping Run would hide
// a poisoned version, or a device that has been waiting a month. Execute refuses on its own if the package is
// absent, so there is nothing to protect by stopping early.
func TestAFailedDownloadDoesNotUnsteerTheDevice(t *testing.T) {
	stagedInto(t)
	now := time.Now().UTC()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()

	calls := &recordingPlatform{fakePlatform: fakePlatform{running: "0.1.0"}, disarms: true}
	res, err := Tick(context.Background(), TickDeps{
		Source:   fakeSource{m: tickManifest(t, []byte("payload"), srv.URL)},
		Platform: calls,
		// ★ A REAL window. The first version of this test left Window zero, so the gate refused before Run
		// reached capture and the disarm below never happened — the test passed and the defect was invisible.
		Config: agentupdate.Config{
			Platform: agentupdate.PlatformWindows, Arch: agentupdate.ArchAMD64, MaxAttempts: 3,
			Window: agentupdate.MaintenanceWindow{LocalStart: "00:00", LocalEnd: "00:00"},
		},
		JournalPath: filepath.Join(t.TempDir(), "journal.json"),
		HTTP:        srv.Client(),
		Load:        func(string) (*agentupdate.Journal, error) { return agentupdate.NewJournal(), nil },
		Save:        func(*agentupdate.Journal, string) error { return nil },
	}, now)
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	// The measured behaviour before this fix was [capture DISARM execute]: a device whose download failed had
	// its steering taken down, because Run only discovers the package is missing after it has disarmed.
	for _, c := range calls.seen {
		if c == "disarm" {
			t.Fatalf("a failed download took steering down; platform calls were %v", calls.seen)
		}
	}
	if len(calls.seen) != 0 {
		t.Fatalf("nothing may be done to a device that has no package to install, got %v", calls.seen)
	}
	// And the reporting the original intent wanted is still there.
	if len(res.Notes) == 0 || res.Outcome.Action == "" {
		t.Fatalf("a staging failure must still be reported: action=%q notes=%v", res.Outcome.Action, res.Notes)
	}
	if !strings.Contains(res.Outcome.Reason, "Steering is deliberately") {
		t.Fatalf("the reason must say why nothing was attempted, got %q", res.Outcome.Reason)
	}
}

// The facts the first version called Run to surface are surfaced directly instead: a version this device has
// already given up on must not look like a device that merely could not download.
func TestAStagingFailureStillReportsAPoisonedVersion(t *testing.T) {
	stagedInto(t)
	now := time.Now().UTC()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()

	m := tickManifest(t, []byte("payload"), srv.URL)
	j := agentupdate.NewJournal()
	j.Begin(m.Version, "0.1.0", now.Add(-72*time.Hour))
	for i := 0; i < 3; i++ {
		j.RecordFailure("disarm failed", 3, now.Add(-48*time.Hour))
	}

	res, err := Tick(context.Background(), TickDeps{
		Source:      fakeSource{m: m},
		Platform:    &recordingPlatform{fakePlatform: fakePlatform{running: "0.1.0"}},
		Config:      agentupdate.Config{Platform: agentupdate.PlatformWindows, Arch: agentupdate.ArchAMD64, MaxAttempts: 3},
		JournalPath: filepath.Join(t.TempDir(), "journal.json"),
		HTTP:        srv.Client(),
		Load:        func(string) (*agentupdate.Journal, error) { return j, nil },
		Save:        func(*agentupdate.Journal, string) error { return nil },
	}, now)
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if !strings.Contains(res.Outcome.Reason, "poisoned") {
		t.Fatalf("a poisoned version must not be hidden behind a download failure, got %q", res.Outcome.Reason)
	}
}

// TestTickDoesNotInstallAnMDMManifest: DSSE executes nothing under MDM delivery, and a tick that fetched and
// ran one would be a second, unmanaged path to a privileged install.
func TestTickDoesNotInstallAnMDMManifest(t *testing.T) {
	stagedInto(t)
	m := tickManifest(t, []byte("payload"), "https://example.invalid/agent.msi")
	m.Delivery = agentupdate.DeliveryMDM
	fp := &fakePlatform{running: "0.1.0"}

	res, err := Tick(context.Background(), TickDeps{
		Source:      fakeSource{m: m},
		Platform:    fp,
		Config:      agentupdate.Config{Platform: agentupdate.PlatformWindows, Arch: agentupdate.ArchAMD64},
		JournalPath: filepath.Join(t.TempDir(), "journal.json"),
		Load:        func(string) (*agentupdate.Journal, error) { return agentupdate.NewJournal(), nil },
		Save:        func(*agentupdate.Journal, string) error { return nil },
	}, time.Now().UTC())
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if len(fp.executed) != 0 {
		t.Fatalf("DSSE launched an installer for an MDM-delivered manifest: %v", fp.executed)
	}
	if res.Outcome.Action != agentupdate.ActionNone {
		t.Fatalf("Action = %q, want %q", res.Outcome.Action, agentupdate.ActionNone)
	}
}

// recordingPlatform records which destructive methods were reached, which is the property the staging tests
// are about: "what did this device have done to it", not "what did the function return".
type recordingPlatform struct {
	fakePlatform
	disarms bool
	seen    []string
}

func (p *recordingPlatform) CaptureRestoreMaterial(m agentupdate.Manifest) ([]string, error) {
	p.seen = append(p.seen, "capture")
	return p.fakePlatform.CaptureRestoreMaterial(m)
}
func (p *recordingPlatform) DisarmBeforeUpdate() bool { return p.disarms }
func (p *recordingPlatform) Disarm() error {
	p.seen = append(p.seen, "disarm")
	return p.fakePlatform.Disarm()
}
func (p *recordingPlatform) Execute(m agentupdate.Manifest) error {
	p.seen = append(p.seen, "execute")
	return p.fakePlatform.Execute(m)
}

// ★ A frozen fleet must not keep downloading the release it has been told not to install. Both reasons for
// staging early — the window, and the rehearsal — assume a window that will open, and a freeze is exactly the
// statement that none will.
func TestAFrozenFleetDoesNotStage(t *testing.T) {
	dir := t.TempDir()
	served := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served++
		http.Error(w, "the fleet is frozen; nothing should have asked for this", http.StatusTeapot)
	}))
	defer srv.Close()

	res, err := Tick(context.Background(), TickDeps{
		Source:   fakeSource{m: tickManifest(t, []byte("payload"), srv.URL)},
		Platform: &fakePlatform{running: "0.1.0"},
		Config: agentupdate.Config{Platform: agentupdate.PlatformWindows, Arch: agentupdate.ArchAMD64,
			MaxAttempts: 3, Frozen: true},
		JournalPath: filepath.Join(dir, "journal.json"),
		HTTP:        srv.Client(),
	}, time.Now())
	if err != nil {
		t.Fatalf("tick: %v", err)
	}
	if served != 0 {
		t.Fatalf("the artifact was fetched %d time(s) while the fleet was frozen", served)
	}
	if res.Outcome.Action != agentupdate.ActionWaiting {
		t.Fatalf("action = %s (%s), want waiting — the hold must still be recorded", res.Outcome.Action, res.Outcome.Reason)
	}
}

// ★ A REHEARSAL MUST NOT RAISE THE PLAN RATCHET (win-dev-1, 2026-08-12). A `--once --dry-run` accepted a plan
// floor and PERSISTED it; the next pass was handed a legitimate, slightly older plan, refused it as a replay,
// and the device went to "waiting: rollout is frozen". The floor is one-way by design, so nothing undoes it —
// the operator who reached for the mode that touches nothing is the one who halted the machine.
//
// Config.DryRun's own comment already said it "changes nothing that outlives the pass". This is that promise.
// ★ A REHEARSAL ON A BOX THAT ALREADY OWES AN OUTCOME. Since the twelfth review the owed outcome is derived
// from the journal — OwesOutcomeReport asks the FILE rather than comparing snapshots taken this pass — so the
// question is already true at the START of a pass on any box that crashed between a terminal save and its
// report. That box is not hypothetical: it is what an interrupted update leaves, and it is exactly the state
// an operator reaches for `--dry-run` to inspect.
//
// Written because the two places that answer that question are guarded differently — the first with an
// explicit `&& !dry`, the second relying on the wrapped save — and an asymmetry there looked like a hole. It
// is not one: the save wrapper catches both. This pins the OUTCOME rather than the mechanism, so it keeps
// holding if the guards are rearranged again, and it reaches a path TestADryRunLeavesNothingBehind does not —
// a pass that goes all the way through Run to would_execute while the journal owes an outcome.
func TestADryRunOnABoxThatOwesAnOutcomeWritesNothing(t *testing.T) {
	stagedInto(t)
	now := time.Now().UTC()
	body := []byte("installer payload")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(body) }))
	defer srv.Close()

	// A journal left terminal by an earlier pass, whose outcome never reached the outbox: phase failed, a
	// failure counted, and ReportedOutcome empty. Its target is a version the manifest does not offer, so the
	// pass still evaluates the release rather than refusing it as poisoned.
	j := agentupdate.NewJournal()
	j.Begin("0.1.9", "0.1.0", now.Add(-2*time.Hour))
	j.RecordFailure("the installer could not be launched", 3, now.Add(-time.Hour))
	if !j.OwesOutcomeReport() {
		t.Fatal("the fixture does not owe an outcome, so this test would pass for the wrong reason")
	}

	saves := 0
	res, err := Tick(context.Background(), TickDeps{
		Source:   fakeSource{m: tickManifest(t, body, srv.URL)},
		Platform: &fakePlatform{running: "0.1.0"},
		Config: agentupdate.Config{Platform: agentupdate.PlatformWindows, Arch: agentupdate.ArchAMD64,
			MaxAttempts: 3, DryRun: true,
			Window: agentupdate.MaintenanceWindow{LocalStart: "00:00", LocalEnd: "23:59"}},
		JournalPath: filepath.Join(t.TempDir(), "journal.json"),
		HTTP:        srv.Client(),
		Load:        func(string) (*agentupdate.Journal, error) { return j, nil },
		Save:        func(*agentupdate.Journal, string) error { saves++; return nil },
	}, now)
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	// The pass must actually have gone through Run to be testing what it claims to.
	if res.Outcome.Action != agentupdate.ActionWouldExecute {
		t.Fatalf("the pass stopped at %q before reaching Run, so nothing here is exercised: %s",
			res.Outcome.Action, res.Outcome.Reason)
	}
	if saves != 0 {
		t.Fatalf("a --dry-run pass wrote the journal %d time(s) on a box that owed an outcome (action=%q)",
			saves, res.Outcome.Action)
	}
	if len(res.Reports) != 0 {
		t.Fatalf("a --dry-run pass queued %d outcome(s)", len(res.Reports))
	}
}

func TestADryRunLeavesNothingBehind(t *testing.T) {
	stagedInto(t)
	now := time.Now().UTC()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "the artifact is not the subject here", http.StatusInternalServerError)
	}))
	defer srv.Close()

	// The state that produces BOTH kinds of write in one pass: a completed attempt to reconcile (journal save
	// + an outcome queued for the fleet), and a plan whose floor would be ratcheted.
	dir := t.TempDir()
	journal := filepath.Join(dir, "journal.json")
	pass := func(dry bool) (saves int, reports int) {
		j := agentupdate.NewJournal()
		j.Begin("0.2.0", "0.1.0", now.Add(-time.Hour))
		j.Enter(agentupdate.PhaseExecuting, now.Add(-time.Hour))
		res, err := Tick(context.Background(), TickDeps{
			Source:   fakeSource{m: tickManifest(t, []byte("payload"), srv.URL)},
			Platform: &fakePlatform{running: "0.2.0"},
			Config: agentupdate.Config{Platform: agentupdate.PlatformWindows, Arch: agentupdate.ArchAMD64,
				MaxAttempts: 3, DryRun: dry},
			JournalPath: journal,
			HTTP:        srv.Client(),
			Load:        func(string) (*agentupdate.Journal, error) { return j, nil },
			Save:        func(*agentupdate.Journal, string) error { saves++; return nil },
			ResolveRollout: func(agentupdate.Manifest) agentupdate.Rollout {
				return agentupdate.Rollout{PlanGeneratedAt: now.Add(-5 * time.Minute)}
			},
		}, now)
		if err != nil {
			t.Fatalf("Tick: %v", err)
		}
		return saves, len(res.Reports)
	}

	saves, reports := pass(true)
	if saves != 0 {
		t.Fatalf("a --dry-run pass wrote the journal %d time(s) — the plan floor it records is one-way and "+
			"freezes the device against every earlier plan", saves)
	}
	if reports != 0 {
		t.Fatalf("a --dry-run pass queued %d outcome(s) for the fleet view; DsseSteer drains that directory on "+
			"its next beat, so a rehearsal would have reported an update that never happened", reports)
	}
	if files, _ := os.ReadDir(agentupdate.ReportsDir(journal)); len(files) != 0 {
		t.Fatalf("a --dry-run pass left %d file(s) in the outbox", len(files))
	}

	// ★ AND THE DIRECTION THAT MATTERS MORE: the same pass WITHOUT the flag must still do both. Without this
	// the test passes just as well against a build that lost the ability to record anything at all — which is
	// the more expensive defect of the two, and the one a guard like this can introduce.
	saves, reports = pass(false)
	if saves == 0 {
		t.Fatal("a real pass recorded nothing: a completed attempt it forgets is one the fleet never hears about")
	}
	if reports == 0 {
		t.Fatal("a real pass queued no outcome, so the fleet view stays at total:0 for a device that updated")
	}
}

// --- the staged installer, after the attempt is over -------------------------------------------------------

// stagedThenUnreachable puts a verified package on disk the way a real pass would, and then returns a manifest
// naming a server that is no longer listening.
//
// ★ The dead URL is the whole point of the helper. Stage returns an already-verified file without touching the
// network, so a test that leaves the origin up cannot tell "the pass left the bytes alone" from "the pass
// deleted them and put them back" — and the second is the failure this pins. With the origin gone, a file that
// is still there at the end was never removed.
func stagedThenUnreachable(t *testing.T) (string, agentupdate.Manifest) {
	t.Helper()
	body := []byte("installer payload")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(body) }))
	m := tickManifest(t, body, srv.URL)
	if _, err := Stage(context.Background(), srv.Client(), m); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	srv.Close()
	p, err := StagedPath(m.Version)
	if err != nil {
		t.Fatalf("StagedPath: %v", err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("the staged package this test rests on is not on disk: %v", err)
	}
	return p, m
}

// tickAfter runs one pass over a journal that is already mid-attempt, with the device reporting running.
func tickAfter(t *testing.T, j *agentupdate.Journal, m agentupdate.Manifest, running string, now time.Time) TickResult {
	t.Helper()
	res, err := Tick(context.Background(), TickDeps{
		Source:      fakeSource{m: m},
		Platform:    &fakePlatform{running: running},
		Config:      agentupdate.Config{Platform: agentupdate.PlatformWindows, Arch: agentupdate.ArchAMD64, MaxAttempts: 3},
		JournalPath: filepath.Join(t.TempDir(), "journal.json"),
		Load:        func(string) (*agentupdate.Journal, error) { return j, nil },
		Save:        func(*agentupdate.Journal, string) error { return nil },
	}, now)
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	return res
}

// TestACompletedUpdateThrowsAwayTheStagedInstaller: measured on win-dev-1 2026-08-11, a landed update left its
// fully-verified MSI in %ProgramData%\DSSE\staged, and would have been joined by one more on every release.
// ClearStaged existed for this and had no callers on either platform.
func TestACompletedUpdateThrowsAwayTheStagedInstaller(t *testing.T) {
	stagedInto(t)
	now := time.Now().UTC()
	staged, m := stagedThenUnreachable(t)

	j := agentupdate.NewJournal()
	j.Begin(m.Version, "0.1.0", now.Add(-time.Hour))
	j.Enter(agentupdate.PhaseExecuting, now.Add(-time.Hour))

	res := tickAfter(t, j, m, m.Version, now)
	if !res.Reconciled {
		t.Fatalf("the attempt was not closed, so this test proves nothing about a completed one (notes=%v)", res.Notes)
	}
	if j.Phase != agentupdate.PhaseCompleted {
		t.Fatalf("phase = %q, want %q", j.Phase, agentupdate.PhaseCompleted)
	}
	if _, err := os.Stat(staged); !os.IsNotExist(err) {
		t.Fatalf("a privileged installer is still sitting at %s after the update landed (stat: %v)", staged, err)
	}
}

// An attempt that did NOT land keeps its bytes: the next window has to be able to retry without downloading
// tens of megabytes again.
func TestAnAttemptThatDidNotLandKeepsItsStagedBytes(t *testing.T) {
	stagedInto(t)
	now := time.Now().UTC()
	staged, m := stagedThenUnreachable(t)

	j := agentupdate.NewJournal()
	j.Begin(m.Version, "0.1.0", now.Add(-time.Hour))
	j.Enter(agentupdate.PhaseExecuting, now.Add(-time.Hour))

	// The device came back up on the OLD version, which is what a failed install looks like from here.
	res := tickAfter(t, j, m, "0.1.0", now)
	if res.Reconciled {
		t.Fatal("an attempt that did not land was closed as if it had")
	}
	if _, err := os.Stat(staged); err != nil {
		t.Fatalf("the staged package was thrown away after a FAILED attempt, so the retry must download it again: %v", err)
	}
}

// A rollback does not clear anything, and the build the device escaped stays on disk. Its bytes are keyed by
// FromVersion and this line never names them in any phase — deliberately: they are the evidence of what
// happened, and what stops them being installed again is the poison, not a deletion.
func TestARollbackLeavesTheEscapedBuildOnDisk(t *testing.T) {
	stagedInto(t)
	now := time.Now().UTC()
	staged, m := stagedThenUnreachable(t)

	j := agentupdate.NewJournal()
	j.BeginRollback("0.1.0", m.Version, now.Add(-time.Hour))
	j.Enter(agentupdate.PhaseRollingBack, now.Add(-time.Hour))
	// ★ The refusal a real rollback writes as it leaves. Without it this same pass begins a FRESH attempt at
	// the build the device just escaped — which is not a defect in the tick but the same fact seen from the
	// other side: the poison is the only thing that makes a rollback stay rolled back, and a fixture that omits
	// it is not the journal any real rollback leaves behind.
	j.Refuse(m.Version, "rolled back away from this build")

	res := tickAfter(t, j, m, "0.1.0", now)
	if !res.Reconciled {
		t.Fatalf("the rollback was not closed, so this test proves nothing (notes=%v)", res.Notes)
	}
	if j.Phase != agentupdate.PhaseRolledBack {
		t.Fatalf("phase = %q, want %q", j.Phase, agentupdate.PhaseRolledBack)
	}
	if _, err := os.Stat(staged); err != nil {
		t.Fatalf("the package this device rolled back AWAY from was deleted (%s): %v", staged, err)
	}
}
