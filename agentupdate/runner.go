package agentupdate

import (
	"errors"
	"fmt"
	"time"
)

// runner.go — the ORDER in which an update happens, and the journal written before each step.
//
// Everything dangerous about auto-update is in the sequencing, so the sequencing lives here, in one
// platform-agnostic place that can be tested without a Windows box. What the platform supplies is only the
// doing: read the running version, capture restore material, take steering down, launch the installer.
//
// Two orderings are load-bearing and neither is obvious from the outside.
//
// Restore material is captured BEFORE anything is touched, and a missing one ABORTS. An update that cannot be
// rolled back is the same as having no rollback, and the moment to discover that is before the installer
// runs, not after. On Windows this is the MSI that produced the running version — a box installed months ago
// does not have it, and that is a reason not to start.
//
// Steering is taken down DELIBERATELY before the installer is handed control, on endpoints entitled to fail
// open. The alternative is letting the installer stop the agent while the WFP redirect is still armed, which
// is the black hole: every connection refused, with no user-mode process left to clear it. Disarming first
// means a failure anywhere in the install lands the box on its native network instead.

// ErrAgentNotRunning is what RunningVersion returns when no agent process is alive on this endpoint, so
// there is no running version to report.
//
// It is a distinct sentinel because it is a NORMAL state with a specific correct response, not a fault. Two
// wrong answers were available and both are worse than refusing:
//
//   - returning the last version some process reported. A value that outlives its process is a lie with a
//     plausible shape: the updater would evaluate MinFromVersion and the upgrade gate against a build nobody
//     is running, and pick the wrong migration or skip the box. This is exactly the "new bytes, old code"
//     confusion the method exists to prevent, one layer up.
//   - returning an I/O error. Run would abort with a fault, and the fleet would show a broken updater rather
//     than what is actually true, which is a broken agent.
//
// Note the tension, because it is real and this is the deliberate side of it: an endpoint whose agent is
// permanently dead is arguably the one that most needs a new build. Refusing means an update cannot fix it.
// Refusing is still right — of the two mistakes, skipping a box is the reversible one, and it is only
// acceptable because the skip is REPORTED (Outcome carries the reason, and dsse-watchdog independently reports
// a dead agent). Recovering a dead agent is the watchdog's job and a re-install's job, not an unattended
// update's.
var ErrAgentNotRunning = errors.New("no agent process is running on this endpoint, so there is no running version")

// ErrRunningVersionUnknown is what RunningVersion returns when an agent IS running but did not report which
// version it is. In practice that means an agent older than the reporting mechanism itself.
//
// Separate from ErrAgentNotRunning because the response differs: that box needs its agent recovered, this box
// needs an INSTALL — and it cannot get one from this updater, which is gated on the very answer it cannot
// give. That is the same bootstrap as restore material (a box installed before stashing existed has nothing to
// roll back to and refuses every update until an install leaves something), and it has the same resolution: one
// delivery by MDM or by hand, after which the device manages itself.
//
// It is a distinct sentinel so those devices can be COUNTED. Folded into either the not-running case or a
// generic error, a fleet with a long tail of old agents looks like a rollout that inexplicably stalls at some
// percentage, and the operator has no name for the thing to fix.
var ErrRunningVersionUnknown = errors.New("the running agent did not report its version")

// Platform is everything the runner cannot do itself. Each method is deliberately small so a fake can be
// exhaustive; the interesting logic is the order they are called in, not the calls.
type Platform interface {
	// RunningVersion is the version of the code ACTUALLY EXECUTING, never what is installed on disk. The
	// difference matters because a box can hold new bytes and run old ones until it reboots — a kernel driver
	// that could not be unloaded, or a system extension whose replacement completes on restart.
	//
	// THE MEANING, since the mechanism differs per platform and win-dev-1 found that the spec had not said
	// what the method means, only what one platform should do. A version counts as "running" only when it is
	// paired with an INDEPENDENT liveness signal for the process that reported it. A value plus liveness is a
	// running version; a value alone is a memory. When there is no live process, return ErrAgentNotRunning
	// rather than the remembered value.
	//
	// Windows satisfies this with a value the agent writes to its service Parameters key at startup and clears
	// on clean shutdown, cross-checked against the SCM's view of the service (clients/windows-wfp/runstate).
	// The registry value is the memory; the SCM is the liveness. macOS has the identical problem — a system
	// extension whose replacement completes on restart is the same "new bytes, old code" case — and the same
	// answer in a different mechanism: the value the running extension reports, paired with its heartbeat.
	// What must NOT differ across platforms is the rule above.
	RunningVersion() (string, error)
	// Conditions is what the device can observe about itself for the gate.
	Conditions(now time.Time) DeviceConditions
	// CaptureRestoreMaterial secures what a rollback would need, locally, and returns a description of it. An
	// error here stops the update: see the note above.
	CaptureRestoreMaterial(m Manifest) ([]string, error)
	// RestoreMaterialFor returns the installer package this device holds for a specific version, or an error
	// saying what it does hold. It is the read half of the same store CaptureRestoreMaterial writes into, and it
	// exists so Rollback can refuse BEFORE touching anything.
	RestoreMaterialFor(version string) (string, error)
	// DisarmBeforeUpdate reports whether this endpoint's posture permits taking steering down first. False on
	// a fail-closed endpoint, where doing so would break the posture the operator chose.
	DisarmBeforeUpdate() bool
	// Disarm takes steering down and confirms it: clears the redirect, restores the resolver, unblocks QUIC.
	Disarm() error
	// Rearm puts steering back and confirms it, for the case the installer never ran.
	//
	// ★ IT EXISTS BECAUSE DISARMING IS NOT FREE (2026-08-11, from a review). Steering is taken down before the
	// installer on endpoints entitled to fail open, which is right — the alternative is the black hole. But if
	// the launch then fails (a staged file that no longer verifies, no msiexec, a refused CreateProcess), the
	// old code recorded the failure and returned, leaving the box on its native network with the control OFF
	// and nothing in the system intending to put it back. A security control that switches off during a failed
	// update and stays off is the silent-regression class this codebase keeps finding, arrived at from a new
	// direction.
	//
	// On a platform that never disarms this is unreachable and must refuse loudly rather than return nil: a
	// no-op wearing the costume of a restoration is worse than not having one.
	Rearm() error
	// Execute launches the installer DETACHED and returns immediately. It must not wait: the installer
	// replaces this very binary.
	Execute(m Manifest) error
	// ExecuteRollback launches the installer for a package ALREADY on this device, DECLARING the downgrade
	// deliberate, and returns immediately for the same reason Execute does.
	//
	// ★ The declaration is the whole method. Both platforms refuse to install an older build over a newer one —
	// the macOS preinstall and the MSI's downgrade guard — and they are RIGHT to: an unintended downgrade is a
	// broken machine. So a rollback is not "an install that happens to go backwards", it is a downgrade that
	// says so, through a mechanism the guard can tell apart from every other install. A guard that anything can
	// override is not a guard; one nothing can override means the material this design refuses to update
	// without is material nothing can use.
	//
	// It is on the interface, rather than being an optional capability discovered at runtime, so that a
	// platform which cannot yet do it FAILS TO COMPILE instead of being found out during an incident.
	ExecuteRollback(pkg, toVersion string) error
}

// Outcome is what one Run produced.
type Outcome struct {
	Action string // "none" | "waiting" | "executing" | "refused" | "resumed"
	Reason string
}

// Outcome actions.
const (
	ActionNone      = "none"      // nothing applicable
	ActionWaiting   = "waiting"   // applicable, held by the gate
	ActionExecuting = "executing" // handed to the installer; this process may be replaced at any moment
	// ActionWouldExecute is a rehearsal that reached the launch and stopped. Distinct from ActionExecuting so
	// that "we tested it" and "it ran" can never read the same in a log.
	ActionWouldExecute = "would_execute"
	// ActionInProgress is an attempt too young to judge. Distinct from `resumed`, which asserts the opposite —
	// that something stopped and never finished — and which drags a network warning behind it.
	ActionInProgress = "in_progress"
	ActionRefused    = "refused" // will not attempt: poisoned, un-rollbackable, or not applicable
	ActionResumed    = "resumed" // an interrupted attempt was found and handed to recovery
)

// Config bundles what a Run needs besides the platform.
type Config struct {
	Window      MaintenanceWindow
	MaxAttempts int
	// Platform/Arch identify this endpoint for Manifest.Applicable.
	Platform string
	Arch     string

	// SteeringSurvivesAgent says whether this platform's interception outlives the process that installed it.
	//
	// TRUE on Windows: the WFP redirect is held in the kernel and only dsse-steer can clear it, so an install
	// that died mid-flight can leave a box refusing every connection with nothing left to fix it — that is the
	// black hole the disarm ordering exists for, and the reason an interrupted attempt tells the operator to
	// check the network first. FALSE on macOS: an app-proxy provider that stops is one the system stops handing
	// flows to, and nothing survives it.
	//
	// It is here rather than inferred from Platform because it is a property of the STEERING MECHANISM, and the
	// day a platform changes mechanism is the day an inference from its name becomes wrong silently.
	SteeringSurvivesAgent bool

	// PlanHold is the reason this device's plan may not authorise an install, or empty when it may. See
	// DeviceConditions.PlanHold: it is carried as a value the GATE reads, because the previous shape — clearing
	// the wave start — was silently undone three lines later by the no-schedule fallback.
	PlanHold string

	// Frozen halts every device carrying it, and is the WITHDRAWAL mechanism: a release found bad after it
	// shipped is stopped by an operator setting this, not by un-publishing the manifest. Un-publishing cannot
	// be the answer — a device that already holds the manifest would never hear about it, and on the Edge a
	// missing manifest is indistinguishable from a misconfigured path.
	Frozen bool
	// EligibleSince is when this device's rollout wave opened. It comes from the control plane, which is the
	// only party that can compute it: it needs the release time, the device's group memberships and the wave
	// schedule together.
	//
	// Zero means "no schedule", which the gate reads as no wave restriction rather than as "start now" — see
	// the fallback below, which then measures the deadline from when this device first became eligible.
	EligibleSince time.Time

	// DryRun stops immediately before the installer is launched and changes nothing that outlives the pass:
	// no phase transition, no journal write, no Execute.
	//
	// ★ IT IS A FLAG ON THE SEQUENCING, not a branch around it, and that is the whole point. A rehearsal that
	// evaluates the gate somewhere else is a rehearsal of different code — it would agree with the real path
	// right up until the day the two drifted, which is the day you would be relying on it. Everything above
	// this point runs exactly as it does for a real update: the manifest is applied, the artifact is staged and
	// its digest verified, the freeze and the wave and the window and the deadline all decide, and steering is
	// NOT taken down. Only the last step is withheld.
	//
	// The previous rehearsal did the opposite — it skipped STAGING (the download and the digest check, the two
	// things most likely to be wrong before a maintenance window) and still called through to here, where an
	// open window would have reached the launch with nothing staged.
	DryRun bool
}

// Run advances one update attempt by one step and returns what it did.
//
// It is written to be called repeatedly on a timer rather than to block: every step persists the journal
// before acting, so the process can be killed between any two lines and the next Run knows where it was.
// save is the journal writer (the caller owns the path); it is called before each action and its failure
// STOPS the update, because an unrecorded step is a step nobody can recover from.
func Run(j *Journal, m Manifest, cfg Config, p Platform, save func(*Journal) error, now time.Time) (out Outcome, err error) {
	// ★ A REHEARSAL PERSISTS NOTHING. Caught by a test: the dry run reached restore-material capture, which
	// enters `snapshotted` and SAVES — so the next pass found an attempt that had "stopped part way" and
	// reported `resumed`. A rehearsal that leaves the device looking mid-update is worse than one that does
	// nothing, because the state it leaves is the one an operator is told to investigate.
	//
	// Suppressed here rather than at each call site: every future write inside this function is covered, and a
	// flag each new code path has to remember is a flag that will be forgotten.
	if cfg.DryRun {
		// Literally nothing: the sequencing runs against a COPY, so neither the file nor the caller's journal
		// moves. Suppressing only the save left the in-memory journal in `snapshotted`, and a caller that
		// inspects it — or a long-lived process that reuses it — would see a device mid-update because someone
		// tested. "Changes nothing" should mean that, not "changes nothing durable".
		j = j.clone()
		save = func(*Journal) error { return nil }
	}
	// An interrupted attempt outranks a new one. Finishing what was started — or admitting it cannot be
	// finished — has to happen before another install is layered on top of a box in an unknown state.
	// ★ AN INSTALLER LAUNCHED SECONDS AGO HAS NOT FAILED (2026-08-11, measured on a live Mac).
	//
	// Execute hands the package over DETACHED and returns; the installer then replaces the agent, and the
	// updater daemon it restarts runs its first pass IMMEDIATELY — by design, because a machine that just
	// booted is the one most likely to be behind. On this Mac that pass landed ten seconds after the handover,
	// while the extension had not yet restarted and rewritten runtime_version.json. Reconcile correctly left
	// the attempt open, and then the branch below declared it interrupted, wrote PhaseFailed, and — because
	// NeedsNetworkRecovery is true for PhaseExecuting — told the operator this box's NETWORK must be checked.
	//
	// The update had succeeded. The journal recorded `failed` for it permanently, since nothing revisits a
	// finished target, and every successful update in the fleet would have reported the same way.
	//
	// So the question is not "is an attempt still recorded" but "could it still be running".
	//
	// ★ MEASURED FROM WHEN THE MACHINE STARTED CHANGING, NOT FROM WHEN THE ATTEMPT WAS RECORDED (2026-08-14,
	// measured on win-dev-1). This used to read attempt_started_at, and an attempt can be recorded and then
	// WAIT — for a window, a wave, or a blocker to clear — because Begin is skipped for a continuing attempt.
	// On that box the attempt was recorded at 09:17 and refused for want of rollback material; the blocker was
	// fixed and the same attempt executed at 09:53, by which point the ten-minute grace had been spent
	// thirty-six minutes earlier. The install succeeded and was recorded as `failed`, with the network alarm
	// this grace exists to prevent. See Journal.InFlightSince.
	if interrupted, phase := j.Interrupted(); interrupted && j.installYoungerThan(InstallGrace, now) {
		// Nothing is written: this is the ordinary middle of an install, not an event.
		return Outcome{Action: ActionInProgress, Reason: fmt.Sprintf("an attempt at %s is in phase %q and was "+
			"started %s ago — the installer may still be running, so this is not being called interrupted yet",
			j.TargetVersion, phase, now.Sub(j.attemptStarted()).Round(time.Second))}, nil
	}
	if interrupted, phase := j.Interrupted(); interrupted {
		// Ask BEFORE moving the phase. Entering PhaseFailed first would erase the very evidence being read —
		// NeedsNetworkRecovery answers from the phase, so by then every interrupted attempt would look
		// harmless, and the boxes that most need their network checked are exactly the ones that would stop
		// saying so. Caught by its own test, which is the only reason it is not still here.
		needsNetwork := j.NeedsNetworkRecovery()
		j.Enter(PhaseFailed, now)
		if err := save(j); err != nil {
			return Outcome{}, fmt.Errorf("record the interrupted attempt: %w", err)
		}
		what := "an update to"
		if j.IsRollback() {
			what = "a rollback to"
		}
		detail := fmt.Sprintf("%s %s stopped in phase %q and never finished", what, j.TargetVersion, phase)
		if needsNetwork && cfg.SteeringSurvivesAgent {
			detail += " — steering was down or the installer was mid-run, so this box's NETWORK must be checked before anything else is attempted on it"
		} else if needsNetwork {
			// ★ THE SAME PHASE, A DIFFERENT PLATFORM, AND THEREFORE A DIFFERENT INSTRUCTION (2026-08-11).
			//
			// The network sentence exists for the Windows black hole: the WFP redirect is held in the kernel and
			// outlives the agent, so an install that died mid-flight can leave a box refusing every connection with
			// no user-mode process left to clear it. On macOS an app-proxy provider that stops is one the system
			// stops routing to — there is no residue, and this Mac was reachable throughout.
			//
			// Sending an operator to check a network that was never touched is not a harmless extra sentence. It
			// is the same failure as the alarm attached to the normal outcome: an instruction that is wrong on one
			// of the two platforms teaches people to skip reading it on both.
			detail += " — steering on this platform does not outlive the agent, so the network is not in question." +
				" What must be established is whether the install completed: compare the RUNNING version against" +
				" the target above"
		}
		return Outcome{Action: ActionResumed, Reason: detail}, nil
	}

	if poisoned, why := j.IsPoisoned(m.Version); poisoned {
		return Outcome{Action: ActionRefused, Reason: fmt.Sprintf("%s is poisoned on this device: %s. "+
			"Name a different version to clear it", m.Version, why)}, nil
	}

	running, err := p.RunningVersion()
	if errors.Is(err, ErrRunningVersionUnknown) {
		// Same treatment, different sentence, and emphatically no failure recorded: this device is not refusing
		// a version, it is unable to be assessed by this mechanism at all, and no number of attempts will change
		// that. Poisoning here would additionally blame the release.
		return Outcome{Action: ActionRefused, Reason: fmt.Sprintf("NOT starting %s: %v. This device must be brought "+
			"up to a version that reports itself — by MDM or a manual install — before the DSSE updater can act on "+
			"it. Nothing here will fix itself with time, so this device should be counted, not retried", m.Version, err)}, nil
	}
	if errors.Is(err, ErrAgentNotRunning) {
		// Refuse, and deliberately do NOT call RecordFailure. Counting this would poison a perfectly good
		// version after MaxAttempts because the agent was down — the version would then be refused on this
		// device even after the agent came back, and the operator would be hunting a release that was never
		// the problem. Poisoning means "this version fails HERE"; this is "this device cannot be assessed".
		return Outcome{Action: ActionRefused, Reason: fmt.Sprintf("NOT starting %s: %v. The version this device "+
			"is running cannot be established, so neither the upgrade check nor min_from_version can be evaluated, "+
			"and an update applied against an unknown starting state is how a box gets the wrong migration. This "+
			"is a dead agent to be recovered, not an update to be forced", m.Version, err)}, nil
	}
	if err != nil {
		return Outcome{}, fmt.Errorf("read the running version: %w", err)
	}
	if aerr := m.Applicable(running, cfg.Platform, cfg.Arch); aerr != nil {
		return Outcome{Action: ActionNone, Reason: aerr.Error()}, nil
	}

	// Applicable but not yet started: this is when the deadline clock begins, so a device that has been
	// waiting is distinguishable from one that just became eligible.
	// ★ A RETRY OF THE SAME VERSION IS A NEW ATTEMPT (2026-08-13, twenty-ninth review). RecordFailure clears
	// neither TargetVersion nor AttemptStartedAt, so a second try at the same release skipped Begin and kept
	// the FIRST attempt's start time — and the interrupted-attempt grace is measured from it. A failure at
	// 10:00 and a retry at 11:00 that is interrupted then looks stale immediately, so the recovery path treats
	// an install that started seconds ago as abandoned and may roll back over a running msiexec.
	//
	// A journal already in a terminal phase for this version is finished with the previous attempt, whatever
	// its target says.
	if j.TargetVersion != m.Version || j.AttemptStartedAt == "" || j.terminal() {
		j.Begin(m.Version, running, now)
		if err := save(j); err != nil {
			return Outcome{}, fmt.Errorf("record the attempt start: %w", err)
		}
	} else if running != "" && j.FromVersion != running {
		// ★ THE SAME ATTEMPT, A DEVICE THAT HAS MOVED UNDER IT (2026-08-14, measured on win-dev-1). Begin is
		// skipped for a continuing attempt, so FromVersion keeps whatever was running when the attempt was first
		// recorded — and a device can change version in between, by an operator's install or a rollback, while
		// the attempt waits for a window or a blocker.
		//
		// It is not a cosmetic field. FromVersion is what the fleet is told this update came FROM, and it is how
		// the restore material is keyed. On that box the journal said the update ran from 0.1.9+7d95761f while
		// the package captured to roll back to was 0.1.10+ba2a21ea: the record and the bytes disagreed about
		// where the device would land, which is the one thing a rollback record has to get right.
		//
		// Deliberately not a Begin: the attempt has not restarted, so the deadline clock and the eligibility it
		// has already earned must survive. Only the fact that went stale is refreshed.
		j.FromVersion = running
		if err := save(j); err != nil {
			return Outcome{}, fmt.Errorf("record the version this attempt is upgrading from: %w", err)
		}
	}

	cond := p.Conditions(now)
	// The plan's two facts override anything the device observed about itself, because they are not
	// observations: they are what the operator and the control plane decided, and a device does not get an
	// opinion about whether the fleet is halted.
	if cfg.Frozen {
		cond.Frozen = true
	}
	cond.PlanHold = cfg.PlanHold
	if !cfg.EligibleSince.IsZero() {
		cond.EligibleSince = cfg.EligibleSince
	}
	if cond.EligibleSince.IsZero() {
		if t, perr := time.Parse(time.RFC3339, j.AttemptStartedAt); perr == nil {
			cond.EligibleSince = t
		}
	}
	if gate := EvaluateGate(cfg.Window, cond); !gate.Proceed {
		j.RecordWait(gate.WaitReason, now)
		if err := save(j); err != nil {
			return Outcome{}, fmt.Errorf("record the wait: %w", err)
		}
		return Outcome{Action: ActionWaiting, Reason: gate.Detail}, nil
	}

	// ★ Restore material first, and a failure here ABORTS rather than continuing hopefully. An update that
	// cannot be rolled back is the same as having no rollback, and this is the last moment it is cheap to
	// find out.
	material, cerr := p.CaptureRestoreMaterial(m)
	if cerr != nil {
		// ★ REFUSE, AND DO NOT COUNT IT. Measured on win-dev-1, 2026-08-11: this branch used to call
		// RecordFailure, so three ORDINARY TICKS on a device with no stored installer package poisoned the
		// version permanently. With a 30-minute interval that is ninety minutes, unattended, with nobody
		// rehearsing anything — and afterwards the device refused that version FOREVER, including after a
		// rollback package appeared and the precondition was satisfied. Verified both halves on the box:
		// three real passes wrote `poisoned: {9.9.9: ...}`, and placing the missing package changed nothing.
		//
		// The message it poisoned with contained its own refutation — "It will keep refusing until an install
		// leaves one behind" — a promise the act of writing it made false.
		//
		// The rule is already stated a hundred lines up, for the dead-agent case: poisoning means "this version
		// fails HERE", and this is "this device is not ready to attempt ANY version yet". It is in fact the
		// weaker of the two: a dead agent may never come back, whereas missing restore material is repaired by
		// the next install that stores a package, which is the ordinary course of events. Counting the one
		// condition guaranteed to fix itself was the exact inversion of what poisoning is for.
		//
		// No save either, matching that precedent: nothing about the journal changed, and writing PhaseFailed
		// would leave a device that never attempted anything looking like one whose update broke.
		return Outcome{Action: ActionRefused, Reason: fmt.Sprintf("NOT starting %s: this box has nothing to roll "+
			"back to (%v). An update that cannot be undone is not safer for being attempted. This is a device "+
			"that is not ready yet, not a bad release, so it is NOT counted against the version — the next "+
			"install that stores a package clears it", m.Version, cerr)}, nil
	}
	j.RestoreMaterial = material
	j.Enter(PhaseSnapshotted, now)
	if err := save(j); err != nil {
		return Outcome{}, fmt.Errorf("record the snapshot: %w", err)
	}

	// ★ Disarm before handing over, where posture permits. Journal FIRST: if this process dies between the
	// write and the disarm, the next Run sees `disarmed` and knows to check the network — whereas writing
	// afterwards would leave a box with steering down and no record of why.
	// ★ A DRY RUN STOPS HERE — after the gate and after restore material, before steering is touched.
	//
	// Placed by a test that caught it in the wrong place: with the stop after the disarm, a rehearsal took the
	// tunnel down on a working machine. Anyone testing an update would lose connectivity to prove they could
	// keep it. Capture runs, because "this box has nothing to roll back to" is exactly what a rehearsal should
	// discover; disarm and execute do not, because they are the two steps that change the machine.
	if cfg.DryRun {
		return Outcome{Action: ActionWouldExecute, Reason: fmt.Sprintf("DRY RUN: %s is staged, its digest verified, "+
			"restore material captured, and every gate passed — a real pass would take steering down and hand it to "+
			"the installer now. Nothing was launched, steering is untouched, and the journal is unchanged.", m.Version)}, nil
	}

	// ★ EVERY EXIT AFTER A SUCCESSFUL DISARM MUST TRY TO PUT IT BACK (2026-08-11, second review). The first
	// version only restored after a failed Execute — so a journal write that failed between the disarm and the
	// launch returned with the control off and nothing intending to restore it. The device would be unprotected
	// because a FILE could not be written.
	//
	// A defer, so no future exit can forget: `launched` is set only once the installer is genuinely running,
	// which is the single case where steering must stay down.
	disarmed, launched := false, false
	defer func() {
		if !disarmed || launched {
			return
		}
		rerr := p.Rearm()
		if rerr == nil {
			return
		}
		// ★ THE CALLER MUST BE TOLD (2026-08-11, third review). The first version recorded this in the journal
		// and dropped it: a device left unprotected reported "the journal could not be written", which sends
		// somebody to look at a disk while the endpoint sits on its native network. It is joined onto whatever
		// is being returned, and it leads, because it is the more urgent half.
		//
		// The journal write is attempted too and its own failure is folded in rather than discarded — if the
		// save that got us here failed, this one probably fails as well, and "we could not even record it" is
		// part of the state somebody needs.
		j.LastFailureReason = failureWithSteering(j.LastFailureReason, true, true, rerr)
		serr := save(j)
		unprotected := fmt.Errorf("★ STEERING WAS TAKEN DOWN FOR THIS INSTALL AND COULD NOT BE RESTORED (%w); "+
			"this endpoint is on its native network with the control OFF and needs a person now", rerr)
		if serr != nil {
			unprotected = fmt.Errorf("%w; and it could not be recorded either (%v)", unprotected, serr)
		}
		if err != nil {
			err = fmt.Errorf("%w; %v", unprotected, err)
		} else {
			err = unprotected
		}
		out.Action, out.Reason = ActionRefused, unprotected.Error()
	}()
	if p.DisarmBeforeUpdate() {
		j.Enter(PhaseDisarmed, now)
		if err := save(j); err != nil {
			return Outcome{}, fmt.Errorf("record the disarm: %w", err)
		}
		if derr := p.Disarm(); derr != nil {
			// Could not confirm steering is down. Proceeding would hand the box to an installer while the
			// redirect may still be armed — the black hole this ordering exists to avoid.
			j.RecordFailure("disarm failed: "+derr.Error(), cfg.MaxAttempts, now)
			if err := save(j); err != nil {
				return Outcome{}, fmt.Errorf("record the disarm failure: %w", err)
			}
			return Outcome{Action: ActionRefused, Reason: fmt.Sprintf("NOT starting: could not confirm steering was "+
				"taken down (%v), and handing the installer a box whose redirect may still be armed is how it ends up "+
				"refusing every connection", derr)}, nil
		}
		disarmed = true
	}

	j.Enter(PhaseExecuting, now)
	if err := save(j); err != nil {
		return Outcome{}, fmt.Errorf("record the execute: %w", err)
	}
	if xerr := p.Execute(m); xerr != nil {
		// ★ PUT THE CONTROL BACK BEFORE REPORTING THE FAILURE. The installer never ran, so nothing is going to
		// restore steering on its own — this device would otherwise sit on its native network until somebody
		// noticed, and the report would say "update failed" while the actual state is "unprotected".
		restored, rerr := restoreSteering(p, disarmed)
		wasDisarmed := disarmed
		disarmed = false // handled here; the defer must not attempt it twice
		j.RecordFailure(failureWithSteering("execute failed: "+xerr.Error(), wasDisarmed, restored, rerr),
			cfg.MaxAttempts, now)
		if err := save(j); err != nil {
			return Outcome{}, fmt.Errorf("record the execute failure: %w", err)
		}
		return Outcome{Action: ActionRefused, Reason: fmt.Sprintf("the installer could not be launched: %v.%s",
			xerr, steeringSentence(wasDisarmed, restored, rerr))}, nil
	}
	launched = true
	return Outcome{Action: ActionExecuting, Reason: fmt.Sprintf("handed %s to the installer; this process may be "+
		"replaced at any moment and the journal is the only record until it comes back", m.Version)}, nil
}

// restoreSteering puts back what Run or Rollback took down, and reports whether it had to and whether it
// worked. Nothing is attempted when steering was never taken down.
func restoreSteering(p Platform, disarmed bool) (attempted bool, err error) {
	if !disarmed {
		return false, nil
	}
	return true, p.Rearm()
}

// steeringSentence is what an operator is told about the control after a launch that never happened.
//
// ★ The three cases are genuinely different and must not render the same: steering was never touched; it was
// taken down and put back; it was taken down and COULD NOT be put back. Only the third is an emergency, and it
// is the one that would otherwise be invisible — a device reporting a failed update while sitting unprotected.
func steeringSentence(disarmed, restored bool, rerr error) string {
	switch {
	case !disarmed:
		return " Steering was never taken down on this endpoint, so nothing about its protection changed."
	case restored && rerr == nil:
		return " Steering was taken down for the install and has been put back."
	default:
		return fmt.Sprintf(" ★ STEERING WAS TAKEN DOWN FOR THIS INSTALL AND COULD NOT BE RESTORED (%v). This "+
			"endpoint is on its native network with the control OFF, and no further attempt will fix that by "+
			"itself — it needs a person or a working agent restart NOW.", rerr)
	}
}

// failureWithSteering is the same distinction, for the journal, where the reason outlives the process.
func failureWithSteering(reason string, disarmed, restored bool, rerr error) string {
	if !disarmed || (restored && rerr == nil) {
		return reason
	}
	return reason + "; ★ steering could NOT be restored afterwards: " + rerr.Error()
}
