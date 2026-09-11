package agentupdate

import (
	"fmt"
	"strings"
	"time"
)

// rollback.go — putting the previous version back, which until now was the one thing the design demanded and
// did not have.
//
// ★ WHAT WAS ACTUALLY MISSING (2026-08-11). Restore material was captured before every update, a device with
// none REFUSED to update at all, and the journal recorded where it would go back to — and nothing anywhere
// could install it. Every update this fleet had ever performed was, in the only sense that matters, an update
// that could not be rolled back; the check that said otherwise was real, and the thing it was protecting did
// not exist. That shape — a precondition enforced for an absent capability — is the same one the WFP redirect
// (armed with no agent) and the keyless updater took, and it is invisible until the moment it is needed.
//
// Two decisions here are not obvious and carry the safety.
//
// A ROLLBACK POISONS THE VERSION IT LEAVES. Without that, the device rolls back at 09:00 and the next ordinary
// tick sees a manifest offering the version it just escaped, finds it applicable, and installs it again — the
// operator watching would see a machine that "would not stay rolled back". Poisoning is exactly the right
// vocabulary for it: it already means "this version is not to be attempted HERE", which is precisely what a
// person who just rolled this box back has decided. The fleet-wide equivalent is the freeze, on the control
// plane; this is the device-local half, and neither substitutes for the other.
//
// AN UNREADABLE RUNNING VERSION DOES NOT REFUSE HERE, and that is the opposite of Run. Run refuses because
// applying an update against an unknown starting state picks the wrong migration. A rollback's entire purpose
// is the box whose agent is broken — refusing on the grounds that the broken agent will not say what it is
// would withhold the mechanism at exactly the moment it exists for. It proceeds and says loudly what it could
// not establish.

// ActionRollingBack is a rollback handed to the installer. ActionWouldRollBack is the rehearsal of one.
const (
	ActionRollingBack   = "rolling_back"
	ActionWouldRollBack = "would_roll_back"
)

// RollbackRequest is what the operator asked for.
type RollbackRequest struct {
	// ToVersion overrides the journal's answer. Empty — the ordinary case — means "the version this device was
	// running before its last attempt", which is what the journal's from_version records.
	//
	// ★ It is bounded by the store, not by trust: the platform can only return a package this device already
	// holds, so the flag names one of a handful of versions rather than an arbitrary one. That bound is what
	// keeps a downgrade override from being a way to push any old build onto a machine.
	ToVersion string

	// LeavingVersion is what this device is escaping, for the case where the RUNNING version cannot be read.
	// Empty on a healthy box, where RunningVersion answers and is used instead.
	//
	// ★ IT EXISTS BECAUSE THE TWO DECISIONS AT THE TOP OF THIS FILE LEFT A HOLE BETWEEN THEM, and it was
	// measured on win-dev-1 (2026-08-11) rather than reasoned about: a rollback landed on a box whose agent
	// could not start, and the journal came back with `poisoned=[]`. A rollback poisons the version it leaves;
	// an unreadable running version does not refuse. Each is right on its own, and together they mean the box
	// the rollback EXISTS FOR — the one whose agent is broken — is exactly the box where nothing gets refused
	// and the next ordinary tick can put the bad build straight back.
	//
	// The caller supplies it because only the platform knows a second, weaker answer to "what is on this
	// machine": on Windows the installed-package record (HKLM\SOFTWARE\DSSE\Agent\InstalledVersion, written by
	// the MSI). Weaker on purpose, and never a substitute for RunningVersion — it says what was INSTALLED, and
	// on the box that matters those differ. For refusing a version it is enough: "do not install this again
	// here" is a statement about the package, and poison comparison ignores build metadata.
	LeavingVersion string
}

// Rollback installs the previous version, deliberately.
//
// It is a separate entry point from Run rather than a branch inside it, because it is an OPERATOR ACTION and
// must not be reachable by the timer. An unattended process that can decide on its own to walk a fleet
// backwards is a worse failure than the one it would be trying to fix.
func Rollback(j *Journal, req RollbackRequest, cfg Config, p Platform, save func(*Journal) error, now time.Time) (out Outcome, err error) {
	// Same rule as Run: a rehearsal persists nothing, against a copy, so nothing a later pass reads can have
	// been moved by someone testing.
	if cfg.DryRun {
		j = j.clone()
		save = func(*Journal) error { return nil }
	}

	// ★ An installer that may still be running is not a box to start a second installer on. Measured from when
	// the machine started being changed, the same question Run asks and for the same reason — except that here
	// the answer is a refusal rather than a quiet "in progress", because a person is waiting on this command and
	// needs to be told to wait rather than left to wonder.
	//
	// The anchor matters more on this path than on Run's: reading attempt_started_at meant an attempt that had
	// waited out the grace before executing looked stale the instant it launched, so a rollback could be started
	// OVER a running installer — two installers on one box, which is the exact outcome this check exists to
	// prevent (2026-08-14; see Journal.InFlightSince).
	if interrupted, phase := j.Interrupted(); interrupted && j.installYoungerThan(InstallGrace, now) {
		return Outcome{Action: ActionRefused, Reason: fmt.Sprintf("NOT rolling back: an attempt at %s entered phase "+
			"%q %s ago and the installer may still be running. Two installers on one box is how a machine ends up "+
			"with neither version. Wait for %s from the attempt and try again", j.TargetVersion, phase,
			now.Sub(j.installStarted()).Round(time.Second), InstallGrace)}, nil
	}

	// ★ AN OUTCOME THIS DEVICE STILL OWES THE FLEET IS NOT ERASED BY ROLLING BACK (2026-08-13, twenty-ninth
	// review). BeginRollback puts the phase back to Verified and zeroes the fingerprint, so a journal holding
	// a terminal failure that had not reached the outbox — the crash window between saving PhaseFailed and
	// queueing it — lost that failure silently, and neither --rollback entry point drains first. The failure
	// that PROMPTED the rollback is exactly the one the fleet never hears about.
	//
	// It is marked pending here rather than sent: this package does not own the outbox, and the caller flushes
	// what the journal owes on its next pass. Refusing the rollback instead would strand an operator on a
	// broken box for the sake of a report.
	if j.OwesOutcomeReport() {
		// MarkReportPendingIfFree rather than a guard: one slot, and the OLDER outcome keeps it — but the one
		// that could not be held is now counted on the device instead of vanishing. See its comment.
		j.MarkReportPendingIfFree(ReportOutcome(j, TerminalReportStatus(j), "", j.LastFailureReason, now))
	} else if interrupted, phase := j.Interrupted(); interrupted {
		// ★ AND A STALE INTERRUPTED ATTEMPT IS A FAILURE NOBODY RECORDED (2026-08-13, twenty-ninth review).
		// The guard above only refuses a YOUNG attempt; an older one fell through to BeginRollback, which
		// overwrites TargetVersion and Phase — so an install that was tried and died left no failure, no
		// pending report, and a fleet view that never learns the attempt happened.
		reason := fmt.Sprintf("an attempt at %s was interrupted in phase %q and never completed; it is "+
			"recorded here because the rollback that follows would otherwise erase it", j.TargetVersion, phase)
		// ★★ AND IT MUST NOT POISON THE VERSION WE ARE RESTORING TO (2026-08-13, thirtieth review #7).
		// RecordFailure counts against j.TargetVersion — which after BeginRollback is the RESTORE TARGET, not
		// the build being escaped. So re-entering --rollback on an unstable box, where the previous rollback was
		// itself interrupted, counted three failures against the known-good version and poisoned it: the device
		// then refuses the only build it was trying to get back to. Sixty lines below there is a guard written
		// for exactly that outcome, and this branch reached it by another road.
		//
		// An interrupted ROLLBACK is still recorded and still reported — the fleet hears about it — but nothing
		// is counted against a version. A rollback that keeps being interrupted is a device problem, and
		// blaming the target for it removes the recovery.
		if j.IsRollback() {
			j.LastFailureReason = reason
			j.Enter(PhaseFailed, now)
		} else {
			j.RecordFailure(reason, DefaultMaxAttempts, now)
			j.Enter(PhaseFailed, now)
		}
		// One pending slot, and the outcome that has been owed longer keeps it — overwriting would lose the
		// one the fleet was already waiting for. What this no longer does is lose the OTHER one in silence:
		// MarkReportPendingIfFree counts it, so a device that owed two outcomes and could report one says so.
		j.MarkReportPendingIfFree(ReportOutcome(j, ReportFailed, "", j.LastFailureReason, now))
	}

	// What is running is reported, never required. See the note at the top of this file.
	running, rerr := p.RunningVersion()
	// leaving is the build this rollback escapes: what gets refused afterwards so it cannot come straight back,
	// and what the journal records as from_version. Normally the running version; the caller's weaker answer
	// when the running one cannot be read, which is the case this whole mechanism is for.
	leaving := running
	var runningNote string
	if rerr != nil {
		running = ""
		leaving = strings.TrimSpace(req.LeavingVersion)
		switch {
		case leaving != "":
			runningNote = fmt.Sprintf(" ★ what this device is RUNNING could not be established (%v), so nothing "+
				"here verified that it is on the version being left; %s is being refused on the strength of what "+
				"is INSTALLED, which is a weaker answer and the right one to act on — this is proceeding because "+
				"a rollback exists for exactly this box", rerr, leaving)
		default:
			// Said in full, because the silence is the danger: the rollback still lands, and then an ordinary
			// tick reinstalls what it just escaped. The operator can only be told at the moment they ask.
			runningNote = fmt.Sprintf(" ★ what this device is running could NOT be established (%v) and no "+
				"installed version was supplied either, so NOTHING HAS BEEN REFUSED on this device: the build "+
				"being left is not named anywhere, and the next ordinary tick may install it again. Freeze the "+
				"fleet or name the version to refuse. This is proceeding because a rollback exists for exactly "+
				"this box", rerr)
		}
	}

	target := strings.TrimSpace(req.ToVersion)
	source := "--rollback-to"
	if target == "" {
		target, source = strings.TrimSpace(j.FromVersion), "the journal's from_version"
		if j.IsRollback() {
			// The last attempt was itself a rollback, so from_version is the version already left behind and
			// rolling back to it would be rolling FORWARD into the build this device just escaped.
			return Outcome{Action: ActionRefused, Reason: fmt.Sprintf("NOT rolling back: the last recorded attempt "+
				"on this device was itself a rollback to %s, so its from_version (%s) is the version that was "+
				"ALREADY abandoned. Going there is not a rollback, it is a re-install of what was rolled back from. "+
				"Name a version explicitly if that is genuinely what is wanted", j.TargetVersion, j.FromVersion)}, nil
		}
	}
	if target == "" {
		return Outcome{Action: ActionRefused, Reason: "NOT rolling back: this device's journal does not record what " +
			"it was running before its last attempt, so there is no previous version to name. This is a device that " +
			"has never updated under this mechanism — name a version explicitly, and only one this device holds a " +
			"package for"}, nil
	}
	// ★ COMPARED AS VERSIONS, NOT AS TEXT (2026-08-13, twenty-ninth review). This was `target == running`, so
	// "0.2.1+stamp" and "0.2.1" missed the short circuit and a needless rollback ran — which then REFUSED the
	// build the device is running, and IsPoisoned matches with SameVersion, so every later manifest offering
	// 0.2.1 was rejected. Build-metadata confusion is the family this package documents as its most expensive
	// past bug, and the guard against it was one comparison short.
	if running != "" && SameVersion(target, running) {
		return Outcome{Action: ActionNone, Reason: fmt.Sprintf("nothing to do: this device is already running %s", target)}, nil
	}

	pkg, perr := p.RestoreMaterialFor(target)
	if perr != nil {
		// Refused, and deliberately nothing written: a rollback that could not start has changed nothing about
		// this device, and a journal that says otherwise would send the next reader to a machine that is fine.
		return Outcome{Action: ActionRefused, Reason: fmt.Sprintf("NOT rolling back to %s (from %s): %v",
			target, source, perr)}, nil
	}

	if cfg.DryRun {
		return Outcome{Action: ActionWouldRollBack, Reason: fmt.Sprintf("DRY RUN: this device holds %s and a real "+
			"pass would install it now, refuse %q on this device afterwards, and record the whole thing. Nothing "+
			"was launched and the journal is unchanged.%s", pkg, leaving, runningNote)}, nil
	}

	j.BeginRollback(target, leaving, now)
	// ★ REFUSE THE VERSION BEING LEFT, and do it BEFORE the installer is handed over rather than after it comes
	// back. There is no "after" from this process's point of view — the installer replaces it — and a rollback
	// that lands without this write is a device that re-installs the bad version on its next tick.
	// ★ AND NEVER POISON THE VERSION BEING RETURNED TO (2026-08-13, twenty-ninth review). LeavingVersion is
	// read from what is INSTALLED, which is right for a box whose agent is dead — and when a failed install
	// never replaced the bundle, what is installed IS the rollback target. Refusing it then poisons 0.2.4 as
	// part of rolling back TO 0.2.4, and every later manifest offering that version is refused. The fix that
	// gave macOS a LeavingVersion closed the "nothing is poisoned" half and opened this one.
	if leaving != "" && !SameVersion(leaving, target) {
		j.Refuse(leaving, fmt.Sprintf("rolled back to %s on %s by an operator; this device will not take %s again "+
			"until a different version is published", target, now.UTC().Format(time.RFC3339), leaving))
	} else if leaving != "" {
		// Said out loud: the operator asked to leave a version and this device is already on it, so there is
		// nothing to refuse and refusing would strand the target.
		j.RecordWait(fmt.Sprintf("rolled back to %s, which is also the version this device reports as installed; "+
			"nothing is refused, because refusing it would make the version being restored unavailable", target), now)
	}
	if err := save(j); err != nil {
		return Outcome{}, fmt.Errorf("record the rollback: %w", err)
	}

	// Steering comes down first where the posture permits it, for the identical reason it does in an update: on
	// Windows the redirect outlives the agent, and an installer run against an armed box with no agent is the
	// black hole. Nothing about the direction of travel changes that.
	// The same defer as Run, for the same reason: a journal write that fails between the disarm and the launch
	// must not leave this device unprotected because a file could not be written.
	// The same defer as Run, including telling the CALLER: a device left unprotected must not be reported as a
	// filesystem problem.
	disarmed, launched := false, false
	defer func() {
		if !disarmed || launched {
			return
		}
		rerr := p.Rearm()
		if rerr == nil {
			return
		}
		j.LastFailureReason = failureWithSteering(j.LastFailureReason, true, true, rerr)
		serr := save(j)
		unprotected := fmt.Errorf("★ STEERING WAS TAKEN DOWN FOR THIS ROLLBACK AND COULD NOT BE RESTORED (%w); "+
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
			j.Enter(PhaseFailed, now)
			if err := save(j); err != nil {
				return Outcome{}, fmt.Errorf("record the disarm failure: %w", err)
			}
			return Outcome{Action: ActionRefused, Reason: fmt.Sprintf("NOT rolling back: could not confirm steering "+
				"was taken down (%v), and an installer run against a box whose redirect may still be armed is how it "+
				"ends up refusing every connection", derr)}, nil
		}
		disarmed = true
	}

	j.Enter(PhaseRollingBack, now)
	if err := save(j); err != nil {
		return Outcome{}, fmt.Errorf("record the rollback launch: %w", err)
	}
	if xerr := p.ExecuteRollback(pkg, target); xerr != nil {
		// ★ NOT RecordFailure. That counts against TargetVersion, which here is the OLD version — the one being
		// restored. Three failed rollbacks would poison the only build this device has left to go back to, and
		// the operator would be locked out of the recovery path by the recovery path.
		// Same as the update path, and for the same reason: the installer never ran, so nothing else is going to
		// put steering back. A recovery attempt that leaves the endpoint unprotected has made the incident worse.
		restored, rerr := restoreSteering(p, disarmed)
		wasDisarmed := disarmed
		disarmed = false // handled here; the defer must not attempt it twice
		j.LastFailureReason = failureWithSteering("rollback launch failed: "+xerr.Error(), wasDisarmed, restored, rerr)
		j.Enter(PhaseFailed, now)
		if err := save(j); err != nil {
			return Outcome{}, fmt.Errorf("record the rollback failure: %w", err)
		}
		return Outcome{Action: ActionRefused, Reason: fmt.Sprintf("the installer for %s could not be launched: %v. "+
			"This device is still running what it was running; %q remains refused on it.%s", target, xerr, leaving,
			steeringSentence(wasDisarmed, restored, rerr))}, nil
	}
	launched = true
	return Outcome{Action: ActionRollingBack, Reason: fmt.Sprintf("handed %s to the installer as a rollback from %q; "+
		// %q is what is being LEFT — the running version where it could be read, the installed one where it
		// could not, and empty only when neither was available (which the note then spells out).
		"this process may be replaced at any moment and the journal is the only record until it comes back. The next "+
		"pass confirms it landed by reading the version that is RUNNING — installed and running are different "+
		"facts.%s", target, leaving, runningNote)}, nil
}

// TerminalReportStatus is what a journal's terminal phase means to the fleet.
//
// ★★ EXPORTED BECAUSE THERE WERE THREE OF IT (2026-08-13, thirtieth review #22). This rule existed verbatim
// here, in the macOS updater, and in the Windows tick — one sentence about what the fleet is told, written out
// three times. Every rule in this lane that has shipped on one platform and not the other started as a
// duplicate somebody kept in step by hand, and this is the file both platforms already import.
//
// A fourth terminal phase is the case that makes it matter: adding one here now reaches both agents, instead of
// reaching whichever one the author remembered.
func TerminalReportStatus(j *Journal) string {
	if j == nil {
		return ReportInstalled
	}
	switch j.Phase {
	case PhaseRolledBack:
		return ReportRolledBack
	case PhaseFailed:
		return ReportFailed
	default:
		return ReportInstalled
	}
}
