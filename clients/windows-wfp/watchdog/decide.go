// Package main — dsse-watchdog: the process that notices a box has been taken off the network, and puts it
// back.
//
// WHY IT IS A SEPARATE PROCESS. The agent already has a fail-open recovery monitor, and it lives inside
// dsse-steer. That is fine for the failure it was built for (the Edge is unreachable) and useless for the one
// this watches: dsse-steer itself being gone. A monitor that dies with the thing it monitors is not a monitor.
//
// WHAT IT WATCHES FOR. The WFP callout driver holds a redirect policy that sends every non-bypassed connect
// to a local port. The only listener on that port is dsse-steer's. Clearing the policy requires an IOCTL that
// only dsse-steer issues. So if dsse-steer dies without issuing it — crash, TerminateProcess, an installer's
// files-in-use kill, power loss — the driver keeps redirecting into nothing and the machine refuses every
// connection, indefinitely, until a person arrives. This process is that person, arriving in seconds.
//
// It is NOT update machinery, even though the agent-update design is what surfaced the problem: a failed
// update is just one of the ways to produce the state, alongside an ordinary crash or a BSOD reboot. It ships
// and is verified on its own.
//
// This file holds only the decision, with no Windows API in it, so the reasoning that decides whether a
// machine gets its network back is exercised by tests on any host rather than only where it runs.
package main

import (
	"fmt"
	"strings"
	"time"
)

// Observation is everything the watchdog knows at one tick. Each field is a three-state answer, because
// "I could not find out" has to be representable: an unknown that decays into a confident "fine" is how a
// watchdog sleeps through the outage it exists for.
type Observation struct {
	// DriverArmed / DriverOwnerPresent / DriverObserveOnly come from IOCTL_DSSE_GET_STATS.
	DriverArmed        bool
	DriverOwnerPresent bool
	DriverObserveOnly  bool
	// DriverStateKnown is false when the driver could not be interrogated for a reason OTHER than it being
	// absent — a failed IOCTL, a version too old to answer. Absent is reported as DriverPresent=false.
	DriverStateKnown bool
	DriverPresent    bool

	// AgentRunning is whether the DsseSteer service is in a running state.
	AgentRunning bool
	// AgentStateKnown is false when the service manager could not be queried.
	AgentStateKnown bool

	// AgentShouldBeRunning is whether the DsseSteer service is configured to start automatically — that is,
	// whether this box is one where the agent NOT running is a deviation rather than a choice.
	//
	// ★ IT EXISTS BECAUSE A CLEAN DEATH LEFT A BOX UNSTEERED AND NOBODY OWNED IT (2026-08-14, measured on
	// win-dev-1). The agent installed by an unattended update exited on its own two minutes after starting.
	// It exited CLEANLY: it disarmed the redirect, restored the resolver, restored the NCSI probe. So there was
	// no residue, Decide fell to its final branch — "it left nothing behind" — and answered ActionNone, which
	// is correct for what this component was built to undo. The SCM did not help either: a graceful exit is not
	// a failure, so the service's RESTART/5000 action never fired. The box sat unsteered for thirty minutes and
	// the only thing that noticed was a person reading the log.
	//
	// "Configured to run and not running, having left nothing behind" is a real state and it belonged to
	// nobody. It does now — as a REPORT, never as an action. See the final branch of Decide for why this
	// watchdog must not start the agent.
	AgentShouldBeRunning bool
	// AgentStartTypeKnown is false when the service's configuration could not be read. Nothing is claimed then:
	// an unreadable start type must not turn a deliberately stopped agent into an alarm.
	AgentStartTypeKnown bool

	// DNSTakeoverResidue: the agent's persisted DNS backup still exists, i.e. DSSE pointed this box's
	// resolver at its own loopback proxy and has not put it back.
	//
	// This is here because of what win-dev-1 measured on 2026-08-09. The driver's own handle-close disarm
	// fixed the black hole on fail-open boxes — and by clearing `armed` it moved them into the one state this
	// watchdog was written to ignore. The kernel cannot restore a resolver; that is a user-mode setting, and
	// the user-mode process is the one that died. So the box keeps IP connectivity, keeps serving cached
	// names, and loses name resolution as TTLs expire. That is worse than the outage it replaced: an outage
	// is attributed correctly, whereas this gets reported as "the internet is flaky".
	//
	// The backup FILE is the right signal, not "the resolver points at loopback". It is DSSE's own record of
	// an unfinished change — written at takeover, deleted by restoreResolverFromBackup on the way out — so it
	// cannot be confused with a box legitimately running a local resolver, and it is the same evidence
	// `--mode recover` already consumes to put the servers back.
	DNSTakeoverResidue bool
	// DNSResidueKnown is false when the check could not be made. It then authorises nothing on its own.
	DNSResidueKnown bool

	// RecoveryToolPath is the steering agent binary this watchdog would run to recover, and RecoveryToolErr
	// says why it could not be found. Recovery is performed by launching that binary with --mode recover, so
	// "can I fix this box?" is a question with an answer BEFORE anything is broken.
	//
	// It is part of the observation because of what happened on win-dev-1, 2026-08-09: the watchdog decided
	// `recover` on a genuinely black-holed box and then failed with "not found", because it assumed the
	// agent's filename. That was fixed by reading the service's ImagePath — but the deeper problem was that
	// resolution happened only at the moment of acting, so a dry run reported `recover` cheerfully on a box
	// where recovery could not run, and every quiet tick before the incident said nothing was wrong.
	//
	// Resolving it every tick turns "this watchdog is not able to do its job here" from something discovered
	// during an outage into something reported before one.
	RecoveryToolPath string
	RecoveryToolErr  string
}

// Action is what the watchdog decided to do this tick.
type Action int

const (
	// ActionNone: nothing is wrong, or nothing that this process should touch.
	ActionNone Action = iota
	// ActionRecover: the box is black-holed. Run the network panic button.
	ActionRecover
	// ActionReportOnly: something is not right but recovering could make it worse, so say so and stop.
	ActionReportOnly
	// ActionCannotRecover: the box needs recovering and this process is unable to do it.
	//
	// Distinct from ActionReportOnly on purpose, because it is a different situation for whoever reads it.
	// Report-only means "wrong, but not mine to touch" and nothing is expected to happen. This means "broken,
	// mine to fix, and I cannot" — a person has to go, which is the outcome this whole component exists to
	// avoid, so it must never be filed under the same heading as a state we are deliberately leaving alone.
	ActionCannotRecover
)

func (a Action) String() string {
	switch a {
	case ActionRecover:
		return "recover"
	case ActionReportOnly:
		return "report_only"
	case ActionCannotRecover:
		return "cannot_recover"
	default:
		return "none"
	}
}

// Decision pairs the action with the sentence an operator will read. The reason is not decoration: this
// process performs an unattended, disruptive-looking act (tearing down steering), and every occurrence has to
// be explainable afterwards without re-deriving it.
type Decision struct {
	Action Action
	Reason string
}

// Decide is the whole policy.
//
// The acting condition is: **the agent is gone, and DSSE has left behind a change to this machine that only
// DSSE can undo.** There are two such changes, and it took a live box to learn that the second one matters as
// much as the first:
//
//   - the WFP redirect is armed with no listener behind it — every connection refused;
//   - the resolver is pointed at the agent's dead loopback proxy — names stop resolving as caches expire.
//
// The first version of this watched only the redirect, and the driver's handle-close disarm then moved every
// fail-open box out of that condition and into the second one, where nothing was watching. Widening it here
// means this process is not "recovery for fail-closed boxes"; it is **the only component that can undo either
// change after an unclean agent death, on every posture.**
//
// Everything else is deliberately left alone. The expensive wrong answer is tearing enforcement off a machine
// that was fine, so an unknown never authorises action and a running agent is never overruled.
func Decide(o Observation) Decision {
	// Unknowns first, and they never authorise action on their own. A watchdog that acts on a failed read is
	// a watchdog that disables steering whenever its own query breaks.
	if !o.AgentStateKnown {
		return Decision{ActionReportOnly, "could not determine whether the DsseSteer service is running; not acting on an unknown"}
	}

	// blackHole: the driver is redirecting for real, and nothing is accepting what it redirects. Requires a
	// readable driver — "present but would not answer" is handled as an unknown below, never as "not armed".
	blackHole := o.DriverPresent && o.DriverStateKnown && o.DriverArmed && !o.DriverObserveOnly
	driverUnreadable := o.DriverPresent && !o.DriverStateKnown
	dnsOrphaned := o.DNSResidueKnown && o.DNSTakeoverResidue

	if o.AgentRunning {
		// The agent is alive. Nothing here is the watchdog's to fix, and acting would be the watchdog causing
		// the outage. The residue is EXPECTED while steering: the backup exists for the whole time DNS is
		// taken over, and is consumed when the agent restores it.
		switch {
		case driverUnreadable:
			return Decision{ActionReportOnly, "the WFP driver is present but would not report its arming state; " +
				"the agent is running, so this is a diagnostic gap rather than an outage — the watchdog cannot tell"}
		case blackHole && !o.DriverOwnerPresent:
			// Up but has not claimed ownership: mid-startup, or a driver too old for the arming handle.
			return Decision{ActionReportOnly, "the WFP driver is redirecting with no policy owner, but the DsseSteer " +
				"service IS running — mid-startup, or an agent/driver pair that predates the arming handle. " +
				"Not recovering: the agent is alive and this may be normal"}
		case blackHole:
			return Decision{ActionNone, "the WFP driver is redirecting and the agent is running; this is normal steering"}
		default:
			return Decision{ActionNone, "the agent is running and the WFP driver is not redirecting"}
		}
	}

	// The agent is gone. What did it leave behind?
	switch {
	case blackHole && dnsOrphaned:
		return o.recoverOrAdmitItCannot("the DsseSteer service is not running, the WFP driver is still redirecting, " +
			"and the resolver is still pointed at the dead agent: every connection on this box is being refused")
	case blackHole:
		return o.recoverOrAdmitItCannot("the DsseSteer service is not running and the WFP driver is still " +
			"redirecting: every connection on this box is being refused")
	case dnsOrphaned:
		// The fail-open case after the driver's handle-close disarm. IP traffic works, so this does NOT look
		// like an outage — which is exactly why it needs a machine to notice it rather than a person.
		return o.recoverOrAdmitItCannot("the DsseSteer service is not running and the resolver is still pointed at " +
			"its dead loopback proxy: IP traffic still works and cached names still resolve, so this decays into " +
			"'the internet is flaky' rather than being reported as a failed agent")
	case driverUnreadable:
		return Decision{ActionReportOnly, "the DsseSteer service is not running and the WFP driver would not " +
			"report its arming state; this box may be redirecting into nothing and the watchdog cannot tell"}
	case !o.DNSResidueKnown:
		return Decision{ActionReportOnly, "the DsseSteer service is not running and the WFP driver is not " +
			"redirecting, but whether the resolver was left pointed at the dead agent could not be checked"}
	case !o.DriverPresent:
		return Decision{ActionNone, "no WFP callout driver on this box and no DNS takeover left behind; " +
			"there is nothing for this watchdog to undo"}
	case o.AgentStartTypeKnown && o.AgentShouldBeRunning:
		// ★ NOTHING TO UNDO IS NOT THE SAME AS NOTHING WRONG (2026-08-14, measured on win-dev-1).
		//
		// This branch used to be folded into the one below and answered ActionNone: the agent left no residue,
		// so there is nothing for this watchdog to undo, so nothing to say. That reading cost this box thirty
		// minutes of not being steered. The agent exited cleanly two minutes after an update installed it —
		// disarmed, resolver restored, NCSI restored — which is a TIDY exit, not a correct one, and tidiness is
		// exactly what made every existing signal read as healthy. The SCM was no help either: a graceful exit
		// is not a failure, so the restart action never fired.
		//
		// REPORT ONLY, AND THAT IS DELIBERATE. Starting the agent would make this process a supervisor, and it
		// is not one — the operator's own runbook stops DsseSteer on purpose to test things, and a watchdog that
		// restarts it turns a diagnosis into a fight. The value here is entirely in ending the silence: this is
		// the one state where the box is unprotected and every other indicator looks fine.
		return Decision{ActionReportOnly, "the DsseSteer service is configured to start automatically and is NOT " +
			"running, and it left nothing behind: the driver is not redirecting and the resolver was restored. " +
			"There is nothing for this watchdog to undo — and THIS BOX IS NOT STEERING. A clean exit produces no " +
			"residue and no SCM restart, so nothing else reports it either. Start DsseSteer, and if it exits " +
			"again on its own, that is the fault to chase"}
	default:
		return Decision{ActionNone, "the agent is not running, but it left nothing behind: the driver is not " +
			"redirecting and the resolver was restored" + notConfiguredToRun(o)}
	}
}

// notConfiguredToRun explains why a stopped agent is being passed over, when the reason is that this box does
// not expect it to be running. Said out loud because "the watchdog was quiet" and "the watchdog checked and
// this is intended" are the same silence otherwise.
func notConfiguredToRun(o Observation) string {
	if !o.AgentStateKnown {
		return ""
	}
	if !o.AgentStartTypeKnown {
		return " (whether it is configured to start automatically could not be read, so no conclusion is drawn " +
			"about it being stopped)"
	}
	return " — and it is not configured to start automatically on this box, so a stopped agent is the intent here"
}

// PostRecoveryOutcome is what a re-read of the box says AFTER recovery has run.
//
// There are three answers and the first version of this code could only express two, which is why win-dev-1
// filed successful recoveries as failures. The re-check asked "is the redirect armed?" and treated any yes as
// failure — but the most common yes on a real box is the SCM bringing the agent back inside the recovery
// window (DsseSteer ships with RESTART/5000, and recovery measured 5.4 s and 9.2 s there), which re-arms the
// driver with a live listener behind it. That is steering resumed: not the black hole, and arguably the best
// available outcome. Filing it as `recovery FAILED` on a box that is fine is how an operator learns to ignore
// event 1002.
type PostRecoveryOutcome int

const (
	// PostRecoveryCleared: the residues are gone and the agent has not come back. The box is on its native
	// network, UNSTEERED — a real state change that someone must know about.
	PostRecoveryCleared PostRecoveryOutcome = iota
	// PostRecoverySteeringResumed: the redirect is armed again AND the agent is running behind it. Enforcement
	// is on. Reportable (this box was black-holed a moment ago) but emphatically not a failure.
	PostRecoverySteeringResumed
	// PostRecoveryStillBroken: recovery ran and the box is still in a state only DSSE can undo, or the state
	// could not be re-read. Unverifiable is reported as broken on purpose: this whole component exists because
	// a disarm that silently did not happen looks exactly like one that did.
	PostRecoveryStillBroken
)

func (o PostRecoveryOutcome) String() string {
	switch o {
	case PostRecoverySteeringResumed:
		return "steering_resumed"
	case PostRecoveryStillBroken:
		return "still_broken"
	default:
		return "cleared"
	}
}

// ClassifyPostRecovery reads the box after recovery ran and says which of the three happened, with the
// sentence explaining it.
//
// The load-bearing distinction is `armed` alone versus `armed with someone behind it`. Armed with the agent
// running is a listener on the redirect's far end; armed with no agent is the black hole. Those are opposite
// situations and the old check could not tell them apart.
func ClassifyPostRecovery(after Observation) (PostRecoveryOutcome, string) {
	armed := after.DriverPresent && after.DriverStateKnown && after.DriverArmed && !after.DriverObserveOnly
	agentBack := after.AgentStateKnown && after.AgentRunning

	if armed && agentBack {
		owner := "and has claimed the driver's policy ownership"
		if !after.DriverOwnerPresent {
			// Mid-startup, or a driver predating the arming handle. Either way there IS a process on the
			// redirect's far end, which is what separates this from the outage.
			owner = "though it has not claimed the driver's policy ownership yet (mid-startup, or a driver " +
				"predating the arming handle)"
		}
		return PostRecoverySteeringResumed, "the redirect is armed again and the DsseSteer service is running behind it " +
			owner + ". The agent came back — most likely the SCM's restart action — inside the recovery window, so " +
			"this box is STEERED and enforced, not black-holed. Recovery is not what is left in place here"
	}

	// The agent is not running (or its state is unreadable). Now armed means nothing is listening.
	if armed {
		if !after.AgentStateKnown {
			return PostRecoveryStillBroken, "the redirect is still armed and the service manager could not be " +
				"queried, so whether anything is listening behind it is unknown; reporting it as unrecovered rather " +
				"than assuming the good case"
		}
		return PostRecoveryStillBroken, "the redirect is STILL armed with no agent behind it: recovery ran and this " +
			"box is still refusing every connection"
	}
	if after.DriverPresent && !after.DriverStateKnown {
		return PostRecoveryStillBroken, "the WFP driver would not report its arming state after recovery, so the " +
			"redirect could not be confirmed clear; an unverified disarm is exactly what this component exists to catch"
	}
	// DNS residue only counts against the recovery while the agent is gone. If the agent is back it has re-taken
	// the resolver, and its backup file is supposed to be there.
	if !agentBack && after.DNSResidueKnown && after.DNSTakeoverResidue {
		return PostRecoveryStillBroken, "the resolver is still pointed at the dead agent: recovery ran and name " +
			"resolution on this box is still broken"
	}
	return PostRecoveryCleared, "both residues are gone: the redirect is not armed and the resolver was restored"
}

// AgentStateDirs lists the directories where the agent's own on-disk state (its DNS backup) would be, best
// first, from the two things this process can learn: the service's configured image path, and its own location.
//
// ★ This exists because the residue check must NOT depend on the agent binary being runnable. On win-dev-1 the
// two were the same lookup, so a box with a missing agent binary reported dns_residue_known=false — and an
// unknown residue degrades the decision to report_only, which made `cannot_recover` unreachable in exactly the
// state it was invented to name. The box really was orphaned and nothing said so.
//
// The service ImagePath still names WHERE the agent was installed even when os.Stat on it fails, and that is
// all the residue lookup needs. "Where did the agent live" and "what can I execute" are different questions
// with different failure modes, and collapsing them cost a real diagnosis.
func AgentStateDirs(serviceImageExe, watchdogExe string) []string {
	var dirs []string
	add := func(d string) {
		if d == "" || d == "." {
			return
		}
		for _, existing := range dirs {
			if strings.EqualFold(existing, d) { // Windows paths; C:\FOO and c:\foo are one directory
				return
			}
		}
		dirs = append(dirs, d)
	}
	add(windowsDir(serviceImageExe))
	add(windowsDir(watchdogExe))
	return dirs
}

// windowsDir is filepath.Dir for Windows paths, written here rather than taken from path/filepath so that the
// tests exercise real Windows shapes (`C:\Program Files\Lantern\DSSE\steer.exe`) on any host. filepath.Dir on
// a non-Windows test machine does not treat `\` as a separator and would return ".", which would have made
// this function's tests pass for the wrong reason and fail on the box that matters.
func windowsDir(p string) string {
	s := strings.TrimSpace(p)
	if s == "" {
		return ""
	}
	s = strings.TrimRight(s, `\/`)
	i := strings.LastIndexAny(s, `\/`)
	if i < 0 {
		return ""
	}
	// Keep the separator on a drive root (`C:\`), where dropping it would name the process's current directory
	// on that drive instead of its root.
	if i == 2 && len(s) >= 3 && s[1] == ':' {
		return s[:3]
	}
	return s[:i]
}

// EventThrottle decides whether a repeating condition should reach the Windows event log again.
//
// ★ Measured on win-dev-1: a box stuck in report_only wrote one event every 15 seconds — 240 an hour from one
// unchanged condition, burying the four IDs this design gave stable numbers to precisely so they could be
// matched. `recover` is self-limiting because acting changes the state; `report_only` and `cannot_recover` are
// not, and a channel nobody can read is the same silent failure as no channel at all.
//
// A condition is announced when it first appears, again whenever it CHANGES (a different action or a different
// sentence is new information), and again after ReassertAfter so a long-running problem does not age out of a
// collector's window. When it goes away, that is announced once too: a collector that saw the alert and never
// sees a resolution has to assume the box is still broken.
//
// The rolling FILE log is unaffected and still carries every tick. The two sinks answer different questions and
// only the event log has a bury problem.
type EventThrottle struct {
	// ReassertAfter re-announces an unchanged condition this often. Zero means never re-announce.
	ReassertAfter time.Duration

	current     string
	announcedAt time.Time
}

// Observe takes this tick's condition — empty meaning "nothing to report" — and returns whether to write it to
// the event log, plus the condition that has just cleared, if any.
func (t *EventThrottle) Observe(condition string, now time.Time) (emit bool, cleared string) {
	if condition == "" {
		if t.current == "" {
			return false, ""
		}
		was := t.current
		t.current = ""
		t.announcedAt = time.Time{}
		return false, was
	}
	if condition != t.current {
		t.current = condition
		t.announcedAt = now
		return true, ""
	}
	if t.ReassertAfter > 0 && now.Sub(t.announcedAt) >= t.ReassertAfter {
		t.announcedAt = now
		return true, ""
	}
	return false, ""
}

// ExecutableFromServiceCommandLine extracts the program path from a Windows service ImagePath.
//
// The watchdog needs this because it must LAUNCH the steering agent to recover, and it cannot assume what that
// binary is called. Verified on win-dev-1, 2026-08-09: the watchdog decided `recover` correctly and then failed
// with "dsse-steer.exe not found beside the watchdog", because that box was hand-deployed as `steer.exe`. A
// watchdog that detects the outage and cannot act on it is the failure it exists to prevent, so the name is now
// read from the service the watchdog is already querying rather than assumed.
//
// Handles the three forms an ImagePath actually takes: quoted (what the MSI writes, and required when the path
// contains spaces), unquoted, and the `\??\` kernel-style prefix used by driver services.
func ExecutableFromServiceCommandLine(cmdline string) string {
	s := strings.TrimSpace(cmdline)
	s = strings.TrimPrefix(s, `\??\`)
	if s == "" {
		return ""
	}
	if s[0] == '"' {
		if end := strings.IndexByte(s[1:], '"'); end >= 0 {
			return strings.TrimSpace(s[1 : 1+end])
		}
		return strings.TrimSpace(s[1:]) // unterminated quote: take the rest rather than nothing
	}
	// Unquoted. Splitting on the first space is wrong for `C:\Program Files\...\steer.exe --flag`, which
	// Windows itself resolves by probing; anchoring on the extension gets the common case right without
	// touching the filesystem. The program is always first, so the first .exe is it.
	if i := strings.Index(strings.ToLower(s), ".exe"); i >= 0 {
		return strings.TrimSpace(s[:i+len(".exe")])
	}
	if sp := strings.IndexByte(s, ' '); sp >= 0 {
		return s[:sp]
	}
	return s
}

// RecoveryLimiter bounds how often the watchdog will recover the same box.
//
// Without it, a box that re-enters the black hole immediately (a crash loop in the agent, say) would be
// recovered on every tick forever, and each recovery tears steering down again — so the machine would spend
// its life flapping between enforced and unenforced while the log filled with successes. A bound turns that
// into a stated, visible refusal to keep trying.
//
// This is NOT a kill switch and it never disables the agent: exceeding the bound means the watchdog stops
// ACTING and starts only reporting. The box keeps whatever state it is in.
type RecoveryLimiter struct {
	Max    int           // recoveries allowed inside Window
	Window time.Duration // rolling window
	times  []time.Time
}

// Allow records an attempt at time now and reports whether it may proceed.
func (l *RecoveryLimiter) Allow(now time.Time) (bool, string) {
	if l.Max <= 0 {
		return true, ""
	}
	cutoff := now.Add(-l.Window)
	kept := l.times[:0]
	for _, t := range l.times {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	l.times = kept
	if len(l.times) >= l.Max {
		return false, fmt.Sprintf("already recovered this box %d time(s) in the last %s; not recovering again. "+
			"Something is putting it back into the black hole faster than recovery can help, and repeating the "+
			"recovery would only flap enforcement on and off", len(l.times), l.Window)
	}
	l.times = append(l.times, now)
	return true, ""
}

// recoverOrAdmitItCannot turns "this box needs recovering" into either an instruction to do it or an admission
// that this process cannot, depending on whether the binary that performs recovery could be found.
//
// The distinction has to be made HERE, at decision time, and not discovered later when the recovery is
// attempted. On win-dev-1 the two were the same thing: the watchdog reported `recover`, tried, and failed with
// "not found" — and a dry run, which never reaches the attempt, reported `recover` and looked healthy. So the
// box carried a watchdog that could not save it, and nothing said so until it was needed. Resolving the tool
// as part of every observation means that gap is reported on the FIRST quiet tick instead of the worst one.
//
// The `why` is carried through unchanged: what is wrong with the box does not change because this process
// cannot fix it, and an operator reading the alert needs both halves — the outage AND the reason nothing is
// coming.
func (o Observation) recoverOrAdmitItCannot(why string) Decision {
	if o.RecoveryToolPath != "" {
		return Decision{ActionRecover, why}
	}
	detail := o.RecoveryToolErr
	if detail == "" {
		detail = "the steering agent binary could not be located"
	}
	return Decision{ActionCannotRecover, why + " — AND THIS WATCHDOG CANNOT FIX IT: " + detail +
		". A person has to intervene; recovery is `dsse-steer --mode recover` run elevated on this box"}
}
