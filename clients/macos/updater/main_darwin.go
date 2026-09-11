//go:build darwin

// Command dsse-updater (macOS) — the loop around the sequencing, running as root because that is the only
// place `installer -pkg -target /` can run.
//
//	dsse-updater --once            one pass, print the decision, and exit
//	dsse-updater --once --dry-run  one pass that will not install
//	dsse-updater --status          what this device would do, and why, touching nothing
//	dsse-updater --loop            run forever (what the LaunchDaemon invokes)
//	dsse-updater --rollback        put the previous version back (operator action; never the timer's)
//	dsse-updater --rollback --dry-run   what a rollback would do, installing nothing
//
// ★ WHY A SEPARATE PROCESS FROM THE EXTENSION, which is the obvious place to put it. The extension is what an
// update REPLACES. A component that installs its own replacement is waiting to be killed halfway through, and
// the half it would be killed in is the privileged one. The same split the Windows side runs, arrived at for
// the same reason.
//
// ★ AND WHY ROOT, stated because it is the uncomfortable part. `installer -pkg` needs it and an unattended
// update cannot prompt. So this is a root daemon whose input is a file another process writes — which is
// exactly why that file's authority is its SIGNATURE and not its location, why the pinned key lives here, and
// why the artifact's digest is re-checked immediately before launch. Every one of those is load-bearing
// because of what this process is allowed to do.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/agentupdate"
	"github.com/lantern-networks/dsse-core/clients/macos/updateplatform"
)

var (
	buildVersion = "0.0.0-dev"
	buildCommit  = "unknown"
)

func main() {
	once := flag.Bool("once", false, "evaluate once, print the decision, and exit")
	loop := flag.Bool("loop", false, "run continuously (the LaunchDaemon entry point)")
	status := flag.Bool("status", false, "print what this device would do and why, touching nothing")
	// ★ FOR A DEVICE WHERE THE "ALREADY REPORTED" ASSUMPTION IS KNOWN TO BE WRONG (2026-08-13, win-dev-1). A
	// journal from a build that predates the outcome counter is read as already reported — right for a build
	// that HAD a reporter, wrong for one whose outbox drain did not exist yet, and on that device the outcome
	// is suppressed for ever. Clearing the field by hand does not work: the next load re-adopts it, silently,
	// which is what turned this into an investigation instead of a line.
	reportAgain := flag.Bool("report-outcome-again", false, "clear an ASSUMED report marker so this device's last terminal outcome is queued for the fleet again. Refuses to touch a marker earned by a report that actually reached the outbox — clearing one of those would send the same outcome twice.")
	// ★ ROLLBACK IS A FLAG ON THIS BINARY AND NOT A MODE OF THE LOOP. The LaunchDaemon passes --loop and can
	// never reach this: an unattended process that decides on its own to walk a fleet backwards is a worse
	// failure than whatever it would be trying to fix. A person types this, on a device, as root.
	rollback := flag.Bool("rollback", false, "put the previous version back: install the package this device stored for the version it was running before its last update, refuse the version being left, and record it. With --dry-run, say what it would do and install nothing.")
	rollbackTo := flag.String("rollback-to", "", "roll back to this exact version instead of the one the journal names. It must be a version this device HOLDS a package for — the store bounds what this flag can do — and --status lists them.")
	dryRun := flag.Bool("dry-run", false, "go through the whole pass — fetch, verify, stage, check the digest, evaluate the freeze/wave/window — and stop immediately before launching the installer. Steering is not taken down and the journal is not written.")
	interval := flag.Duration("interval", 30*time.Minute, "how often to evaluate in --loop")
	updatePin := flag.String("update-pin", "", "Ed25519 public key (hex) the update MANIFEST is verified against. This is the authority to RUN CODE and is deliberately not the agent-policy key. Overrides the agent config; when both are empty this device can never update, and it says so on every pass.")
	planPin := flag.String("plan-pin", "", "Ed25519 public key (hex) the rollout PLAN is verified against — the agent-policy key. Overrides the agent config; when both are empty the plan is accepted unverified, which means the freeze is only as strong as the file's permissions.")
	configPath := flag.String("agent-config", updateplatform.AgentConfigPath(), "the agent configuration the signing keys are read from when no pin flag is given")
	// ★ WHAT AM I. Added 2026-08-13 after answering that question about a live device by noticing a log line was
	// MISSING from --status: the packaged updater was never stamped, so every device reported
	// 0.0.0-dev+unknown, and the age of the component that decides which code runs as root had to be inferred
	// from an absent sentence. One field, readable without root, is the whole fix.
	showVersion := flag.Bool("version", false, "print this build's version and commit, and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("dsse-updater %s+%s\n", buildVersion, buildCommit)
		return
	}

	u := &updater{
		manifestPath: filepath.Join(updateplatform.DataRoot, "update-manifest.json"),
		planPath:     filepath.Join(updateplatform.DataRoot, "update-plan.json"),
		journalPath:  filepath.Join(updateplatform.DataRoot, "update", "journal.json"),
		updateKeys:   splitKeys(*updatePin),
		planKeys:     splitKeys(*planPin),
		// The SAME configuration --status reports from, or the screen and the gate describe different files.
		platform:   &updateplatform.Platform{ConfigPath: *configPath},
		dryRun:     *dryRun,
		configPath: *configPath,
	}

	// ★ THE ORDINARY PATH IS THE CONFIG, NOT THE FLAGS. The LaunchDaemon passes only --loop, because the macOS
	// package is generic and the keys are tenant material that arrives in agent_config.json. The flags stay for
	// operating on a device by hand, and they WIN when given — a person at a terminal overriding the file is a
	// deliberate act; the file quietly overriding the person would not be.
	//
	// A config that cannot be read is reported, never treated as "no keys": those two states must never render
	// the same, which is exactly how this daemon shipped unable to update while looking configured.
	if len(u.updateKeys) == 0 {
		pins, err := updateplatform.LoadPins(*configPath)
		if err != nil {
			u.pinSource = fmt.Sprintf("★ the update-signing key could NOT be read from %s: %v", *configPath, err)
		} else {
			u.updateKeys = pins.Update
			u.pinSource = fmt.Sprintf("update key from the agent config %s (%d)", *configPath, len(pins.Update))
		}
	} else {
		u.pinSource = "update key from --update-pin"
	}
	// ★ The plan key comes from a DIFFERENT place, and deliberately. It is the agent-policy key, which already
	// reaches this device through the signed trust bundle and ROTATES there. Reading a hand-placed copy instead
	// would mean that the day the key rotates, every plan stops verifying and every device holds itself frozen —
	// safe, silent, and a fleet that has quietly stopped being updatable.
	if len(u.planKeys) == 0 {
		// u.updateKeys is what will actually verify a release here — the flag if one was given, the config
		// otherwise — and the separation rule has to be checked against THAT, not against the file alone.
		keys, src := updateplatform.PlanKeys(updateplatform.TrustAnchorPointerPath(), *configPath, u.updateKeys)
		u.planKeys = keys
		u.planSource = src
	} else {
		u.planSource = "--plan-pin"
	}

	// ★★ THE SEPARATION IS ENFORCED ONCE, OVER THE KEYS ACTUALLY IN FORCE (2026-08-13, thirty-first review #9).
	// It used to live inside PlanKeys and therefore covered only keys ADOPTED from the trust bundle: --plan-pin
	// skipped it entirely, and a config-supplied plan key was never compared against a flag-supplied update key.
	// So `--update-pin X --plan-pin X` was expressible, on a device whose plan carries the FREEZE — one key for
	// both means the party a halt exists to stop is the party who signs the halt.
	//
	// Here, after both sets are resolved, is the only place that sees every lane.
	if kept, refused := agentupdate.SeparatePlanKeys(u.updateKeys, u.planKeys); len(refused) > 0 {
		u.planKeys = kept
		u.planSource = fmt.Sprintf("★ REFUSED %d plan key(s) that are also this device's UPDATE-signing key: one "+
			"key signing both the release and the halt means a compromised release key can also unfreeze the "+
			"fleet (was: %s)", len(refused), u.planSource)
	}

	switch {
	case *reportAgain:
		os.Exit(agentupdate.ForgetAssumedOutcomeCommand(u.journalPath, os.Stdout, os.Stderr))
	case *status:
		u.printStatus()
	case *rollback || *rollbackTo != "":
		if !u.rollback(*rollbackTo, time.Now()) {
			os.Exit(1)
		}
	case *once:
		fmt.Println(u.pass(time.Now()).line())
	case *loop:
		u.run(*interval)
	default:
		fmt.Fprintln(os.Stderr, "dsse-updater: one of --once / --status / --loop / --rollback is required")
		os.Exit(2)
	}
}

// lockPath is the device-wide update lock. Beside the journal, because it guards the same thing the journal
// records — and because a lock in a temp directory is a lock that vanishes with a reboot cleanup and stops
// excluding anything.
// addressing is who this device is, when the running extension has recorded it. The platform interface does
// not carry it — it is a macOS marker detail — so this asks the concrete type and answers empty otherwise.
func (u *updater) addressing() (string, string) {
	if p, ok := u.platform.(*updateplatform.Platform); ok {
		return p.Addressing()
	}
	return "", ""
}

func (u *updater) lockPath() string { return filepath.Join(filepath.Dir(u.journalPath), "update.lock") }

type updater struct {
	manifestPath string
	planPath     string
	journalPath  string
	updateKeys   []string
	planKeys     []string
	platform     agentupdate.Platform
	dryRun       bool
	configPath   string // the agent configuration, kept so the publisher requirement can be stated at start
	pinSource    string // where the update key came from, so "unpinned" is never mistaken for "unconfigured"
	planSource   string // and where the plan key came from, which is a different place on purpose
}

// run is the LaunchDaemon's loop. The first pass happens immediately: a machine that has just booted is the
// one most likely to be behind, and waiting a full interval to find out delays every update by that much.
func (u *updater) run(interval time.Duration) {
	fmt.Printf("dsse-updater: started version=%s+%s interval=%s uid=%d\n",
		buildVersion, buildCommit, interval, os.Geteuid())
	if os.Geteuid() != 0 {
		// Said loudly and NOT fatally. A non-root loop still reports, and reporting a device that cannot
		// install is more useful than a daemon that refused to start and left nothing behind.
		fmt.Println("dsse-updater: ★ WARNING not running as root — every observation still works and no install " +
			"can. installer -pkg -target / needs root, which is why this belongs in a LaunchDaemon.")
	}
	// ★ THE PUBLISHER REQUIREMENT IS STATED AT START, because its ABSENCE is invisible in every other way: a
	// device that checks nobody's signature updates exactly as happily as one that does. Printed once per start
	// rather than once per pass — a line that repeats every fifteen minutes is a line people filter out, which is
	// the documented history of "no update-signing key is pinned".
	fmt.Printf("dsse-updater: package publisher: %s\n", updateplatform.DescribePublisherRequirement(u.configPath))
	for {
		fmt.Println(u.pass(time.Now()).line())
		time.Sleep(interval)
	}
}

// result is one pass, in the shape a log reader and a person both need.
type result struct {
	action string
	reason string
	notes  []string
}

func (r result) line() string {
	s := fmt.Sprintf("dsse-updater: version=%s+%s action=%s reason=%q", buildVersion, buildCommit, r.action, r.reason)
	for _, n := range r.notes {
		s += "\n  " + n
	}
	return s
}

// pass is one evaluation: close out anything outstanding, learn what should be installed, stage it, and let
// the shared sequencing decide.
//
// The ORDER is the content and it is the same on both platforms. Reconcile first, because an attempt that
// finished after the process that started it was replaced would otherwise be read as interrupted — and
// `executing` also means "check this box's network", so a successful update would raise that alarm every
// time. Staging before the gate, because a maintenance window spent downloading is a window that installed
// nothing.
func (u *updater) pass(now time.Time) result {
	// ★ HELD FOR THE WHOLE DECISION, from reading the journal to launching the installer. Every shorter window
	// has the same race inside it: the LaunchDaemon's pass and an operator's rollback both read the same idle
	// journal, both write a transition, and both hand a package to `installer`. One machine, two installs.
	//
	// NOT queued. An operator staring at a terminal while a thirty-minute daemon pass finishes learns nothing;
	// "something else is deciding right now" is available immediately and is the true answer.
	lock, lerr := agentupdate.LockDevice(u.lockPath())
	if lerr != nil {
		return result{action: "blocked", reason: fmt.Sprintf("not evaluating: %v", lerr)}
	}
	defer lock.Release()

	j, err := agentupdate.LoadJournal(u.journalPath)
	if err != nil {
		return result{action: "blocked", reason: fmt.Sprintf("not attempting anything: %v. Until this file is "+
			"readable or removed by hand, this device cannot be told apart from one whose previous update stopped "+
			"half way", err)}
	}

	var notes []string

	// 0. ★★ DRAIN WHAT IS ALREADY OWED, BEFORE ANYTHING CAN OVERWRITE IT (2026-08-13, thirtieth review #4).
	//
	// The journal holds ONE pending report. --rollback stacks the failure that prompted it into that slot — the
	// twenty-ninth review's fix, so the outcome that caused a rollback is not erased by the rollback — and the
	// entry point does not flush. Reconcile below then closes the landed rollback and calls MarkReportPending
	// again, which replaced the slot unconditionally. In the ordinary case, where a rollback completes inside
	// one tick, the preserved failure was gone and the fleet heard only "rolled_back": the fix's own outcome
	// deleted by the next pass through the same file.
	//
	// Draining first is the fix rather than refusing the overwrite, because the slot must describe the CURRENT
	// terminal state when it is flushed — MarkOutcomeReported records the journal's fingerprint at the moment
	// of the flush, not the report's. Keeping a stale report in the slot would mark the wrong outcome as
	// delivered. An empty slot cannot be overwritten.
	notes = u.flushPending(j, notes)

	// 1. Close out what the last pass could not observe.
	running, runErr := u.platform.RunningVersion()
	if changed, note := agentupdate.Reconcile(j, running, runErr, now); note != "" {
		notes = append(notes, note)
		if changed {
			// The journal is saved BEFORE the report is queued: a report describing a completion this device
			// would forget on the next boot would put the fleet view ahead of the device.
			// ★ THE OUTCOME IS IN THE SAME SAVE AS THE TRANSITION (2026-08-12, eleventh review). The terminal
			// phase used to be persisted first and the report built afterwards, so a crash between the two left
			// a journal that is no longer interrupted and an outcome nothing would ever regenerate.
			status := agentupdate.ReportInstalled
			if j.IsRollback() {
				status = agentupdate.ReportRolledBack
			}
			u.markPending(j, status, running, note, now)
			if !u.persist(j, "a completed attempt and the outcome it owes the fleet", &notes) && !u.dryRun {
				return result{action: "blocked", notes: notes,
					reason: "a completed attempt could not be recorded"}
			}
			notes = u.flushPending(j, notes)
			// Something progressed, so a refusal seen later is a new event rather than a repeat.
			if !u.dryRun {
				agentupdate.ClearRefusal(agentupdate.ReportsDir(u.journalPath))
			}

			// ★ THE SAME RULE, FROM THE SAME PLACE (2026-08-14, thirty-first review #11). This was the verbatim
			// twin of the Windows copy, written out here — as its previous comment said — "rather than left as a
			// difference nobody can see", after that rule shipped on Windows alone and the staged packages of
			// withdrawn releases accumulated on this platform for a round. Hoisting it is what stops the next
			// rule doing the same; only ClearStaged is platform-specific.
			for _, c := range agentupdate.StagedClears(j, u.dryRun) {
				if cerr := updateplatform.ClearStaged(c.Version); cerr != nil {
					notes = append(notes, agentupdate.StagedClearNote(c, cerr))
				}
			}
		}
	}

	// A terminal outcome that could not be queued on an earlier pass. Retried BEFORE anything else, so a device
	// whose disk was briefly full does not lose the record of an update it performed.
	// Anything a previous pass — or a previous PROCESS — left owed. Derived from the journal, so a crash
	// between the terminal save and the report is recovered here rather than lost.
	//
	// ★ NO `&& !u.dryRun` HERE, deliberately, and it used to have one (2026-08-12).
	// persist() is already wrapped for a rehearsal and markPending only touches memory, so the flag was
	// redundant — and it was not harmless: the identical block after Run carries no such flag, so a rehearsal
	// that noticed an owed outcome THERE said "would have queued a failed outcome" and one that noticed the
	// SAME fact HERE said nothing at all. Same rehearsal, same Mac, different amount of truth depending on
	// which line got there first. The guards that remain are the ones that change CONTROL FLOW rather than
	// suppress a write — see the stop below, which must not fire on a rehearsal.
	if j.OwesOutcomeReport() {
		u.markPending(j, agentupdate.TerminalReportStatus(j), running, "recovered: the outcome was recorded and never queued", now)
		u.persist(j, "an outcome left owed by an earlier pass", &notes)
	}
	// The SAME report is retried, so however many attempts it takes the Edge sees one event.
	notes = u.flushPending(j, notes)
	// ★ AND IF IT IS STILL OWED, THIS PASS STOPS (2026-08-12, eleventh review). The journal holds ONE pending
	// outcome, so carrying on meant a failure later in the same pass could overwrite one that had never been
	// delivered. Stopping keeps the older one, which is the one at risk.
	if j.PendingReport != nil && !u.dryRun {
		return result{action: "blocked", notes: notes,
			reason: "an earlier outcome is still waiting to reach the fleet view and could not be queued; this " +
				"pass stops rather than replacing it with a newer one"}
	}

	// 2. What should this device be running?
	m, merr := updateplatform.FileManifestSource{Path: u.manifestPath, TrustedKeys: u.updateKeys}.Fetch(context.Background(), now)
	if merr != nil {
		// ★ REPORTED (2026-08-12, seventh review). Windows queues this and macOS returned straight into local
		// classification, so a bad signature, an expired manifest or a substituted document lived in this
		// device's log and nowhere else — the fleet view stayed empty for exactly the case an operator would
		// most want surfaced. classifyManifestFailure decides whether it is worth an alarm locally; that is a
		// different question from whether the control plane should be told.
		outcome := u.classifyManifestFailure(merr, notes)
		// "idle" is the one case that is NOT a refusal: no manifest published for this device is not a device
		// that cannot update, and reporting it would fill the fleet view with devices nobody has released to.
		if outcome.action != "idle" {
			// The DOCUMENT identifies this refusal: an unverifiable manifest supplies no version this device
			// may believe, and without the digest a second substituted document would be suppressed as a
			// repeat of the first — exactly the sequence worth seeing.
			if !u.dryRun {
				// The digest of the bytes verification ACTUALLY rejected — not a re-read of the path, which a
				// courier can replace between the two.
				u.reportRefusalOf(j, updateplatform.RejectedDigest(merr), running,
					"the update manifest could not be used: "+merr.Error(), now)
			}
		}
		return outcome
	}

	// 3. The plan: the freeze, and this device's wave.
	// ★ The plan is judged against what this device is actually being offered, and against the newest plan it
	// has already accepted. Blind application let an old plan's open wave authorise a release it was never
	// computed for, and let a replayed pre-halt plan lift a freeze — see RolloutExpectation.
	device, tenant := u.addressing()
	rollout, rerr := updateplatform.LoadRollout(u.planPath, u.planKeys, now, agentupdate.RolloutExpectation{
		Version:        m.Version,
		NotBefore:      j.AcceptedPlanFloor(),
		MaxAge:         agentupdate.DefaultPlanMaxAge,
		DeviceIdentity: device,
		TenantID:       tenant,
	})
	if rerr != nil {
		// NOT fatal, and not ignored either: LoadRollout answers a damaged plan with a FREEZE, and that answer
		// is the one that has to reach the gate. Returning here would abort the pass and leave the device
		// unfrozen — the exact inversion the freeze exists to prevent.
		notes = append(notes, "rollout plan: "+rerr.Error())
	}
	if rollout.Frozen && rollout.FrozenReason != "" {
		notes = append(notes, "rollout frozen: "+rollout.FrozenReason)
	}
	if rollout.WaveWithheld != "" {
		notes = append(notes, "wave withheld: "+rollout.WaveWithheld)
	}
	// The ratchet moves only for a plan that was actually read and understood. A plan that froze this device
	// BECAUSE it could not be verified must not also raise the floor — that would let one damaged document
	// lock out every later one.
	//
	// ★ AND A DRY RUN DOES NOT PERSIST IT (2026-08-12, found on win-dev-1 and checked here because the Windows
	// side said to). --dry-run's own help says "the journal is not written"; this Save is OUTSIDE Run, so it
	// was written anyway — and the floor is ONE-WAY by design, which is what makes it a replay defence, so
	// nothing undoes it. Measured on Windows: a rehearsal against a plan generated 00:46:58Z, then a real pass
	// with the fleet's current plan from 00:42:19Z, and the device FROZE itself as a replay against a control
	// plane doing nothing wrong. The operator who reached for the mode that touches nothing is the one who
	// halted the machine.
	//
	// Accepted in memory either way, so the pass stays self-consistent and judges this plan as current;
	// persisted only when the pass is real.
	if !rollout.PlanGeneratedAt.IsZero() && rerr == nil && j.AcceptPlanFloor(rollout.PlanGeneratedAt) {
		u.persist(j, "the accepted-plan floor "+rollout.PlanGeneratedAt.UTC().Format(time.RFC3339), &notes)
	}

	// ★ ALREADY RUNNING IT? STOP HERE (2026-08-12, eighth review, same as the Windows tick). Applicable is
	// evaluated inside Run, which is AFTER staging — so the pass that had just deleted the staged package for a
	// completed update went straight on to download it again, every thirty minutes, for as long as that
	// release stayed published. With the artifact source down it went further and recorded a stage FAILURE
	// against the version this Mac is already running: a refusal about a release that had nothing wrong with it.
	//
	// Only the "same version" case is short-circuited; every other reason Applicable can refuse still goes
	// through Run, where an operator can see it.
	if aerr := m.Applicable(running, agentupdate.PlatformDarwin, updateplatform.CurrentArch()); errors.Is(aerr,
		agentupdate.ErrNotAnUpgrade) {
		return result{action: "idle", notes: notes,
			reason: fmt.Sprintf("this device is running %s and %s is not newer: nothing to do", running, m.Version)}
	}

	// 4. Bytes on disk, before the window opens. Skipped for MDM delivery, where the management system holds
	// the payload and DSSE must not become a second download path for a privileged install.
	if m.Delivery == agentupdate.DeliveryMDM {
		return result{action: "mdm_report", notes: notes,
			reason: fmt.Sprintf("%s is authorised for this device and is delivered by MDM, not by DSSE. This "+
				"device is running %q; DSSE will report the difference and install nothing", m.Version, running)}
	}
	// ★ STAGED EVEN IN A DRY RUN (corrected 2026-08-11). This used to be skipped for --dry-run, whose own help
	// text promised "fetch, verify and stage as normal" — so the one safe rehearsal of an update did not
	// exercise the download or the digest check, the two things most likely to be wrong before a maintenance
	// window. It then called through to the sequencing anyway, where an open window would have reached the
	// launch with nothing staged. A rehearsal that skips the risky part proves nothing about it.
	//
	// ★ EXCEPT WHEN THE FLEET IS FROZEN (2026-08-11, observed while verifying that a freeze reaches a device).
	// The rehearsal argument and the window argument both say "have the bytes ready before the window opens".
	// A frozen fleet has no window that will open. A release withdrawn because it is bad was still being
	// downloaded by every device, every tick — harmless, since nothing installs it and the digest is checked
	// anyway, and still the wrong behaviour to leave in: "we halted it" and "every endpoint keeps fetching it"
	// should not both be true, and an operator reading the traffic would reasonably conclude the halt had not
	// taken.
	//
	// The pass still calls Run, so the gate records the hold and the journal says why this device is waiting.
	// Skipping the pass entirely would leave a frozen fleet with no record of being frozen.
	if rollout.Frozen {
		notes = append(notes, "not staging: this fleet is frozen, and there is no window for the bytes to be ready for")
	} else if _, serr := updateplatform.Stage(context.Background(), nil, m); serr != nil {
		// Reportable: unlike a missing manifest, this device HAS been told to update and cannot. A fleet
		// stuck here looks identical to one that was never targeted unless it says so.
		// ★ REPORTED, ONCE PER DISTINCT REFUSAL (2026-08-12, sixth review). This device HAS been told to update
		// and cannot — the exact state an operator needs to see — and it used to return here without queuing
		// anything, so a fleet stuck on unstageable artifacts still read `total: 0`. The fingerprint keeps it
		// from sending the same sentence every thirty minutes.
		why := fmt.Sprintf("could not stage the %s artifact, so the update cannot proceed: %v", m.Version, serr)
		if !u.dryRun {
			u.reportRefusal(j, m.Version, running, why, now)
		}
		return result{action: "stage_failed", notes: notes, reason: why}
	}

	// 5. The sequencing decides.
	plan := updateplatform.DefaultPlan().Apply(rollout)
	out, rerr2 := agentupdate.Run(j, m, agentupdate.Config{
		Window:      plan.Window(),
		MaxAttempts: plan.MaxAttempts,
		Platform:    agentupdate.PlatformDarwin,
		Arch:        updateplatform.CurrentArch(),
		// FALSE, and it is the same finding as DisarmBeforeUpdate: an app-proxy provider that stops is one the
		// system stops routing to, so an interrupted install leaves no residue and the operator must be sent to
		// look at the version that is running, not at this Mac's network.
		SteeringSurvivesAgent: false,
		Frozen:                rollout.Frozen,
		EligibleSince:         rollout.EligibleSince,
		// The rehearsal goes through the SAME sequencing and stops one step short of the installer.
		DryRun: u.dryRun,
	}, u.platform, func(jj *agentupdate.Journal) error { return jj.Save(u.journalPath) }, now)
	// ★ A NEW FAILURE IS AN EVENT THE FLEET NEEDS; A REPEATED REFUSAL IS NOT. The report is emitted on a
	// journal TRANSITION — a failure count that moved during this pass — rather than on every pass that finds
	// itself unable to proceed. Otherwise a poisoned device would send the same sentence every thirty minutes
	// forever and the fleet view would be mostly noise, which is its own way of hiding an outage.
	// ★ A FAILURE IS OBSERVED ONCE TOO (2026-08-12, tenth review). The transition used to be read by comparing
	// against a snapshot taken THIS pass, so once the counter had moved the next pass saw no change — a failed
	// outcome whose queue failed was gone for good.
	// ★ DERIVED FROM THE JOURNAL, NOT FROM THIS PASS (2026-08-12, twelfth review). Run persists PhaseFailed
	// internally and returns, so a crash between its save and this one lost the event, for the same reason.
	// OwesOutcomeReport asks the FILE — a fingerprint of the terminal state against the one already reported —
	// so the answer survives the process. The in-pass comparison is gone rather than left unused: an exported
	// helper that answers "was there a new failure" is how this window gets reopened.
	if j.OwesOutcomeReport() {
		u.markPending(j, agentupdate.TerminalReportStatus(j), running, j.LastFailureReason, now)
		u.persist(j, "a terminal attempt and the outcome it owes the fleet", &notes)
	}
	notes = u.flushPending(j, notes)
	if rerr2 != nil {
		return result{action: "blocked", notes: notes,
			reason: fmt.Sprintf("the update was abandoned because its record could not be kept: %v", rerr2)}
	}
	return result{action: out.Action, reason: out.Reason, notes: notes}
}

// reportRefusal queues a standing refusal, at most once per distinct reason.
//
// A refusal repeats by nature — every tick, until something changes — so reporting it like an event would
// bury the fleet view in repetition, and NOT reporting it leaves the devices an operator most needs to see
// invisible. The fingerprint is the middle: a different refusal is a new event, the same one is not.
func (u *updater) reportRefusalOf(j *agentupdate.Journal, digest, running, reason string, now time.Time) {
	u.refusal(j, "", digest, running, reason, now)
}

func (u *updater) reportRefusal(j *agentupdate.Journal, version, running, reason string, now time.Time) {
	u.refusal(j, version, "", running, reason, now)
}

func (u *updater) refusal(j *agentupdate.Journal, version, digest, running, reason string, now time.Time) {
	dir := agentupdate.ReportsDir(u.journalPath)
	r := agentupdate.ReportOutcome(j, agentupdate.ReportRefused, running, reason, now)
	// ★ THE VERSION BEING REFUSED IS THE ONE BEING OFFERED (2026-08-12, seventh review). Staging and manifest
	// verification both happen BEFORE Run captures anything into the journal, so an ordinary journal still
	// names the PREVIOUS target — and only filling this in when empty meant a device running 0.2.7 that could
	// not stage 0.2.8 reported a refusal of 0.2.7. A sentence about the wrong release is worse than none.
	// ★ NOTHING INHERITED (2026-08-12, seventh and eighth reviews). Staging and manifest verification both run
	// BEFORE Run captures anything into the journal, so an ordinary journal still names the PREVIOUS target —
	// and a refusal that kept it reported a failure against a release that had nothing wrong with it. When
	// there is no trustworthy version (an unverifiable manifest names one this device must not believe) BOTH
	// fields are cleared rather than left describing the last good update.
	r.TargetVersion, r.FromVersion = strings.TrimSpace(version), ""
	r.RejectedDigest = digest
	device, tenant := u.addressing()
	r.DeviceID, r.TenantID = device, tenant
	// Stored FIRST, suppression marker only after the file is durably in place — the other order leaves this
	// device permanently silent about a refusal it never managed to record.
	if _, err := agentupdate.AppendRefusal(dir, r, agentupdate.RefusalFingerprint(version+digest, reason)); err != nil {
		fmt.Fprintf(os.Stderr, "dsse-updater: this refusal could NOT be queued for the fleet view: %v\n", err)
	}
}

// report queues one terminal outcome for the component that can actually send it.
//
// ★ THE UPDATER DOES NOT SPEAK TO THE EDGE, AND THAT IS THE DESIGN (2026-08-12). It runs as root and launches
// installers; handing it the device's (T) client certificate would put the credential that proves this
// machine's identity inside the process most likely to be replaced mid-execution. The network extension
// already holds that identity and already beats on a timer, so it sends what is written here.
//
// Best-effort, deliberately: a device that cannot write a report has still performed the update, and failing
// an update over its bookkeeping would be the worse trade. A write failure is said out loud rather than
// swallowed, because "the fleet view is empty" and "nothing happened" must not look the same from here either.
// persist is every durable write this pass makes, in one place.
//
// ★ --dry-run PROMISED "the journal is not written" AND WROTE IT (2026-08-12, found on win-dev-1, checked here
// because they said to, and it was worse here than the one thing they found). Three side effects escaped the
// flag: the accepted-plan floor (a ONE-WAY replay defence — a rehearsal against a plan slightly ahead of the
// fleet's froze the device on its next real pass), the journal saves around reconciliation, and reports queued
// into the outbox, which the Edge counts.
//
// A rehearsal must be able to reach every decision and change nothing. So the writes go through here, and a
// dry pass says what it WOULD have written instead of writing it.
func (u *updater) persist(j *agentupdate.Journal, what string, notes *[]string) bool {
	if u.dryRun {
		*notes = append(*notes, "rehearsal: would have recorded "+what)
		return false
	}
	if err := j.Save(u.journalPath); err != nil {
		*notes = append(*notes, "could not record "+what+": "+err.Error())
		return false
	}
	return true
}

// recordOutcome queues a terminal outcome, and when that fails stores the REPORT ITSELF in the journal so the
// next pass retries the same one — same id, so it counts once however many attempts it takes.
// markPending puts the outcome in the journal. The caller saves it — in the SAME save as the terminal
// transition — so a crash cannot land between the two.
func (u *updater) markPending(j *agentupdate.Journal, status, running, reason string, now time.Time) {
	report := agentupdate.ReportOutcome(j, status, running, reason, now)
	device, tenant := u.addressing()
	report.DeviceID, report.TenantID = device, tenant
	// IfFree, so the older owed outcome keeps the single slot and the one that cannot be held is COUNTED on
	// the device rather than discarded in silence. The callers used to spell that guard out themselves and the
	// loss went unrecorded — thirty-first review, 2026-08-14.
	j.MarkReportPendingIfFree(report)
}

// flushPending queues whatever the journal owes the fleet and clears it once the outbox has it. Nothing is
// built fresh here: the same report is retried, so the Edge sees one event however many attempts it takes.
func (u *updater) flushPending(j *agentupdate.Journal, notes []string) []string {
	if j.PendingReport == nil {
		return notes
	}
	if u.dryRun {
		return append(notes, "rehearsal: would have queued a "+j.PendingReport.Status+" outcome")
	}
	if err := agentupdate.AppendReport(agentupdate.ReportsDir(u.journalPath), j.PendingReport.Report); err != nil {
		// ★★ AND IT DOES NOT RETRY FOR EVER (2026-08-13, thirty-first review #10, gate 4). A pass STOPS while an
		// outcome is owed, so a device that could not queue one — a full disk, a permissions change — could
		// never update again. Not late: never. After DefaultReportMaxAttempts the outcome is quarantined, said
		// out loud, and the device is released to keep taking security fixes.
		if quarantined := j.RecordReportQueueFailure(err.Error(), agentupdate.DefaultReportMaxAttempts,
			time.Now().UTC()); quarantined {
			u.persist(j, "that an outcome was given up on", &notes)
			return append(notes, "★ GAVE UP queueing a terminal outcome after "+
				fmt.Sprint(agentupdate.DefaultReportMaxAttempts)+" attempts ("+err.Error()+") — the fleet will "+
				"never hear about it, and this device is released so it can go on updating. See --status.")
		}
		u.persist(j, "a failed attempt to queue an outcome", &notes)
		return append(notes, "a terminal outcome could not be queued for the fleet view; the report is held in "+
			"the journal and the next pass will retry THAT report, so it counts once")
	}
	j.ClearReportPending()
	j.ClearReportQueueFailures()
	j.MarkOutcomeReported()
	u.persist(j, "that the pending outcome is queued", &notes)
	return notes
}

// queue is the same rule for the outbox: a rehearsal must not put an outcome in front of the fleet.
func (u *updater) queue(j *agentupdate.Journal, status, running, reason string, now time.Time,
	notes *[]string) bool {
	if u.dryRun {
		*notes = append(*notes, "rehearsal: would have queued a "+status+" outcome for the fleet view")
		return false
	}
	return u.report(j, status, running, reason, now)
}

// report queues one terminal outcome and reports whether it is durably in the outbox.
func (u *updater) report(j *agentupdate.Journal, status, running, reason string, now time.Time) bool {
	// Built FROM THE JOURNAL, which is the only place from_version lives — building it by hand here is how
	// that field ended up populated only by tests.
	r := agentupdate.ReportOutcome(j, status, running, reason, now)
	device, tenant := u.addressing()
	r.DeviceID, r.TenantID = device, tenant
	if err := agentupdate.AppendReport(agentupdate.ReportsDir(u.journalPath), r); err != nil {
		fmt.Fprintf(os.Stderr, "dsse-updater: this outcome (%s %s) could NOT be queued for the fleet view: %v\n",
			status, r.TargetVersion, err)
		return false
	}
	return true
}

// rollback is the operator's recovery path: put back the version this device came from. It reports whether
// the command did what was asked.
//
// ★ NO MANIFEST, NO PLAN, NO KEYS, NO GATE — and every one of those absences is deliberate. A rollback runs
// when the control plane published something bad, or when a device's agent is broken and cannot be assessed;
// requiring a verified manifest would mean the recovery path depends on the same publishing that caused the
// incident, and requiring a maintenance window would mean a broken box waits until 02:00. What bounds this
// instead is the store: only a package this device already holds can be installed, and only by root.
//
// The freeze is the fleet-wide half of the same decision and is NOT a substitute — it stops the next device
// from taking the bad release and does nothing for the ones already on it.
func (u *updater) rollback(to string, now time.Time) bool {
	// The same lock as a pass, for the same reason: the daemon may be mid-decision on this device right now.
	lock, lerr := agentupdate.LockDevice(u.lockPath())
	if lerr != nil {
		fmt.Fprintf(os.Stderr, "dsse-updater: not rolling back: %v. The updater daemon evaluates every 30 minutes "+
			"and an install may be starting; try again in a moment\n", lerr)
		return false
	}
	defer lock.Release()

	j, err := agentupdate.LoadJournal(u.journalPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dsse-updater: not rolling back: %v. Until this file is readable or removed by hand, "+
			"this device cannot be told apart from one whose previous update stopped half way\n", err)
		return false
	}
	if os.Geteuid() != 0 {
		// Said before anything is attempted rather than as an installer error two steps later: the whole command
		// needs root, and a person who typed it without sudo should be told that and not something else.
		fmt.Fprintf(os.Stderr, "dsse-updater: rolling back needs root (uid=%d). Try: sudo %s --rollback\n",
			os.Geteuid(), os.Args[0])
		return false
	}

	// ★ WHAT THIS DEVICE IS ESCAPING, FROM WHERE IT SURVIVES A DEAD AGENT (2026-08-13, twenty-seventh review).
	// macOS passed no LeavingVersion, so on the machine a rollback exists FOR — a crash-looping extension, a
	// stale or missing runtime marker — nothing was poisoned: Rollback ran with running="" and leaving="",
	// Refuse was never called, and the next thirty-minute pass reinstalled the very build the operator had just
	// backed out of. The installed bundle answers when the running agent cannot.
	out, rerr := agentupdate.Rollback(j, agentupdate.RollbackRequest{
		ToVersion:      to,
		LeavingVersion: updateplatform.InstalledVersion(),
	}, agentupdate.Config{
		Platform: agentupdate.PlatformDarwin,
		Arch:     updateplatform.CurrentArch(),
		DryRun:   u.dryRun,
	}, u.platform, func(jj *agentupdate.Journal) error { return jj.Save(u.journalPath) }, now)
	if rerr != nil {
		fmt.Fprintf(os.Stderr, "dsse-updater: the rollback was abandoned because its record could not be kept: %v\n", rerr)
		return false
	}
	fmt.Printf("dsse-updater: version=%s+%s action=%s reason=%q\n", buildVersion, buildCommit, out.Action, out.Reason)
	if out.Action == agentupdate.ActionRollingBack {
		// ★ "Handed to the installer" is not "running the old version again", and this is the same distinction
		// the install path had to learn: the receipt and the running code are different facts. So the command
		// says what still has to be confirmed, and where.
		fmt.Println("  The installer is running. Confirm it LANDED — do not assume it from this line:")
		fmt.Printf("    sudo %s --status     # running version, and journal phase=%s once confirmed\n",
			os.Args[0], agentupdate.PhaseRolledBack)
		fmt.Println("  The system extension has to restart before it reports its version, so give it a minute.")
	}
	return out.Action != agentupdate.ActionRefused
}

func (u *updater) classifyManifestFailure(err error, notes []string) result {
	switch {
	case isNoManifest(err):
		return result{action: "idle", reason: "no update is published for this device", notes: notes}
	case isRejected(err):
		// The loud one. A manifest that does not verify is either a broken release or a substitution, and both
		// need a person — so this must never read like "nothing published".
		return result{action: "unverified", notes: notes,
			reason: fmt.Sprintf("★ REFUSED an update manifest: %v. Nothing was installed, which is the safe "+
				"outcome, but a manifest that does not verify needs looking at now", err)}
	default:
		return result{action: "blocked", reason: fmt.Sprintf("nothing was attempted on this device: %v", err), notes: notes}
	}
}

// printStatus answers the question actually asked about a device that has not updated, which is never "what
// version is it" but "what is this box waiting for".
func (u *updater) printStatus() {
	fmt.Printf("dsse-updater %s+%s (uid=%d)\n", buildVersion, buildCommit, os.Geteuid())
	fmt.Printf("  manifest        : %s\n", u.describeManifest())
	fmt.Printf("  pinned keys     : update=%d plan=%d\n", len(u.updateKeys), len(u.planKeys))
	// ★ WHERE the keys came from, always. "0 keys" was already printed before this change and was still not
	// enough: it did not distinguish a device nobody configured from one whose config could not be read, and
	// the fix for those two is not the same.
	fmt.Printf("  update key from : %s\n", u.pinSource)
	fmt.Printf("  plan key from   : %s\n", u.planSource)
	// ★ The OTHER key, the one this device does not hold: who signed the package itself. A device may be
	// perfectly pinned for manifests and still install anything the manifest names, which is the state every
	// Mac was in until 2026-08-13.
	fmt.Printf("  package publisher: %s\n", updateplatform.DescribePublisherRequirement(u.configPath))
	if j, jerr := agentupdate.LoadJournal(u.journalPath); jerr == nil {
		if line := j.DescribeQuarantine(); line != "" {
			// Printed where an operator is already looking. An outcome the fleet never heard about is
			// discoverable here or only by subtraction from a report that does not mention it.
			fmt.Printf("  %s\n", line)
		}
	}
	if len(u.updateKeys) == 0 {
		fmt.Println("  ★ WARNING no update-signing key is pinned, so this device can NEVER update.")
	}
	if v, err := u.platform.RunningVersion(); err == nil {
		fmt.Printf("  running version : %s\n", v)
	} else {
		fmt.Printf("  running version : UNKNOWN — %v\n", err)
	}
	c := u.platform.Conditions(time.Now())
	fmt.Printf("  conditions      : in_use=%t (known=%t) idle=%s (known=%t) ac=%t (known=%t)\n",
		c.InUse, c.InUseKnown, c.IdleFor.Round(time.Second), c.IdleKnown, c.OnACPower, c.PowerKnown)
	fmt.Printf("  %s\n", updateplatform.DescribeSessions())

	// The SAME expectation a pass uses, or --status would answer a different question from the one that matters.
	var floor time.Time
	if j, jerr := agentupdate.LoadJournal(u.journalPath); jerr == nil {
		floor = j.AcceptedPlanFloor()
		// ★ AND WHAT THE FLEET WILL NEVER BE TOLD (2026-08-14, thirty-first review). There is one pending slot;
		// when a second terminal outcome arrives while the first is still owed, the older one keeps it and the
		// newer is counted rather than dropped in silence. Printed here because a counter nobody can read is
		// the same shortfall one layer along — the fleet view of this device is incomplete and this is the only
		// place that says so.
		if j.DroppedOwedOutcomes > 0 {
			fmt.Printf("  ★ OUTCOMES LOST : %d — this device reached a terminal outcome while it still owed an "+
				"earlier one, and holds room for one. The fleet will never hear about them (most recent: %s)\n",
				j.DroppedOwedOutcomes, j.LastDroppedOwedOutcome)
		}
	}
	sdevice, stenant := u.addressing()
	statusExp := agentupdate.RolloutExpectation{NotBefore: floor, MaxAge: agentupdate.DefaultPlanMaxAge,
		DeviceIdentity: sdevice, TenantID: stenant}
	src := updateplatform.FileManifestSource{Path: u.manifestPath, TrustedKeys: u.updateKeys}
	if m, merr := src.Fetch(context.Background(), time.Now()); merr == nil {
		statusExp.Version = m.Version
	}
	r, rerr := updateplatform.LoadRollout(u.planPath, u.planKeys, time.Now(), statusExp)
	fmt.Printf("  rollout plan    : %s\n", r.Source)
	if rerr != nil {
		fmt.Printf("                    %v\n", rerr)
	}
	if r.Frozen {
		fmt.Printf("  ★ FROZEN        : %s\n", r.FrozenReason)
	}
	if r.WaveWithheld != "" {
		fmt.Printf("  ★ WAVE WITHHELD : %s\n", r.WaveWithheld)
	}
	if !r.EligibleSince.IsZero() {
		fmt.Printf("  wave opens      : %s (%s)\n", r.EligibleSince.Format(time.RFC3339), r.Plan.WaveReason)
	}
	// ★ THE PLAN THIS DEVICE ACTUALLY HOLDS, including when it was generated.
	//
	// Added after answering "why is this device still refusing?" required base64-decoding the plan file by
	// hand. The answer was that the device held a plan generated six minutes before the operator changed it —
	// entirely correct behaviour, indistinguishable from a broken one without this line. A status command that
	// omits the inputs to the decision makes every timing question look like a bug.
	w := updateplatform.DefaultPlan().Apply(r).Window()
	fmt.Printf("  window in force : %s-%s local, idle>=%dm, unattended=%v, ac=%v, deadline=%dd\n",
		w.LocalStart, w.LocalEnd, w.RequireIdleMinutes, w.RequireUnattended, w.RequireACPower, w.DeadlineDays)
	if g := strings.TrimSpace(r.Plan.GeneratedAt); g != "" {
		fmt.Printf("  plan generated  : %s (a change made after this is not here yet — the courier refreshes every 15m)\n", g)
	} else {
		fmt.Printf("  plan generated  : (not stated — this is the built-in default, not a plan from the control plane)\n")
	}
	if j, err := agentupdate.LoadJournal(u.journalPath); err == nil {
		kind := ""
		if j.IsRollback() {
			kind = " kind=ROLLBACK"
		}
		fmt.Printf("  journal         : phase=%s target=%q%s poisoned=%v\n", j.Phase, j.TargetVersion, kind, j.PoisonedVersions())
		if j.LastFailureReason != "" {
			// ★ Printed unconditionally rather than only for a poisoned version: the sentence that matters most
			// here — steering was taken down and could not be restored — is written on the FIRST failure, and a
			// device is unprotected from that moment, not from the third.
			fmt.Printf("  last failure    : %s\n", j.LastFailureReason)
		}
		// ★ AN OPEN PHASE THAT IS ACTUALLY FINISHED, said out loud (2026-08-11, read off this Mac seconds after
		// the first successful rollback). The device was RUNNING 0.2.4, the rollback had landed — and this line
		// said phase=rolling_back, because only a pass reconciles and the next one was up to thirty minutes away.
		//
		// Correct, and unreadable at the one moment it is read: someone checking whether a rollback worked, during
		// the incident that caused it, sees the phase for "an installer is running" on a machine where nothing is.
		//
		// Reconciled against a COPY so this stays what it claims to be — a command that touches nothing. What it
		// reports is the arithmetic the next pass will do, not a fact it has established.
		if interrupted, _ := j.Interrupted(); interrupted {
			if running, rerr := u.platform.RunningVersion(); rerr == nil {
				if changed, note := agentupdate.Reconcile(j.Copy(), running, nil, time.Now()); changed {
					fmt.Printf("                    ↳ already finished: %s\n", note)
					fmt.Printf("                      (the next pass records it; `--once` does it now)\n")
				} else if note != "" {
					fmt.Printf("                    ↳ %s\n", note)
				}
			}
		}
		// ★ WHAT A ROLLBACK WOULD DO, printed BEFORE anyone needs it. The question "can this device go back" has
		// to be answerable on a good day: during the incident the answer arrives too late to change anything, and
		// a device with no stored package is one that has to be recovered by hand.
		fmt.Printf("  rollback would  : %s\n", u.describeRollback(j))
	} else {
		fmt.Printf("  journal         : UNREADABLE — %v\n", err)
	}

	// ★ A live downgrade authorisation is worth seeing. It should exist only in the seconds between the updater
	// launching a rollback and the package's preinstall consuming it; one still here later means a rollback that
	// never reached the installer, and it is the single file that can talk this product's downgrade guard down.
	if in, err := updateplatform.ReadIntent(updateplatform.IntentPath()); err == nil {
		state := "live"
		if in.Expired(time.Now()) {
			state = "EXPIRED (it authorises nothing; the preinstall refuses and deletes it)"
		}
		fmt.Printf("  ★ downgrade authorisation present: to=%s issued=%s expires=%s — %s\n",
			in.ToVersion, in.IssuedAt, in.ExpiresAt, state)
	}
}

// describeRollback answers, in one line, what `--rollback` would install and whether it could.
func (u *updater) describeRollback(j *agentupdate.Journal) string {
	held, herr := updateplatform.DefaultRollbackStore().List()
	var names []string
	for _, e := range held {
		names = append(names, e.Version)
	}
	inventory := "none stored"
	switch {
	case herr != nil:
		inventory = fmt.Sprintf("the store could not be listed (%v)", herr)
	case len(names) > 0:
		inventory = "held: " + strings.Join(names, ", ")
	}

	target := strings.TrimSpace(j.FromVersion)
	if j.IsRollback() {
		return fmt.Sprintf("★ nothing automatically — the last attempt was itself a rollback to %s, so from_version "+
			"(%s) is the build already abandoned. Name a version with --rollback-to. (%s)",
			j.TargetVersion, j.FromVersion, inventory)
	}
	if target == "" {
		return fmt.Sprintf("★ nothing — this device has never recorded a version to come back from. (%s)", inventory)
	}
	if _, err := u.platform.RestoreMaterialFor(target); err != nil {
		// ★ The reason is quoted and NOT summarised. An earlier version of this line said "this device holds no
		// package for it" and then printed a reason that began "this device holds a package for it and cannot
		// install it" — a sentence containing its own refutation, read off this Mac. There are two distinct
		// states here (no package at all, and a package that predates the authorisation) and the caller below
		// knows which; restating either from up here can only get it wrong.
		return fmt.Sprintf("★ NOTHING — it would go to %s and cannot: %v (%s)", target, err, inventory)
	}
	return fmt.Sprintf("install %s, and refuse the version it leaves on this device. (%s)", target, inventory)
}

func (u *updater) describeManifest() string {
	m, err := updateplatform.FileManifestSource{Path: u.manifestPath, TrustedKeys: u.updateKeys}.
		Fetch(context.Background(), time.Now())
	switch {
	case isNoManifest(err):
		return "none published for this device (nothing to install; this is the ordinary state)"
	case isRejected(err):
		return fmt.Sprintf("★ REFUSED — %v. Nothing will be installed, which is safe, but a manifest that does "+
			"not verify is either a broken release or a substitution and needs looking at now", err)
	case err != nil:
		return fmt.Sprintf("could not be read from %s: %v", u.manifestPath, err)
	}
	s := fmt.Sprintf("verified, offering %s for %s/%s, delivery=%s, valid until %s",
		m.Version, m.Platform, m.Arch, m.Delivery, m.NotAfter)
	if m.Delivery == agentupdate.DeliveryMDM {
		s += " — DSSE will NOT install this one; the MDM delivers it and DSSE only reports what landed"
	}
	return s
}

// isNoManifest / isRejected keep the classification in one place. They are wrappers rather than inline
// errors.Is calls because the two are the difference between a quiet device and one that needs a person
// tonight, and a reader should be able to find both answers together.
func isNoManifest(err error) bool { return errors.Is(err, updateplatform.ErrNoManifest) }
func isRejected(err error) bool   { return errors.Is(err, updateplatform.ErrManifestRejected) }

func splitKeys(s string) []string {
	var out []string
	for _, k := range strings.Split(s, ",") {
		if k = strings.TrimSpace(k); k != "" {
			out = append(out, k)
		}
	}
	return out
}
