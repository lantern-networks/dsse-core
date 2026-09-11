// tick.go — one pass of the updater, and the thing agentupdate.Run cannot do for itself.
//
// Run owns the ordering of a single attempt. It does not fetch, it does not stage, and — the part that
// matters most here — it cannot observe its own outcome, because Execute launches the installer DETACHED and
// returns while the journal still says `executing`. This process may then be replaced by that very installer.
//
// SO SOMEBODY HAS TO CLOSE THE LOOP, and it was nobody.
//
// The next pass calls Run, Run checks Interrupted() first, and `executing` is an interrupted phase — so a
// perfectly successful update reports "a previous attempt stopped in phase executing and never finished".
// Worse, `executing` also satisfies NeedsNetworkRecovery(), so the sentence carries "this box's NETWORK must
// be checked before anything else is attempted on it". That fires on the HAPPY PATH, every time, and an alarm
// that rings on success is how people learn to ignore the one that matters.
//
// Reconcile is the fix, and the whole trick is that the outcome is knowable after the fact: if the agent is
// now running the version the attempt was moving to, the attempt worked. Nothing else can produce that.
package updateplatform

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/agentupdate"
)

// Reconcile moved to agentupdate: see agentupdate.Reconcile.
//
// It was always a pure decision about a journal — no Windows in it — and macOS needs the identical one. Two
// copies of "did the attempt that replaced this process actually land" is two chances to disagree about
// whether a device updated, and the wrong answer either way is expensive: a false yes closes an attempt that
// failed, a false no re-runs one that succeeded.

// ManifestSource supplies the signed manifest this device should act on.
//
// An interface rather than a concrete control-plane client, because where the manifest comes from is a
// transport question — the updater is a separate service from the agent and does not automatically hold the
// agent's mTLS material — and that is a decision to make deliberately rather than to bury in a tick loop. It
// also lets the ordering below be tested without a network.
type ManifestSource interface {
	// Fetch returns the manifest already VERIFIED against the trusted update keys (agentupdate.Open). It
	// returns ErrNoManifest when this device has nothing to do.
	Fetch(ctx context.Context, now time.Time) (agentupdate.Manifest, error)
}

// ErrNoManifest means the control plane published nothing for this device. It is a normal, quiet outcome and
// must not read as a failure: most ticks on most devices produce it.
var ErrNoManifest = errors.New("updateplatform: no manifest published for this device")

// TickDeps is everything one pass needs, injected so the ordering can be tested.
type TickDeps struct {
	Source      ManifestSource
	Platform    agentupdate.Platform
	Config      agentupdate.Config
	JournalPath string
	// ManifestPath is the envelope file, used ONLY to identify a document that would not verify — the refusal
	// for one has no version to name it by. Empty simply omits the digest.
	ManifestPath string
	HTTP         *http.Client
	// Load and Save are indirected for tests; nil uses the real journal file at JournalPath.
	Load func(path string) (*agentupdate.Journal, error)
	Save func(j *agentupdate.Journal, path string) error
	// ResolveRollout judges the couriered plan against the manifest THIS PASS is acting on, and returns what it
	// decided together with the maintenance window that plan implies. Nil leaves Config as the caller set it.
	//
	// ★ IT IS A CALLBACK BECAUSE THE MANIFEST MUST BE READ ONCE (2026-08-11, second review). The caller used to
	// fetch the manifest to judge the plan, and Tick then fetched it AGAIN — with the courier free to replace
	// the file in between. A wave opened for manifest A could authorise the install of manifest B, which is the
	// same "two documents, no binding" defect the plan checks exist to close, reintroduced by where they were
	// wired. One fetch, inside the lock, handed to both.
	ResolveRollout func(m agentupdate.Manifest) agentupdate.Rollout
	// ResolveWindow turns the same decision into this pass's maintenance window.
	//
	// ★ IT IS HERE BECAUSE THE WINDOW USED TO ARRIVE A TICK LATE (2026-08-11, third review). The caller applied
	// the new window to ITS copy of the config after Tick had already taken one, so a plan that closed the
	// window still allowed one install in the window it had just closed — the tick that learned about the
	// change was the tick that ignored it.
	ResolveWindow func(r agentupdate.Rollout) agentupdate.MaintenanceWindow
}

// TickResult is what one pass did, for the log and the event record.
type TickResult struct {
	Outcome    agentupdate.Outcome
	Reconciled bool
	// Notes are the sentences worth recording even when nothing happened.
	Notes []string
	// Reports are the terminal outcomes this tick produced. They are ALREADY QUEUED in the outbox by the time
	// this returns — the field is what happened, not a list for the caller to write.
	//
	// ★ THE APPEND BELONGS INSIDE THE LOCK (2026-08-12, eighth review). The caller used to write them after
	// Tick returned, which is after the device lock is released: the service and a hand-run --once could both
	// read a missing suppression marker, both return, and both then append the same refusal. The whole
	// check-append-mark sequence is one operation and it happens where the exclusion already is.
	//
	// ★ WHY THE TICK DOES NOT SEND THEM. The updater deliberately holds no network identity: it runs as
	// LocalSystem and launches msiexec, and handing it the device client certificate would put the credential
	// that proves this machine's identity inside the process most likely to be replaced mid-execution. So it
	// writes, and DsseSteer — which already holds that certificate and already beats on a timer — sends.
	Reports []agentupdate.Report
}

// Tick runs one pass: reconcile what is outstanding, learn what should be installed, get it on disk verified,
// and let Run decide.
//
// The ORDER is the content. Reconcile comes first so a completed attempt is closed before Run can misread it
// as interrupted. Staging comes before Run because Run's Execute assumes a verified package is already on
// disk — and staging early means the artifact is present and checked long before the maintenance window, so
// the window is spent installing rather than downloading.
// LockPath is the device-wide update lock for this endpoint: beside the journal, guarding the same thing the
// journal records.
func LockPath(journalPath string) string {
	return filepath.Join(filepath.Dir(journalPath), "update.lock")
}

func Tick(ctx context.Context, d TickDeps, now time.Time) (TickResult, error) {
	// ★ HELD FOR THE WHOLE DECISION. The service ticks on a timer and an operator can run --once or a rollback
	// at the same moment; both would read the same idle journal and both would start an installer. Atomic
	// journal writes prevent a torn file and prevent nothing about two processes acting at once.
	lock, lerr := agentupdate.LockDevice(LockPath(d.JournalPath))
	if lerr != nil {
		return TickResult{Outcome: agentupdate.Outcome{Action: agentupdate.ActionNone,
			Reason: "not evaluating: " + lerr.Error()}}, nil
	}
	defer lock.Release()

	var res TickResult

	load := d.Load
	if load == nil {
		load = agentupdate.LoadJournal
	}
	save := d.Save
	if save == nil {
		save = func(j *agentupdate.Journal, path string) error { return j.Save(path) }
	}
	// ★ A REHEARSAL REACHES EVERY DECISION AND CHANGES NOTHING (2026-08-12, tenth review). Run has honoured
	// DryRun internally from the start — it clones the journal and no-ops the save — and everything AROUND it
	// did not: a dry pass could save a completed phase, queue an outcome the Edge then counts, clear the
	// refusal marker and DELETE the staged installer. The plan-floor fix closed one of five.
	//
	// Wrapped once, here, rather than a flag each new write has to remember: that is the flag that gets
	// forgotten, and it was.
	if d.Config.DryRun {
		save = func(*agentupdate.Journal, string) error { return nil }
	}
	dry := d.Config.DryRun

	j, err := load(d.JournalPath)
	if err != nil {
		return res, fmt.Errorf("read the update journal: %w", err)
	}
	if j == nil {
		j = agentupdate.NewJournal()
	}

	// 0. ★★ DRAIN WHAT IS ALREADY OWED, BEFORE ANYTHING CAN OVERWRITE IT (2026-08-13, thirty-first review #1 —
	// the macOS twin of this landed a round earlier and this side did not, which is the one-OS family again).
	//
	// The journal holds ONE pending report. --rollback stacks the failure that prompted it into that slot, so
	// the outcome that caused a rollback is not erased by the rollback, and the rollback entry point does not
	// flush. Reconcile below then closes the landed rollback and calls MarkReportPending again, which replaces
	// the slot unconditionally: in the ordinary case, where a rollback completes inside one tick, the preserved
	// failure is gone and the fleet hears only "rolled_back".
	//
	// Draining first rather than refusing the overwrite, because the slot must describe the CURRENT terminal
	// state when it is flushed — MarkOutcomeReported records the journal's fingerprint at the moment of the
	// flush, not the report's — so keeping a stale report would mark a different outcome as delivered. An empty
	// slot cannot be overwritten.
	res.Reports, res.Notes = flushPendingReport(res.Reports, res.Notes, d.JournalPath, j, save, dry)

	// 1. Close out anything outstanding, BEFORE Run can misread it.
	running, runErr := d.Platform.RunningVersion()
	if changed, note := agentupdate.Reconcile(j, running, runErr, now); note != "" {
		res.Notes = append(res.Notes, note)
		if changed {
			res.Reconciled = true
			status := agentupdate.ReportInstalled
			if j.IsRollback() {
				status = agentupdate.ReportRolledBack
			}
			// ★ ONE SAVE CARRIES BOTH, AND THE MARK COMES FIRST (2026-08-12, eleventh through thirteenth
			// reviews). The terminal phase was persisted and the report built AFTERWARDS — so a crash between
			// them left a journal that is no longer interrupted and an outcome nothing would regenerate; and
			// then, when the pending report was added, it was still marked after that save, so a failure to
			// save AFTER a successful append left neither the pending report nor the ReportedOutcome on disk.
			// The next process rebuilt the outcome with a NEW id, which is precisely what the Edge's
			// de-duplication cannot see through.
			//
			// So: mark, save, then queue. After that save the device either owes the outcome or has recorded
			// that it does not, and nothing in between is a state a restart can land in.
			j.MarkReportPending(agentupdate.ReportOutcome(j, status, running, note, now))
			if err := save(j, d.JournalPath); err != nil {
				return res, fmt.Errorf("record the completed attempt: %w", err)
			}
			res.Reports, res.Notes = flushPendingReport(res.Reports, res.Notes, d.JournalPath, j, save, dry)
			// Something progressed: a refusal seen later is a new event, not a repeat of the old one.
			if !dry {
				agentupdate.ClearRefusal(agentupdate.ReportsDir(d.JournalPath))
			}

			// ★ THE RULE LIVES IN agentupdate.StagedClears (2026-08-14, thirty-first review #11). It used to be
			// spelled out here and again, verbatim, in the macOS updater — because it shipped on Windows first
			// and was carried across by hand a round later. A rule written per platform is one that will next be
			// changed on one of them, and the platform that misses it is silent: a privileged installer piling up
			// at a predictable root-only path says nothing. Only the deletion is platform-specific now.
			for _, c := range agentupdate.StagedClears(j, dry) {
				if cerr := ClearStaged(c.Version); cerr != nil {
					res.Notes = append(res.Notes, agentupdate.StagedClearNote(c, cerr))
				}
			}
		}
	}

	// A terminal outcome that could not be queued on an earlier pass. Retried BEFORE anything else, so a box
	// whose disk was briefly full does not lose the record of an update it performed — and the SAME report is
	// retried, so however many attempts it takes the Edge sees one event.
	// Anything a previous pass — or a previous PROCESS — left owed. Derived from the journal, so a crash
	// between the terminal save and the report is recovered here rather than lost.
	//
	// ★ NO `&& !dry` HERE, deliberately, and it used to have one. The save above is already wrapped for a
	// rehearsal, so the flag was redundant — and it was not harmless: the identical block after Run has no such
	// flag, so a rehearsal that noticed an owed outcome THERE said "would have queued a failed outcome" and one
	// that noticed it HERE said nothing at all. The same rehearsal, told or not told depending on which line
	// spotted the same fact.
	//
	// It is also the pattern the wrapper exists to remove: the comment above says "wrapped once, rather than a
	// flag each new write has to remember", and this was such a flag. The guards that remain are the ones that
	// change CONTROL FLOW rather than suppress a write — see the stop below, which must not fire on a
	// rehearsal.
	// IfFree: the older owed outcome keeps the single slot, and the one that cannot be held is COUNTED on the
	// device instead of being dropped without a word (thirty-first review, 2026-08-14).
	if j.OwesOutcomeReport() {
		j.MarkReportPendingIfFree(agentupdate.ReportOutcome(j, agentupdate.TerminalReportStatus(j), running, j.LastFailureReason,
			now))
		if serr := save(j, d.JournalPath); serr != nil {
			res.Notes = append(res.Notes, "an outcome left owed by an earlier pass could not be recorded: "+serr.Error())
		}
	}
	res.Reports, res.Notes = flushPendingReport(res.Reports, res.Notes, d.JournalPath, j, save, dry)
	// ★ AND IF IT IS STILL OWED, THIS PASS STOPS (2026-08-12, eleventh review). The journal holds ONE pending
	// outcome, so carrying on meant a new failure later in the same pass could overwrite an outcome that had
	// never been delivered. Stopping keeps the older one, which is the one at risk; the next tick retries it
	// and then proceeds normally.
	if j.PendingReport != nil && !dry {
		res.Outcome = agentupdate.Outcome{Action: agentupdate.ActionNone,
			Reason: "an earlier outcome is still waiting to reach the fleet view and could not be queued; this " +
				"pass stops rather than replacing it with a newer one"}
		return res, nil
	}

	// 2. What should this device be running? ONE fetch, inside the lock, used by every decision below.
	m, err := d.Source.Fetch(ctx, now)
	if errors.Is(err, ErrNoManifest) {
		res.Outcome = agentupdate.Outcome{Action: agentupdate.ActionNone, Reason: "no manifest published for this device"}
		return res, nil
	}
	if err != nil {
		// A manifest that will not verify is a device that CANNOT be updated, and it used to leave the fleet
		// view unchanged — indistinguishable from a device with nothing to do. Same once-per-refusal rule.
		// The DOCUMENT identifies this refusal: an unverifiable manifest supplies no version this box may
		// believe, and without the digest a second substituted document is suppressed as a repeat of the first.
		if !dry {
			// The digest of the bytes verification ACTUALLY rejected — not a re-read of the path, which a
			// courier can replace between the two.
			res.Reports = appendRefusalOf(res.Reports, d.JournalPath, j, RejectedDigest(err),
				running, "the update manifest could not be used: "+err.Error(), now)
		}
		return res, fmt.Errorf("fetch the update manifest: %w", err)
	}

	// 3. The plan, judged against THIS manifest — and the ratchet raised inside the lock, where the journal is
	// already being read and written. Doing it in the caller left a read-modify-save outside every exclusion.
	if d.ResolveRollout != nil {
		r := d.ResolveRollout(m)
		d.Config.Frozen, d.Config.EligibleSince, d.Config.PlanHold = r.Frozen, r.EligibleSince, r.WaveWithheld
		if d.ResolveWindow != nil {
			d.Config.Window = d.ResolveWindow(r)
		}
		if r.Frozen && strings.TrimSpace(r.FrozenReason) != "" {
			res.Notes = append(res.Notes, "rollout frozen: "+r.FrozenReason)
		}
		if r.WaveWithheld != "" {
			res.Notes = append(res.Notes, "wave withheld: "+r.WaveWithheld)
		}
		// ★ A REHEARSAL MUST NOT RAISE THE RATCHET, and it did. Measured on win-dev-1 2026-08-12: a
		// `--once --dry-run` — the command whose own help says "the journal is not written" — accepted a plan
		// floor of 00:46:58Z and PERSISTED it. The next pass was handed a legitimate plan generated at
		// 00:42:19Z, refused it as a replay, and the device went to `waiting: rollout is frozen`.
		//
		// A dry run froze the box. The floor is one-way by design — that is what makes it a replay defence —
		// so nothing undoes it, and the operator who reached for the mode that touches nothing is the one who
		// halted the machine against a control plane doing nothing wrong.
		//
		// Accepted in memory so the pass stays self-consistent (this plan is judged as current within it) and
		// not written, which is the whole distinction the flag promises.
		if !r.PlanGeneratedAt.IsZero() && j.AcceptPlanFloor(r.PlanGeneratedAt) && !d.Config.DryRun {
			if serr := save(j, d.JournalPath); serr != nil {
				res.Notes = append(res.Notes, "could not record which plan this device has accepted: "+serr.Error())
			}
		}
	}

	// ★ ALREADY RUNNING IT? STOP HERE (2026-08-12, eighth review). Applicable was evaluated inside Run, which
	// is AFTER staging — so the tick that had just deleted the staged installer for a completed update went
	// straight on to download it again, every interval, for as long as that release stayed published. And when
	// the artifact source was down it went further and recorded a stage FAILURE against the version this box
	// is already running successfully: a refusal about a release that had nothing wrong with it.
	//
	// Checked here, before Stage touches the network, and only for the "same version" case: every other reason
	// Applicable can refuse (wrong platform, wrong arch, a min_from_version this box predates) still goes
	// through Run, which records them where an operator can see them.
	if aerr := m.Applicable(running, d.Config.Platform, d.Config.Arch); errors.Is(aerr, agentupdate.ErrNotAnUpgrade) {
		res.Outcome = agentupdate.Outcome{Action: agentupdate.ActionNone,
			Reason: fmt.Sprintf("this device is running %s and %s is not newer: nothing to do", running, m.Version)}
		return res, nil
	}

	// 4. Get it on disk, verified. Deliberately before the gate: an artifact staged days ahead means the
	// maintenance window is spent installing rather than downloading, and a download that fails is discovered
	// in daylight rather than at 02:00.
	//
	// ★ EXCEPT WHEN THE FLEET IS FROZEN (2026-08-11, observed on macOS while verifying that a freeze reaches a
	// device — the same ordering is here). Both arguments for staging early say "have the bytes ready before the
	// window opens", and a frozen fleet has no window that will open. A release withdrawn because it is bad was
	// still being downloaded by every device on every tick: harmless, since nothing installs it, and still not
	// something to leave in — "we halted it" and "every endpoint keeps fetching it" should not both be true.
	//
	// Run is still called, so the gate records the hold and the journal says why this device is waiting.
	if d.Config.Frozen {
		res.Notes = append(res.Notes, "not staging: this fleet is frozen, and there is no window for the bytes to be ready for")
	} else if _, serr := Stage(ctx, d.HTTP, m); serr != nil {
		if errors.Is(serr, ErrDeliveryNotOurs) {
			res.Notes = append(res.Notes, "this manifest is MDM-delivered; DSSE is not fetching or installing it. "+
				"★ What DSSE establishes here is the VERSION the running agent reports, not the bytes: the "+
				"authorised digest is published and nothing on this endpoint compares it")
			res.Outcome = agentupdate.Outcome{Action: agentupdate.ActionNone, Reason: "delivery is the MDM's"}
			return res, nil
		}
		// ★ Run is NOT called without the bytes, and this is a correction to the first version of this file.
		//
		// The intent there was right — "reporting could not stage while silently not evaluating would hide a
		// poisoned version or a device that has been waiting a month" — and the consequence was not. Run's
		// order is capture, DISARM, execute, so it only discovers the package is missing AFTER steering has
		// been taken down. Measured: with a valid window and a download that 500s, the platform calls are
		// [capture DISARM execute] and the outcome is `refused`. A failed download therefore unsteers the
		// device, and three of them poison a version that was never the problem. The original test did not
		// catch it because its Config had an empty window, so the gate refused before Run reached capture.
		//
		// What the intent wanted is kept without paying that: the journal facts that would otherwise be
		// hidden are reported here explicitly, since they are the reason Run was being called at all.
		res.Outcome = agentupdate.Outcome{
			Action: agentupdate.ActionRefused,
			Reason: fmt.Sprintf("not attempting %s: the artifact could not be staged (%v). Steering is deliberately "+
				"left up — handing this to the update sequencing would take it down before discovering the package "+
				"is absent%s", m.Version, serr, journalContext(j, m)),
		}
		res.Notes = append(res.Notes, "could not stage "+m.Version+": "+serr.Error())
		// ★ REPORTED, ONCE PER DISTINCT REFUSAL (2026-08-12, sixth review). This box HAS been told to update and
		// cannot — the exact state an operator needs to see — and this path returned without queuing anything,
		// so a fleet stuck on unstageable artifacts still read `total: 0`. The fingerprint keeps it from
		// sending the same sentence every interval.
		if !dry {
			res.Reports = appendRefusal(res.Reports, d.JournalPath, j, m.Version, running,
				"could not stage "+m.Version+": "+serr.Error(), now)
		}
		return res, nil
	}

	// 4. Let Run decide. Everything dangerous about the ordering is in there.
	out, err := agentupdate.Run(j, m, d.Config, d.Platform, func(jj *agentupdate.Journal) error {
		return save(jj, d.JournalPath)
	}, now)
	// ★ DERIVED FROM THE JOURNAL, NOT FROM THIS PASS (2026-08-12, twelfth review). The question used to be
	// "did the failure count move while I was looking" — NewFailureSince, against a snapshot taken this pass —
	// and Run persists PhaseFailed internally before returning, so a crash between its save and this one lost
	// the event: the next pass compared two identical snapshots and saw nothing to report. OwesOutcomeReport
	// asks the FILE instead. A terminal state whose fingerprint has not been marked reported still owes an
	// outcome, whoever is running and however many restarts ago it happened.
	//
	// The snapshot that fed the old comparison is gone with it. It was still being taken — a full journal copy
	// on every pass — and assigned to nothing.
	//
	// A REPEATED REFUSAL IS STILL NOT AN EVENT: the fingerprint is what makes this fire once per terminal
	// state, so a poisoned device does not send the same sentence every interval forever.
	// IfFree: the older owed outcome keeps the single slot, and the one that cannot be held is COUNTED on the
	// device instead of being dropped without a word (thirty-first review, 2026-08-14).
	if j.OwesOutcomeReport() {
		j.MarkReportPendingIfFree(agentupdate.ReportOutcome(j, agentupdate.TerminalReportStatus(j), running, j.LastFailureReason,
			now))
		if serr := save(j, d.JournalPath); serr != nil {
			res.Notes = append(res.Notes, "a terminal attempt could not be recorded for the fleet view: "+serr.Error())
		}
	}
	res.Reports, res.Notes = flushPendingReport(res.Reports, res.Notes, d.JournalPath, j, save, dry)
	if err != nil {
		return res, err
	}
	res.Outcome = out
	return res, nil
}

// appendRefusal queues a standing refusal at most once per distinct reason.
//
// A refusal repeats by nature — every tick, until something changes — so reporting it like an event would bury
// the fleet view in repetition, and NOT reporting it leaves the boxes an operator most needs to see invisible.
func appendRefusalOf(reports []agentupdate.Report, journalPath string, j *agentupdate.Journal,
	digest, running, reason string, now time.Time) []agentupdate.Report {
	return refuse(reports, journalPath, j, "", digest, running, reason, now)
}

func appendRefusal(reports []agentupdate.Report, journalPath string, j *agentupdate.Journal,
	version, running, reason string, now time.Time) []agentupdate.Report {
	return refuse(reports, journalPath, j, version, "", running, reason, now)
}

func refuse(reports []agentupdate.Report, journalPath string, j *agentupdate.Journal,
	version, digest, running, reason string, now time.Time) []agentupdate.Report {
	dir := agentupdate.ReportsDir(journalPath)
	fingerprint := agentupdate.RefusalFingerprint(version+digest, reason)
	if agentupdate.RefusalAlreadyReported(dir, fingerprint) {
		return reports
	}
	r := agentupdate.ReportOutcome(j, agentupdate.ReportRefused, running, reason, now)
	r.Fingerprint = fingerprint
	// ★ THE VERSION BEING REFUSED IS THE ONE BEING OFFERED (2026-08-12, seventh review). Staging runs BEFORE
	// Run captures the new manifest into the journal, so an ordinary journal still names the PREVIOUS target —
	// and the old code only filled this in when it was empty. A device running 0.2.7 that could not stage
	// 0.2.8 reported a refusal of 0.2.7, which is a sentence about the wrong release.
	// ★ THE VERSION BEING REFUSED, AND NOTHING INHERITED (2026-08-12, seventh and eighth reviews). Staging and
	// manifest verification both run BEFORE Run captures anything into the journal, so an ordinary journal
	// still names the PREVIOUS target — and a refusal that kept it reported a failure against a release that
	// had nothing wrong with it. When there is no trustworthy version (an unverifiable manifest names one this
	// device must not believe) BOTH fields are cleared rather than left to describe the last good update.
	r.TargetVersion, r.FromVersion = strings.TrimSpace(version), ""
	r.RejectedDigest = digest
	// Stored FIRST, marker only after it is durably in place, and all of it inside the device lock this
	// function is called under.
	if _, aerr := agentupdate.AppendRefusal(dir, r, fingerprint); aerr != nil {
		return reports
	}
	return append(reports, r)
}

// recordOutcome queues a terminal outcome, and when that fails stores the REPORT ITSELF in the journal so the
// next pass retries the same one.
//
// ★ EVERY TERMINAL OUTCOME IS OBSERVED EXACTLY ONCE. Reconcile is the only writer of PhaseCompleted and
// NewFailureSince only fires on the pass where the counter moves — so an outbox error, on either path, used to
// be the end of that event. The journal is what survives a crash, so the report goes there.

// flushPendingReport queues the outcome the journal is holding, and clears it once the outbox has it.
//
// The report is in the journal BEFORE this runs — written in the same save as the terminal transition — so
// every path through here either delivers it or leaves it owed. Nothing is built fresh: the same report is
// retried, so the Edge sees one event however many attempts it takes.
func flushPendingReport(reports []agentupdate.Report, notes []string, journalPath string,
	j *agentupdate.Journal, save func(*agentupdate.Journal, string) error, dry bool) ([]agentupdate.Report,
	[]string) {
	if j.PendingReport == nil {
		return reports, notes
	}
	if dry {
		return reports, append(notes, "rehearsal: would have queued a "+j.PendingReport.Status+" outcome")
	}
	before := len(reports)
	reports = queueReport(TickResult{Reports: reports}, journalPath, j.PendingReport.Report)
	if len(reports) == before {
		// ★★ AND IT DOES NOT RETRY FOR EVER (2026-08-13, thirty-first review #10, gate 4). A tick STOPS while an
		// outcome is owed, so a device that could not queue one — a full disk, a permissions change — could
		// never update again. Not late: never. After DefaultReportMaxAttempts the outcome is quarantined, said
		// out loud, and the device is released so it can go on taking security fixes.
		if j.RecordReportQueueFailure("the outbox refused the report", agentupdate.DefaultReportMaxAttempts,
			time.Now().UTC()) {
			_ = save(j, journalPath)
			return reports, append(notes, fmt.Sprintf("★ GAVE UP queueing a terminal outcome after %d attempts — "+
				"the fleet will never hear about it, and this device is released so it can go on updating",
				agentupdate.DefaultReportMaxAttempts))
		}
		_ = save(j, journalPath)
		return reports, append(notes, "a terminal outcome could not be queued for the fleet view; the report is "+
			"held in the journal and the next pass will retry THAT report, so it counts once")
	}
	j.ClearReportPending()
	j.ClearReportQueueFailures()
	j.MarkOutcomeReported()
	if serr := save(j, journalPath); serr != nil {
		return reports, append(notes, "the pending outcome was queued and the journal could not be updated ("+
			serr.Error()+"): it will be sent again, and the Edge de-duplicates it by id because the SAME report "+
			"is retried")
	}
	return reports, notes
}

// queueReport writes one outcome to the outbox and records it in the result. Inside the device lock, like
// everything else here: two processes appending the same pass's outcomes is the race the lock exists for.
func queueReport(res TickResult, journalPath string, r agentupdate.Report) []agentupdate.Report {
	if err := agentupdate.AppendReport(agentupdate.ReportsDir(journalPath), r); err != nil {
		return res.Reports
	}
	return append(res.Reports, r)
}

// journalContext adds the standing facts a staging failure would otherwise bury: a version this device has
// already given up on, and how long it has been waiting. Both were the reason the first version of this file
// called Run anyway, and both are cheap to state directly.
func journalContext(j *agentupdate.Journal, m agentupdate.Manifest) string {
	if j == nil {
		return ""
	}
	var extra []string
	if poisoned, why := j.IsPoisoned(m.Version); poisoned {
		extra = append(extra, fmt.Sprintf("note that %s is already poisoned on this device (%s), so staging it "+
			"would not have helped", m.Version, why))
	}
	if j.AttemptStartedAt != "" {
		if started, err := time.Parse(time.RFC3339, j.AttemptStartedAt); err == nil {
			extra = append(extra, fmt.Sprintf("this device has been waiting for %s since %s",
				m.Version, started.UTC().Format(time.RFC3339)))
		}
	}
	if len(extra) == 0 {
		return ""
	}
	return "; " + strings.Join(extra, "; ")
}
