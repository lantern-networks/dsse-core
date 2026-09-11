package agentupdate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/lantern-networks/dsse-core/durablefile"
	"sync"
	"time"
)

// journal.go — the updater's memory across its own death.
//
// The failure this exists for is the one where "roll back to the previous version" has nothing to roll back
// to: the installer was killed, or the power went, part-way through. The process that would report that
// failure is the process that failed, so the state has to live outside it.
//
// Three properties follow, and each is a decision rather than an implementation detail.
//
// It is written BEFORE each transition, not after. A journal that records what finished cannot distinguish
// "never started" from "started and died", and those need opposite responses.
//
// It lives outside the update payload. Under INSTALLDIR or inside the .app it would be destroyed by the very
// update it is tracking — the record and the thing it records must not share a fate.
//
// It counts failures per target version, and stops. Combined with a maintenance window, an update that fails
// every time is a machine for breaking a fleet at the same hour every night; the ceiling turns that into a
// stated refusal.

// SchemaJournal is the on-disk schema marker.
const SchemaJournal = "dsse_agent_update_journal.v1"

// Phase is where an update attempt had got to. The names are the state machine's, so a journal read during an
// incident uses the same vocabulary as the design.
type Phase string

const (
	PhaseIdle          Phase = "idle"
	PhaseVerified      Phase = "verified"       // manifest + artifact check passed; waiting on the gate
	PhaseSnapshotted   Phase = "snapshotted"    // restore material captured
	PhaseDisarmed      Phase = "disarmed"       // steering deliberately taken down before handing to the installer
	PhaseExecuting     Phase = "executing"      // the installer is running; NOBODY may assume anything about the box
	PhaseRollingBack   Phase = "rolling_back"   // the installer for the PREVIOUS version is running, deliberately
	PhaseObserving     Phase = "observing"      // installer returned; confirming the running version changed
	PhaseCompleted     Phase = "completed"      // the new code is running
	PhasePendingReboot Phase = "pending_reboot" // installed, not in effect until a restart
	PhaseFailed        Phase = "failed"
	PhaseRolledBack    Phase = "rolled_back"
	PhaseUnrecoverable Phase = "unrecoverable" // neither version runs; the box was put back on its native network
)

// interruptedPhases are the phases from which a fresh start means the previous attempt died mid-flight.
//
// `disarmed` and `executing` are the dangerous pair: steering is down, or the installer was mid-run. Finding
// either at startup means the box may be in a state nobody chose. `snapshotted` is included because restore
// material was captured and then nothing happened with it — harmless, but it is still an attempt that did not
// finish, and treating it as normal would hide a crash loop that never reaches the installer.
// `rolling_back` is in the same class as `executing` and for the identical reason: an installer is running and
// nothing may be assumed about the box until something observes what came back up. That it is the OLD package
// changes who chose it, not what state the machine is in while it runs.
var interruptedPhases = map[Phase]bool{
	PhaseSnapshotted: true,
	PhaseDisarmed:    true,
	PhaseExecuting:   true,
	PhaseRollingBack: true,
	PhaseObserving:   true,
}

// inFlightPhases are the phases entered once this attempt has started CHANGING the machine. Entering the first
// of them is what starts the InstallGrace clock — see InFlightSince.
//
// `snapshotted` is deliberately NOT here, though it is an interrupted phase: capturing restore material touches
// nothing an installer could still be finishing, so an attempt stuck there has genuinely stalled and should not
// be given the benefit of the doubt.
var inFlightPhases = map[Phase]bool{
	PhaseDisarmed:    true,
	PhaseExecuting:   true,
	PhaseRollingBack: true,
}

// Journal is the persisted record. One per device.
type Journal struct {
	Schema string `json:"schema"`
	// TargetVersion is the version the current/most recent attempt is moving to.
	TargetVersion string `json:"target_version,omitempty"`
	// FromVersion is what was running when the attempt began — the thing a rollback goes back to.
	FromVersion string `json:"from_version,omitempty"`
	Phase       Phase  `json:"phase"`
	UpdatedAt   string `json:"updated_at"`
	// AttemptStartedAt is when this device became eligible and started WAITING. It is the deadline clock and
	// the EligibleSince fallback — not a measure of how long an installer has been running.
	AttemptStartedAt string `json:"attempt_started_at,omitempty"`
	// InFlightSince is when the machine actually started being changed: the first disarm, execute, or rollback
	// of this attempt.
	//
	// ★ IT IS SEPARATE FROM AttemptStartedAt BECAUSE THEY ANSWER DIFFERENT QUESTIONS, AND CONFLATING THEM
	// REPORTED SUCCESSFUL UPDATES AS FAILURES (2026-08-14, measured on win-dev-1). InstallGrace stops a
	// just-launched installer from being called interrupted, and it was measured from AttemptStartedAt — but an
	// attempt is recorded as soon as it is applicable and may then wait: for a window, for a wave, or for a
	// blocker to clear. On this box the attempt was recorded at 09:17 and refused (nothing to roll back to);
	// the blocker was fixed and the SAME attempt executed at 09:53. Begin is skipped for a continuing attempt,
	// so the ten-minute grace had expired thirty-six minutes before the installer was handed anything. The
	// updater came back as the new version, found `executing`, called it interrupted, wrote PhaseFailed, and
	// told the operator to check the network of a box whose update had just succeeded.
	InFlightSince string `json:"in_flight_since,omitempty"`
	// Failures counts consecutive failed attempts per target version.
	Failures map[string]int `json:"failures,omitempty"`
	// Poisoned records versions this device will no longer attempt, and why. The reason is kept because the
	// operator reading it needs to know whether this was three crashes or one unrecoverable install.
	Poisoned map[string]string `json:"poisoned,omitempty"`
	// LastWaitReason is the most recent gate hold, so "why is this device still on the old build" is answerable
	// without waiting for the next tick.
	LastWaitReason string `json:"last_wait_reason,omitempty"`
	// LastFailureReason is why the most recent attempt failed, kept whether or not it poisoned the version.
	//
	// ★ It exists because the reason used to be discarded until the THIRD failure — Poisoned is only written at
	// the ceiling — and the sentence that matters most is written on the first: "steering was taken down for
	// this install and could not be restored". A device sitting unprotected recorded a failure count and no
	// account of what happened. Found by a test asserting the journal carried what the operator was told.
	LastFailureReason string `json:"last_failure_reason,omitempty"`
	// RestoreMaterial names what was captured for a rollback, so a recovery can check it is still there.
	RestoreMaterial []string `json:"restore_material,omitempty"`
	// PlanGeneratedAt is the newest rollout plan this device has ACCEPTED, in RFC3339.
	//
	// It is the monotonic floor that makes replaying an older signed plan useless: a correctly signed document
	// from before a release was withdrawn is otherwise indistinguishable from the current one, because the
	// signature says nothing about when. Kept in the journal because the journal is what already survives the
	// updater's own death, and losing this must fail SAFE — an empty floor accepts the next plan and starts the
	// ratchet again, which is where a fresh device begins anyway.
	PlanGeneratedAt string `json:"plan_generated_at,omitempty"`

	// PendingReport names an outcome that has been REACHED but not yet queued for the fleet view.
	//
	// ★ A TERMINAL OUTCOME IS PRODUCED EXACTLY ONCE (2026-08-12, ninth review). Reconcile is the only writer of
	// PhaseCompleted: the pass that closes an attempt is the only pass that can report it, and the next one
	// sees a phase that is not interrupted and returns changed=false. So an outbox write that failed after the
	// journal was saved lost that outcome PERMANENTLY — the device had installed the release and the fleet
	// would never hear about it.
	//
	// ★ IT CARRIES THE WHOLE REPORT, NOT THE STATUS (2026-08-12, tenth review). Holding only the status meant
	// the retry BUILT A NEW REPORT — new id, new timestamp — so the Edge could not recognise it as the same
	// event, and a pass that queued the outcome but failed to clear the marker reported it twice. It also
	// covered only `completed`: a FAILED outcome whose queue failed was observed once (the failure counter had
	// already moved, so the in-pass comparison found nothing on the next pass) and lost permanently.
	//
	// Set when the outcome is reached and cleared once it is durably queued.
	PendingReport *PendingReport `json:"pending_report,omitempty"`
	// DroppedOwedOutcomes counts terminal outcomes this device owed the fleet and could not hold, because the
	// single pending slot was already occupied by an older one. See MarkReportPendingIfFree.
	//
	// It exists so the shortfall is legible rather than merely present: without it, a device that discarded an
	// outcome and a device that never had one are the same journal.
	DroppedOwedOutcomes int `json:"dropped_owed_outcomes,omitempty"`
	// LastDroppedOwedOutcome names the most recent one, so --status can say WHAT was lost and not only how many.
	LastDroppedOwedOutcome string `json:"last_dropped_owed_outcome,omitempty"`
	// PendingReportAttempts counts consecutive failures to put PendingReport in the outbox. See
	// RecordReportQueueFailure: a pass stops while an outcome is owed, so without a bound a device that cannot
	// queue one outcome can never update again.
	PendingReportAttempts int `json:"pending_report_attempts,omitempty"`
	// Quarantined holds outcomes this device gave up reporting. It persists and is printed by --status, because
	// the fleet will never hear about them and that must not be discoverable only by subtraction.
	Quarantined []QuarantinedReport `json:"quarantined_reports,omitempty"`

	// ReportedOutcomeAssumed records that ReportedOutcome was not earned by a report reaching the outbox but
	// ASSUMED, on load, from a journal written before the outcome counter existed. The distinction is what
	// makes "this device will never report its last outcome" answerable instead of mysterious.
	// ReportedOutcomeEarned records that this marker was set by an outcome that actually reached the outbox,
	// rather than adopted by a compatibility shim. It exists because the terminal counter cannot answer that
	// question on a journal the legacy-flush lane wrote — see MarkOutcomeReported.
	ReportedOutcomeEarned bool `json:"reported_outcome_earned,omitempty"`

	ReportedOutcomeAssumed bool `json:"reported_outcome_assumed,omitempty"`

	// ReportedOutcomeForgotten records that an operator deliberately undid an ASSUMED marker. Without it the
	// undo does not survive a reload — the adoption's guards all read false again and it re-adopts.
	ReportedOutcomeForgotten bool `json:"reported_outcome_forgotten,omitempty"`

	// ReportedOutcome fingerprints the last terminal outcome that reached the outbox.
	//
	// ★ "HAS THIS BEEN REPORTED" MUST BE ANSWERABLE FROM DISK (2026-08-12, twelfth review). It was answered
	// from an in-pass comparison — Reconcile's changed flag, and NewFailureSince against a snapshot taken this
	// pass — so a crash between the terminal save and the report left a journal whose terminal state was
	// already recorded and whose outcome nothing would ever produce again. Both windows are the same shape and
	// neither closes by reordering two writes: the question has to survive the process.
	//
	// Derived from persisted state (phase, target, failure count), so the answer is the same after a restart as
	// before one.
	ReportedOutcome string `json:"reported_outcome,omitempty"`

	// TerminalSeq counts terminal transitions on this device. It exists so two outcomes that describe the same
	// phase and version are still two events — see OutcomeFingerprint.
	TerminalSeq int `json:"terminal_seq,omitempty"`
	// AttemptKind is whether the recorded attempt is moving this device FORWARD or BACK.
	//
	// ★ It exists because every other field reads identically for the two. A rollback records the old version as
	// its target and the new one as where it came from, so a journal without this field says "attempt at 0.2.0,
	// from 0.2.1" — which is what an operator sees during the incident their rollback caused, and it looks like
	// a device that updated backwards on its own. It also decides which terminal phase success writes:
	// `completed` and `rolled_back` are different outcomes and must never render the same.
	//
	// Empty means an update, so every journal written before this field existed reads correctly.
	AttemptKind string `json:"attempt_kind,omitempty"`
}

// Attempt kinds. KindUpdate is the zero value's meaning, so it is never written.
const (
	KindUpdate   = "update"
	KindRollback = "rollback"
)

// AcceptedPlanFloor is the newest plan this device has accepted, for RolloutExpectation.NotBefore.
func (j *Journal) AcceptedPlanFloor() time.Time {
	if j == nil {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, j.PlanGeneratedAt)
	if err != nil {
		return time.Time{}
	}
	return t
}

// AcceptPlanFloor raises the floor to generated, and reports whether it moved. It never lowers it: that is the
// whole point of a ratchet.
func (j *Journal) AcceptPlanFloor(generated time.Time) bool {
	if j == nil || generated.IsZero() || !generated.After(j.AcceptedPlanFloor()) {
		return false
	}
	j.PlanGeneratedAt = generated.UTC().Format(time.RFC3339)
	return true
}

// IsRollback reports whether the recorded attempt is a deliberate return to an earlier version.
func (j *Journal) IsRollback() bool { return j != nil && j.AttemptKind == KindRollback }

// ★ LOOKING FOR "WAS THERE A NEW FAILURE"? IT IS OwesOutcomeReport (2026-08-12).
//
// There was a NewFailureSince(before, after) here that compared two snapshots of the journal taken during the
// same pass. It answered a question the fleet does need — transitions, not states, because a poisoned device
// reporting every thirty minutes forever is its own way of hiding an outage — but it answered it from memory.
// Run persists a terminal phase internally and returns, so a crash in between lost the event permanently: the
// counter had already moved, and the next pass compared against a snapshot that already contained it.
//
// OwesOutcomeReport asks the FILE instead, comparing a fingerprint of the terminal state against the one
// already reported, so the answer survives the process. It is still once-per-transition. The old helper is
// deleted rather than kept: with no callers left it could only serve to reintroduce the window.

// DefaultMaxAttempts is how many times one target version may fail before the device stops trying it.
const DefaultMaxAttempts = 3

// NewJournal returns an empty journal.
func NewJournal() *Journal {
	return &Journal{Schema: SchemaJournal, Phase: PhaseIdle}
}

// Interrupted reports whether the journal shows an attempt that started and never reached a terminal phase.
// This is the question asked at every startup, and the reason the journal is written before transitions.
func (j *Journal) Interrupted() (bool, Phase) {
	if j == nil {
		return false, PhaseIdle
	}
	if interruptedPhases[j.Phase] {
		return true, j.Phase
	}
	return false, j.Phase
}

// NeedsNetworkRecovery reports whether the interrupted phase is one where the box may have been left without
// working steering — steering was taken down on purpose, or the installer was mid-run.
//
// Separate from Interrupted because the responses differ: a stuck `snapshotted` needs the attempt retried,
// while a stuck `disarmed` or `executing` needs the network checked FIRST, before anything else is attempted
// on a box that may not have one.
func (j *Journal) NeedsNetworkRecovery() bool {
	if j == nil {
		return false
	}
	return j.Phase == PhaseDisarmed || j.Phase == PhaseExecuting || j.Phase == PhaseRollingBack
}

// Begin starts an attempt at target, from the version currently running.
func (j *Journal) Begin(target, from string, now time.Time) {
	j.Schema = SchemaJournal
	j.TargetVersion = target
	j.FromVersion = from
	j.AttemptStartedAt = now.UTC().Format(time.RFC3339)
	// A new attempt has not touched the machine yet. Carrying the previous attempt's stamp would hand this one
	// a grace period that had already been spent.
	j.InFlightSince = ""
	j.Phase = PhaseVerified
	j.UpdatedAt = j.AttemptStartedAt
	j.AttemptKind = ""
}

// BeginRollback starts a deliberate return to target, leaving the version currently running.
//
// Separate from Begin rather than a parameter on it, because the two have different callers and the wrong one
// being reached by accident is the difference between installing a new build and installing an old one.
func (j *Journal) BeginRollback(target, from string, now time.Time) {
	j.Begin(target, from, now)
	j.AttemptKind = KindRollback
}

// Refuse records that this device will not attempt version again, without counting a failure against it.
//
// The case it exists for is the rollback: leaving a version behind on purpose has to stop the updater from
// installing it again on the next tick, and going through RecordFailure to get there would be a lie about what
// happened (nothing failed here — an operator decided) as well as arithmetic on a counter that means
// "consecutive failed attempts". Same durable effect as poisoning, because it IS poisoning; only the reason
// differs, and the reason is what the operator reads later.
func (j *Journal) Refuse(version, reason string) {
	v := strings.TrimSpace(version)
	if v == "" {
		return
	}
	if j.Poisoned == nil {
		j.Poisoned = map[string]string{}
	}
	j.Poisoned[v] = reason
}

// Enter records a phase transition. Callers persist immediately after, BEFORE performing the action the phase
// names.
// enterTerminal bumps the terminal counter when a phase is one an operator hears about.
func (j *Journal) enterTerminal(p Phase) {
	switch p {
	case PhaseCompleted, PhaseRolledBack, PhaseFailed:
		j.TerminalSeq++
	}
}

func (j *Journal) Enter(p Phase, now time.Time) {
	if j.Phase != p {
		j.enterTerminal(p)
	}
	// ★ THE MOMENT THE MACHINE STARTS CHANGING, WHICH IS NOT THE MOMENT THE ATTEMPT WAS RECORDED
	// (2026-08-14, measured on win-dev-1). See InstallGrace and installYoungerThan: the grace that keeps a
	// successful update from being called interrupted was anchored to AttemptStartedAt, and an attempt can sit
	// recorded for hours before anything is handed to an installer. Stamped on the FIRST in-flight transition
	// only, so disarm→executing does not restart the clock partway through an install.
	if inFlightPhases[p] && j.InFlightSince == "" {
		j.InFlightSince = now.UTC().Format(time.RFC3339)
	}
	j.Phase = p
	j.UpdatedAt = now.UTC().Format(time.RFC3339)
}

// RecordWait notes why the gate held this device, without disturbing the attempt state.
func (j *Journal) RecordWait(reason string, now time.Time) {
	j.LastWaitReason = reason
	j.UpdatedAt = now.UTC().Format(time.RFC3339)
}

// RecordFailure counts a failed attempt at the current target and poisons the version once it has failed
// maxAttempts times.
//
// Poisoning is a refusal to keep trying, not a kill switch: the device stays exactly as it is, running
// whatever it was running. What stops is the retrying — because with a maintenance window, an update that
// fails every time is a machine for breaking a fleet at the same hour every night, and the log filling with
// identical failures is not the operator finding out.
func (j *Journal) RecordFailure(reason string, maxAttempts int, now time.Time) (poisoned bool) {
	if maxAttempts <= 0 {
		maxAttempts = DefaultMaxAttempts
	}
	v := strings.TrimSpace(j.TargetVersion)
	if v == "" {
		j.LastFailureReason = reason
		j.Enter(PhaseFailed, now)
		return false
	}
	if j.Failures == nil {
		j.Failures = map[string]int{}
	}
	j.LastFailureReason = reason
	j.Failures[v]++
	j.Enter(PhaseFailed, now)
	if j.Failures[v] < maxAttempts {
		return false
	}
	if j.Poisoned == nil {
		j.Poisoned = map[string]string{}
	}
	j.Poisoned[v] = fmt.Sprintf("failed %d times; last: %s", j.Failures[v], reason)
	return true
}

// RecordSuccess clears the failure history for the version that just landed. Consecutive failures are what
// the ceiling counts, so one success has to reset it — otherwise a device that failed twice months ago is
// one bad night away from being poisoned.
// QuarantinedReport is an outcome the device stopped trying to queue.
type QuarantinedReport struct {
	ID       string `json:"id,omitempty"`
	Status   string `json:"status"`
	Version  string `json:"version,omitempty"`
	At       string `json:"at"`
	Attempts int    `json:"attempts"`
	Reason   string `json:"reason,omitempty"`
}

// PendingReport is a Report held in the journal, and it reads the shape an OLDER BUILD wrote.
//
// ★ I CHANGED A FIELD'S TYPE INSIDE A SCHEMA VERSION (2026-08-12, eleventh review). `pending_report` shipped
// as a STRING (the status) and became an object, under the same `dsse_agent_update_journal.v1`. A device that
// had recorded `"pending_report":"installed"` under the older build would fail to unmarshal its journal
// entirely — and this updater treats an unreadable journal as "do not attempt anything", so that device would
// be permanently blocked from updating until somebody deleted the file by hand.
//
// The schema string is a promise about what a reader can expect, and changing a field's type without changing
// it breaks the one property it exists to provide. The version is not bumped here because the OLD shape is
// still accepted: a string is read as the status it always was, and the retry then carries no id — which is
// worse than a full report and far better than a device that cannot update at all.
type PendingReport struct {
	Report
}

// MarshalJSON always writes the OBJECT. Without it the embedded Report's own marshalling is used, which is what
// we want — but stating it here keeps the pair visible: read two shapes, write one.
func (p PendingReport) MarshalJSON() ([]byte, error) { return json.Marshal(p.Report) }

// UnmarshalJSON accepts both shapes: the object this build writes, and the bare status string an older one did.
//
// A legacy string yields a Report with only a status; LoadJournal completes it, because a report with no
// timestamp is one AppendReport refuses — which would leave the device retrying forever and, since a pass stops
// while an outcome is owed, unable to update at all. Reading the old shape and then being unable to act on it
// is the same outage with an extra step.
func (p *PendingReport) UnmarshalJSON(raw []byte) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) > 0 && trimmed[0] == '"' {
		var status string
		if err := json.Unmarshal(trimmed, &status); err != nil {
			return err
		}
		p.Report = Report{Status: status}
		return nil
	}
	return json.Unmarshal(trimmed, &p.Report)
}

// OutcomeFingerprint identifies the terminal state this journal is in, or "" when it is not in one.
//
// Phase and target say WHICH outcome; the failure count distinguishes a second failure of the same version
// from the first. Nothing here is derived from the current pass, which is the whole point.
func (j *Journal) OutcomeFingerprint() string {
	if j == nil {
		return ""
	}
	switch j.Phase {
	case PhaseCompleted, PhaseRolledBack:
		return string(j.Phase) + "|" + j.TargetVersion + "|" + strconv.Itoa(j.TerminalSeq)
	case PhaseFailed:
		// ★ THE FAILURE COUNT IS NOT ENOUGH (2026-08-12, thirteenth review). Not every terminal failure goes
		// through RecordFailure — an interrupted attempt and a rollback that could not be launched do not
		// increment it — so a second failure of the same version produced the SAME fingerprint as the first and
		// was treated as already reported. TerminalSeq is bumped on every terminal transition, so two failures
		// are two events whatever route they arrived by.
		return string(j.Phase) + "|" + j.TargetVersion + "|" + strconv.Itoa(j.Failures[j.TargetVersion]) +
			"|" + strconv.Itoa(j.TerminalSeq)
	default:
		return ""
	}
}

// OwesOutcomeReport reports whether this journal is in a terminal state whose outcome has not reached the
// outbox. True after a crash between the transition and the report, which is the case it exists for.
func (j *Journal) OwesOutcomeReport() bool {
	fingerprint := j.OutcomeFingerprint()
	return fingerprint != "" && fingerprint != j.ReportedOutcome
}

// MarkOutcomeReported records that the current terminal state has reached the outbox.
//
// ★★ IT SAYS THE MARKER WAS EARNED, BECAUSE THE COUNTER CANNOT (2026-08-13, thirtieth review). The rule added
// in ae9af550 — "a build that has TerminalSeq cannot earn a marker while the counter is still zero" — is false
// in one lane of this same file. A journal written by an OLD build carries a pending_report and no counter;
// completeLegacyPendingReport fills it in on load, the current build flushes it to the outbox and lands here,
// and nothing on that path ever calls Enter. So the marker is EARNED, by a current build, with TerminalSeq
// still 0 — and the next load would reclassify it as an assumption, after which --report-outcome-again would
// happily send the fleet an outcome it already has, twice.
//
// The fact is now recorded instead of inferred. That is the repair this family keeps needing: two situations
// were sharing one value, so the one that cannot be derived gets written down.
//
// ★ AND THE ASSUMPTION IS CLEARED HERE (carry-over #1, open since the assumed flag was introduced). A device
// whose marker was ASSUMED and which then genuinely reports has an earned marker still labelled an assumption,
// so ForgetAssumedOutcome would clear something the fleet really did receive.
func (j *Journal) MarkOutcomeReported() {
	if j != nil {
		j.ReportedOutcome = j.OutcomeFingerprint()
		j.ReportedOutcomeEarned = true
		j.ReportedOutcomeAssumed = false
	}
}

// MarkReportPending records the exact outcome that still has to reach the outbox. The SAME report is retried,
// so the Edge sees one event however many attempts it takes.
func (j *Journal) MarkReportPending(r Report) {
	if j != nil {
		j.PendingReport = &PendingReport{Report: r}
	}
}

// MarkReportPendingIfFree fills the pending slot when it is empty, and COUNTS the outcome it could not hold
// when it is not. It reports whether the slot took the report.
//
// ★ WHY THIS EXISTS (2026-08-14, thirty-first review, PLAUSIBLE). There is one slot, and overwriting it loses
// an outcome the fleet was already owed — so the callers guarded on `PendingReport == nil` and dropped the
// newer one. Correct about which to keep, silent about the loss: two terminal outcomes existed, the fleet
// heard about one, and nothing anywhere said the other had been discarded. An operator reading the fleet view
// sees a device with a plausible history and no way to know it is incomplete.
//
// Which to keep is unchanged: the OLDER one, because it has been owed longer and the newer failure is usually
// a consequence of the same trouble. What changes is that the device now records that it happened, so
// --status can say the fleet's picture of this box is short by N outcomes rather than merely being short.
func (j *Journal) MarkReportPendingIfFree(r Report) bool {
	if j == nil {
		return false
	}
	if j.PendingReport != nil {
		j.DroppedOwedOutcomes++
		j.LastDroppedOwedOutcome = strings.TrimSpace(r.Status + " " + r.TargetVersion)
		return false
	}
	j.MarkReportPending(r)
	return true
}

// ClearReportPending is called once the outcome is durably queued.
func (j *Journal) ClearReportPending() {
	if j != nil {
		j.PendingReport = nil
	}
}

func (j *Journal) RecordSuccess(now time.Time) {
	if v := strings.TrimSpace(j.TargetVersion); v != "" {
		delete(j.Failures, v)
	}
	// A rollback that landed is not an update that completed. `rolled_back` is the phase every report and every
	// operator reads to answer "is this device on the build we shipped", and folding it into `completed` would
	// make a fleet that had to be walked backwards indistinguishable from one that took the release.
	if j.IsRollback() {
		j.Enter(PhaseRolledBack, now)
		return
	}
	j.Enter(PhaseCompleted, now)
}

// IsPoisoned reports whether this device has given up on a version, and why.
//
// There is no remote un-poison, deliberately. Naming a different target version already clears the block, so
// a dedicated override would only ever be a button for forcing a known-bad build back onto a device that has
// already refused it three times.
// ★ Matched with SameVersion rather than by map key, because the two writers of this map do not speak the same
// dialect: RecordFailure keys it by the manifest's version ("0.2.1") and a rollback keys it by what the device
// was RUNNING ("0.2.1+20260811035942"). An exact-key lookup silently misses the second — so a device that was
// just rolled back would find the version unpoisoned on its next tick and install the bad build again, which is
// the one thing a rollback has to prevent.
func (j *Journal) IsPoisoned(version string) (bool, string) {
	if j == nil || j.Poisoned == nil {
		return false, ""
	}
	if r, ok := j.Poisoned[strings.TrimSpace(version)]; ok {
		return true, r
	}
	for v, r := range j.Poisoned {
		if SameVersion(v, version) {
			return true, r
		}
	}
	return false, ""
}

// PoisonedVersions lists what this device has given up on, sorted, for reporting.
func (j *Journal) PoisonedVersions() []string {
	if j == nil {
		return nil
	}
	out := make([]string, 0, len(j.Poisoned))
	for v := range j.Poisoned {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// Save writes the journal atomically: a temp file in the same directory, fsync'd, then renamed over the
// target. A torn journal is worse than none — it would be unparseable at exactly the moment it is needed,
// and an unparseable journal is indistinguishable from a device that never attempted anything.
func (j *Journal) Save(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create journal dir: %w", err)
	}
	b, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	// ★ THROUGH THE SHARED PACKAGE (2026-08-13, thirtieth review #20). This was a hand-written
	// temp-fsync-chmod-rename, and durablefile was extracted from four copies of it — but the migration stopped
	// before reaching the one place the Windows failure had actually been MEASURED. So the read-only-attribute
	// handling that win-dev-1 added there did not protect the journal, and the refactor's claim to have
	// consolidated the copies was false in the file that motivated it.
	//
	// The guarantees are the ones the comment below always described, now in one implementation: the contents
	// are flushed before the rename, and the rename is made durable by the platform's own means.
	//
	// ★ THE FILE WAS DURABLE AND THE RENAME WAS NOT (2026-08-12, fourteenth review). fsync on the temp file
	// persists its CONTENTS; the directory entry that makes those contents this journal is a separate write,
	// and a power cut between them leaves the PREVIOUS journal in place. Everything this file is for lives in
	// that gap: an interrupted install reads as never attempted, an owed outcome is not owed, and the accepted
	// plan floor — a one-way replay defence — moves BACKWARDS, which is the one direction it must never go.
	return durablefile.Write(path, b, 0o600)
}

// LoadJournal reads the journal. A MISSING file is not an error — it is a device that has never attempted an
// update, which is the normal state. A CORRUPT file IS an error, because treating it as "never attempted"
// would silently discard the record of an interrupted update, which is the one moment this file matters.
func LoadJournal(path string) (*Journal, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return NewJournal(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read journal %q: %w", path, err)
	}
	var j Journal
	if err := json.Unmarshal(b, &j); err != nil {
		return nil, fmt.Errorf("journal %q is unreadable (%w) — an interrupted update cannot be ruled out from here", path, err)
	}
	if j.Schema != SchemaJournal {
		return nil, fmt.Errorf("journal %q has schema %q, want %q", path, j.Schema, SchemaJournal)
	}
	j.completeLegacyPendingReport()
	j.flagLegacyReportedOutcomeAsAssumed()
	j.adoptLegacyReportedOutcome()
	return &j, nil
}

// adoptLegacyReportedOutcome decides what a journal written BEFORE ReportedOutcome existed means.
//
// ★ THE OBVIOUS READING WOULD RE-REPORT THE WHOLE FLEET (2026-08-12, thirteenth review). An older build
// reported at the terminal transition and cleared what it queued, so a terminal journal with no pending report
// is one whose outcome ALREADY REACHED the fleet — and treating the missing field as "never reported" would
// have every device in the fleet re-send its last outcome, with a new id, on its first pass after the upgrade.
// The success rate and the audit trail would both double in a single afternoon of rollout.
//
// So the absence is read as "reported", which is what the old build's behaviour actually was. A terminal
// journal that still holds a PENDING report is the other case and keeps it: that one was genuinely owed.
// ★ AND "TERMINAL WITH NEITHER FIELD" IS ALSO WHAT A CRASH ON THE CURRENT BUILD LEAVES (2026-08-12,
// fourteenth review). The shape this adopts is produced by TWO different histories: an old build that reported
// and cleared, and a CURRENT build that entered a terminal phase, saved, and died before it could mark the
// outcome pending. Reading both as "reported" fixed the upgrade stampede by reopening, for every device, the
// exact window the twelfth review closed — and this one is silent, because the outcome is simply never owed.
//
// TerminalSeq separates them. It is bumped on every terminal transition and only by builds that have it, so a
// journal whose phase is terminal while the counter is still zero was written before the counter existed.
// That is the only journal this may speak for.
// ★ AND THE ASSUMPTION IS NOT ALWAYS TRUE, SO IT SAYS SO NOW (2026-08-13, win-dev-1). "An older build
// reported at the terminal transition and cleared what it queued" holds for builds that HAD a reporter. The
// oldest do not: the outbox drain arrived in 4e4ec483, and a journal written before that records a terminal
// outcome nothing ever sent. This adoption then suppresses it permanently — and silently, which cost a
// Windows session hours: the marker was cleared by hand and CAME BACK on the next load, with no report file
// anywhere, which reads exactly like the "journal says reported, outbox holds nothing" corruption it is not.
//
// The behaviour stays (re-reporting the fleet on upgrade is the worse failure), and the state becomes legible:
// the marker records that it was ASSUMED rather than earned, and the load says so once. ForgetAssumedOutcome
// is the supported way to undo it for a device where the assumption is known to be wrong.
// legacyNoticeSaid keeps the two legacy-adoption notices to ONE per process per outcome.
//
// ★ IT PRINTED TWICE IN A SINGLE --status (2026-08-13, on a real Mac). printStatus loads the journal once for
// the plan floor and once for the journal line, and each load re-adopts and re-announced. The sentence reads
// like an EVENT — "this device holds a terminal outcome … it is ASSUMED already reported" — so seeing it twice
// invites the reading that two outcomes were suppressed. It is one state, observed twice.
//
// Keyed by the fingerprint rather than a bare sync.Once so that a long-running daemon still announces a NEW
// suppressed outcome, and so one test cannot silence another.
var legacyNoticeSaid = struct {
	sync.Mutex
	seen map[string]bool
}{seen: map[string]bool{}}

func sayLegacyNoticeOnce(fingerprint, format string, args ...any) {
	legacyNoticeSaid.Lock()
	already := legacyNoticeSaid.seen[fingerprint]
	legacyNoticeSaid.seen[fingerprint] = true
	legacyNoticeSaid.Unlock()
	if !already {
		log.Printf(format, args...)
	}
}

func (j *Journal) adoptLegacyReportedOutcome() {
	if j == nil || j.ReportedOutcome != "" || j.PendingReport != nil || j.TerminalSeq != 0 {
		return
	}
	// ★ AND AN OPERATOR WHO ALREADY UNDID THIS MUST NOT HAVE IT DONE AGAIN (2026-08-13, twenty-ninth review).
	// ForgetAssumedOutcome cleared the marker and saved — and every guard above is then false, so the next
	// load re-adopted it. The rescue was a permanent no-op, which is worse than none: the operator watches a
	// command report success and the state does not move, exactly the shape a Windows session spent hours
	// inside before the cause was found.
	if j.ReportedOutcomeForgotten {
		return
	}
	if fingerprint := j.OutcomeFingerprint(); fingerprint != "" {
		j.ReportedOutcome = fingerprint
		j.ReportedOutcomeAssumed = true
		sayLegacyNoticeOnce(fingerprint, "agent update journal: this device holds a terminal outcome (%s) from a build that predates "+
			"the outcome counter, so it is ASSUMED already reported and will not be sent. If this device has "+
			"never appeared in the fleet view, that assumption is wrong for it — the build may predate the "+
			"reporting lane entirely.", fingerprint)
	}
}

// flagLegacyReportedOutcomeAsAssumed marks a report marker that a build without the terminal counter wrote.
//
// ★ WITHOUT IT THERE IS NO WAY BACK THROUGH A SUPPORTED COMMAND (2026-08-13, win-dev-1). The marker and the
// `assumed` flag arrived in different builds, so the devices the assumption HARMS most — the oldest, whose
// build had no reporting lane at all and whose outcome therefore never went anywhere — are exactly the ones
// whose markers predate the flag that would identify them. On disk an assumption and an earned marker are the
// same string, ForgetAssumedOutcome correctly refuses to touch what looks earned, and --report-outcome-again
// answers "nothing to do" to an operator holding a device that has never appeared in the fleet view. The only
// way out was editing the journal by hand, which is not an answer.
//
// The rule is an invariant of this file rather than a guess: MarkOutcomeReported stores OutcomeFingerprint(),
// which is only non-empty in a terminal phase, and Enter bumps TerminalSeq on every transition INTO a terminal
// phase. So a build that has the counter cannot earn a marker while the counter is still zero. Nothing outside
// this file writes either field. A marker with terminal_seq == 0 was therefore written by a build that could
// not have earned it durably — the same population adoptLegacyReportedOutcome already speaks for, arriving one
// build later.
//
// ★ IT CHANGES NO BEHAVIOUR BY ITSELF. The outcome stays suppressed, because re-reporting the fleet on upgrade
// remains the worse failure. What changes is that the state is now legible and the supported command works on
// it. If the classification is ever wrong the cost is a duplicate outcome in the fleet view, and a duplicate
// is the direction this product chooses: an outcome nobody recorded is worse than one recorded twice.
func (j *Journal) flagLegacyReportedOutcomeAsAssumed() {
	if j == nil || j.ReportedOutcome == "" || j.ReportedOutcomeAssumed || j.TerminalSeq != 0 {
		return
	}
	// ★ AN EARNED MARKER IS NEVER AN ASSUMPTION, WHATEVER THE COUNTER SAYS (2026-08-13, thirtieth review). The
	// legacy-flush lane earns a marker without ever calling Enter, so TerminalSeq stays 0 on a journal whose
	// outcome genuinely reached the outbox. Reclassifying that as assumed is how the same outcome gets sent to
	// the fleet twice.
	//
	// Devices that went through that lane BEFORE this field existed carry no flag and are still misclassified —
	// a window of hours, and the cost is one duplicate outcome, which is the direction this product chooses over
	// an outcome nobody recorded.
	if j.ReportedOutcomeEarned {
		return
	}
	// An operator who already undid this must not have it re-imposed — the same re-adoption loop the guard in
	// adoptLegacyReportedOutcome closes, reachable by a second route.
	if j.ReportedOutcomeForgotten {
		return
	}
	j.ReportedOutcomeAssumed = true
	sayLegacyNoticeOnce(j.ReportedOutcome, "agent update journal: this device's report marker (%s) was written by a build that predates the "+
		"terminal counter, so it could not have been earned durably. It is recorded as ASSUMED — nothing is "+
		"re-sent, but --report-outcome-again can now act on it if this device has never appeared in the fleet "+
		"view.", j.ReportedOutcome)
}

// ForgetAssumedOutcome undoes an ASSUMED report marker, so the outcome is owed again.
//
// It refuses to touch a marker that was earned: clearing one of those would re-send an outcome the fleet
// already has, which is the stampede the assumption exists to prevent. Returns whether anything changed.
func (j *Journal) ForgetAssumedOutcome() bool {
	if j == nil || !j.ReportedOutcomeAssumed || j.ReportedOutcome == "" {
		return false
	}
	j.ReportedOutcome = ""
	j.ReportedOutcomeAssumed = false
	// Recorded IN the journal, because the decision has to survive the save that follows it.
	j.ReportedOutcomeForgotten = true
	return true
}

// completeLegacyPendingReport fills in what an older build's `pending_report` string could not carry.
//
// ★ READING IT WAS NOT ENOUGH (2026-08-12, twelfth review). The compatibility shim turned the old string into
// a Report with only a status — and AppendReport refuses a report with no timestamp, so the retry failed on
// every pass; and a pass stops while an outcome is owed. The device could read its journal again and STILL
// never update. Restoring the ability to parse a file is not the same as restoring the ability to act on it.
//
// The timestamp comes from the journal's own UpdatedAt, which is when that outcome was recorded, and the id
// from the version and that time — stable, so a retry after a restart is still the same event to the Edge.
func (j *Journal) completeLegacyPendingReport() {
	if j == nil || j.PendingReport == nil {
		return
	}
	if strings.TrimSpace(j.PendingReport.At) == "" {
		at := strings.TrimSpace(j.UpdatedAt)
		if at == "" {
			at = time.Now().UTC().Format(time.RFC3339)
		}
		j.PendingReport.At = at
	}
	if strings.TrimSpace(j.PendingReport.ID) == "" {
		j.PendingReport.ID = "aue_recovered_" + legacyReportID(j.TargetVersion, j.PendingReport.At)
	}
	if strings.TrimSpace(j.PendingReport.TargetVersion) == "" {
		j.PendingReport.TargetVersion = j.TargetVersion
	}
	if strings.TrimSpace(j.PendingReport.Kind) == "" {
		j.PendingReport.Kind = "update"
		if j.IsRollback() {
			j.PendingReport.Kind = "rollback"
		}
	}
}

// legacyReportID is stable for one recovered outcome, so retrying it after a restart is the same event.
func legacyReportID(version, at string) string {
	sum := sha256.Sum256([]byte(version + "\x00" + at))
	return hex.EncodeToString(sum[:8])
}

// Copy is a deep copy for callers outside this package that want to ask a question WITHOUT answering it — a
// status command reconciling against a throwaway to report what the next pass will conclude, rather than
// concluding it. A read-only command that quietly advances the state machine is not a read-only command.
func (j *Journal) Copy() *Journal { return j.clone() }

// clone is a deep copy, used to run a rehearsal against a journal nobody else holds. Maps are copied rather
// than shared: a shallow copy would leave the rehearsal writing failures and poison into the caller's journal
// through the same map header, which is the bug it exists to prevent, only harder to see.
func (j *Journal) clone() *Journal {
	if j == nil {
		return nil
	}
	c := *j
	if j.Failures != nil {
		c.Failures = make(map[string]int, len(j.Failures))
		for k, v := range j.Failures {
			c.Failures[k] = v
		}
	}
	if j.Poisoned != nil {
		c.Poisoned = make(map[string]string, len(j.Poisoned))
		for k, v := range j.Poisoned {
			c.Poisoned[k] = v
		}
	}
	return &c
}

// InstallGrace is how long after the machine STARTED BEING CHANGED the installer is still allowed to be
// running before the attempt is called interrupted.
//
// It has to cover a macOS system-extension replacement plus the extension restarting and rewriting its runtime
// marker, or a Windows MSI plus a service restart — and being generous costs only a delayed diagnosis, while
// being tight costs a false "this box's network must be checked" on every machine that updated successfully.
// Ten minutes is far longer than either takes and far shorter than a maintenance window.
const InstallGrace = 10 * time.Minute

func (j *Journal) attemptStarted() time.Time {
	t, err := time.Parse(time.RFC3339, j.AttemptStartedAt)
	if err != nil {
		return time.Time{}
	}
	return t
}

// installStarted is when this attempt began changing the machine, falling back to when the attempt was
// recorded for journals written before InFlightSince existed.
//
// The fallback keeps the OLD behaviour for old journals rather than denying them the grace outright: on those
// the two timestamps were the only thing available, and refusing the benefit of the doubt during an upgrade
// would turn every in-flight install at the moment of rollout into a false interruption.
func (j *Journal) installStarted() time.Time {
	if t, err := time.Parse(time.RFC3339, j.InFlightSince); err == nil {
		return t
	}
	return j.attemptStarted()
}

// installYoungerThan reports whether the machine started being changed recently enough that the installer
// could still be running. An UNPARSEABLE or absent time returns false — the grace is a benefit of the doubt,
// and a journal that cannot say when its install began has not earned one.
func (j *Journal) installYoungerThan(d time.Duration, now time.Time) bool {
	started := j.installStarted()
	if started.IsZero() {
		return false
	}
	return now.Sub(started) < d
}

// terminal reports whether this journal's phase is one an attempt ENDED in. A journal in one of these is
// finished with whatever it was doing, whatever TargetVersion still says.
func (j *Journal) terminal() bool {
	if j == nil {
		return false
	}
	switch j.Phase {
	case PhaseCompleted, PhaseRolledBack, PhaseFailed, PhaseUnrecoverable:
		return true
	default:
		return false
	}
}
