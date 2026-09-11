package agentupdate

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// legacy_adoption_crash_test.go — the shape "terminal, no pending report, no reported outcome" is produced by
// TWO histories, and only one of them means "already reported".
//
// ★ THE FIX FOR THE UPGRADE STAMPEDE REOPENED THE CRASH WINDOW (2026-08-12, fourteenth review). Reading the
// missing field as "reported" stops a fleet re-sending its last outcome after an upgrade — and says the same
// thing about a CURRENT build that entered a terminal phase, saved, and died before marking the outcome
// pending. That outcome is then never owed, by anything, ever: the quietest way to lose it.

func writeJournal(t *testing.T, j *Journal) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "journal.json")
	if err := j.Save(path); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestACrashBetweenTheTerminalSaveAndTheReportStillOwesIt(t *testing.T) {
	j := NewJournal()
	j.Begin("0.2.9", "0.2.8", time.Now().UTC())
	// What Run persists internally and returns from. The process dies here.
	j.Enter(PhaseFailed, time.Now().UTC())
	j.LastFailureReason = "the installer exited non-zero"
	if j.TerminalSeq == 0 {
		t.Fatal("a terminal transition did not bump TerminalSeq; the discriminator this test relies on is gone")
	}
	path := writeJournal(t, j)

	reloaded, err := LoadJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.OwesOutcomeReport() {
		t.Fatal("a journal written by THIS build — terminal, TerminalSeq bumped, nothing pending and nothing " +
			"reported — came back not owing an outcome. That is a device that failed an update and will never " +
			"tell the fleet, and no later pass can notice because the terminal state is already recorded.")
	}
}

// The other half, which is the reason the adoption exists at all: a journal from a build that predates
// TerminalSeq must NOT be re-reported, or the first pass after an upgrade re-sends the whole fleet's history.
func TestAJournalFromBeforeTheCounterIsStillTreatedAsReported(t *testing.T) {
	j := NewJournal()
	j.Begin("0.2.9", "0.2.8", time.Now().UTC())
	j.Enter(PhaseCompleted, time.Now().UTC())
	path := writeJournal(t, j)

	// Strip terminal_seq the way an older build's file has it: absent.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	delete(doc, "terminal_seq")
	out, _ := json.Marshal(doc)
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}

	reloaded, err := LoadJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.OwesOutcomeReport() {
		t.Fatal("a pre-upgrade journal came back owing its outcome: every device in the fleet would re-send " +
			"its last outcome, with a new id, on the first pass after the rollout")
	}
}

// And a legacy journal that still holds a PENDING report was genuinely owed — the adoption must not swallow it.
func TestALegacyJournalWithAPendingReportKeepsIt(t *testing.T) {
	j := NewJournal()
	j.Begin("0.2.9", "0.2.8", time.Now().UTC())
	j.Enter(PhaseCompleted, time.Now().UTC())
	j.MarkReportPending(Report{ID: "aue_x", Status: ReportInstalled, At: time.Now().UTC().Format(time.RFC3339)})
	path := writeJournal(t, j)

	reloaded, err := LoadJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.PendingReport == nil {
		t.Fatal("the pending report was dropped on load; that outcome reached the journal and nothing else")
	}
}

// ★ THE ASSUMPTION IS WRONG FOR BUILDS THAT PREDATE THE REPORTING LANE (2026-08-13, win-dev-1). A journal
// written before the outcome counter is read as "already reported" — true for a build that HAD a reporter and
// cleared what it queued, false for one whose outbox drain did not exist yet. On that device the marker
// suppresses the outcome for ever, and it does it silently: cleared by hand it comes BACK on the next load
// with no report file anywhere, which reads exactly like the corruption it is not.
func TestAnAssumedReportMarkerSaysThatItWasAssumed(t *testing.T) {
	j := NewJournal()
	j.Begin("0.1.4+c84cf6fc", "0.1.3", time.Now().UTC())
	j.Enter(PhaseRolledBack, time.Now().UTC())
	j.TerminalSeq = 0 // a build that predates the counter
	path := writeJournal(t, j)

	reloaded, err := LoadJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.OwesOutcomeReport() {
		t.Fatal("the upgrade stampede guard stopped working")
	}
	if !reloaded.ReportedOutcomeAssumed {
		t.Fatal("the marker does not record that it was ASSUMED — an operator seeing a device that never " +
			"appears in the fleet view has no way to tell this from a report that was genuinely sent")
	}

	// And there is a supported way back for a device where the assumption is known to be wrong.
	if !reloaded.ForgetAssumedOutcome() {
		t.Fatal("an assumed marker could not be forgotten")
	}
	if !reloaded.OwesOutcomeReport() {
		t.Fatal("after forgetting the assumption the outcome is still not owed")
	}
	// ★ AND IT SURVIVES THE SAVE THAT FOLLOWS IT (2026-08-13, twenty-ninth review). The first version of this
	// test stopped at the line above, so it passed against a rescue that was a permanent no-op: the operator's
	// undo was written and the next load re-adopted the marker, because every guard in the adoption reads
	// false again once the field is cleared. A round trip is the only version of this assertion that means
	// anything — the command's whole purpose is to change what the NEXT pass sees.
	if err := reloaded.Save(path); err != nil {
		t.Fatal(err)
	}
	afterRestart, err := LoadJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if !afterRestart.OwesOutcomeReport() {
		t.Fatal("the operator's undo did not survive a reload: the marker was re-adopted, so the command reports " +
			"success and nothing changes — for ever")
	}
}

// An EARNED marker must not be forgettable: clearing it re-sends an outcome the fleet already has, which is
// the stampede the assumption exists to prevent.
func TestAnEarnedReportMarkerCannotBeForgotten(t *testing.T) {
	j := NewJournal()
	j.Begin("0.2.9", "0.2.8", time.Now().UTC())
	j.Enter(PhaseCompleted, time.Now().UTC())
	j.MarkOutcomeReported()

	if j.ForgetAssumedOutcome() {
		t.Fatal("a marker earned by an actual report was cleared: that device will report its outcome a second time")
	}
	if j.OwesOutcomeReport() {
		t.Fatal("the earned marker was dropped anyway")
	}
}

// ★★ THE STATE A REAL WINDOWS ENDPOINT WAS ACTUALLY STUCK IN (2026-08-13, measured on hardware).
//
// The report marker and the `assumed` flag shipped in different builds. This device's journal was written by
// the build in between: it HAS a marker, put there by the adoption shim, and no flag saying the marker was
// assumed. Every guard then reads the wrong way — adoptLegacyReportedOutcome returns early because a marker
// exists, ForgetAssumedOutcome refuses because the marker looks earned, and --report-outcome-again tells an
// operator "nothing to do" about a device that has never appeared in the fleet view. The only way out was
// editing the journal by hand.
//
// The population this hurts is the one the assumption is most wrong about: builds old enough to have no
// reporting lane at all, whose outcome genuinely never went anywhere.
func TestAMarkerFromTheBuildBetweenTheShimAndTheFlagCanStillBeUndone(t *testing.T) {
	j := NewJournal()
	j.Begin("0.1.4+c84cf6fc", "0.1.3", time.Now().UTC())
	j.Enter(PhaseRolledBack, time.Now().UTC())
	j.TerminalSeq = 0 // predates the counter, exactly as on that box
	// What the in-between build persisted: the fingerprint, and nothing recording that it was an assumption.
	j.ReportedOutcome = j.OutcomeFingerprint()
	j.ReportedOutcomeAssumed = false
	path := writeJournal(t, j)

	reloaded, err := LoadJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.OwesOutcomeReport() {
		t.Fatal("the outcome became owed on load — this is the upgrade stampede, and nothing here should re-send")
	}
	if !reloaded.ReportedOutcomeAssumed {
		t.Fatal("a marker with terminal_seq == 0 cannot have been earned by any build that has the counter, and " +
			"it is still being treated as earned — the operator's only route is a hand-edited journal")
	}
	if !reloaded.ForgetAssumedOutcome() {
		t.Fatal("--report-outcome-again would still answer \"nothing to do\"")
	}
	if err := reloaded.Save(path); err != nil {
		t.Fatal(err)
	}
	after, err := LoadJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if !after.OwesOutcomeReport() {
		t.Fatal("the undo did not survive the reload")
	}
	if after.ReportedOutcomeAssumed {
		t.Fatal("the marker was re-imposed by the second route into the assumption")
	}
}

// ★ THE OTHER HALF OF THE RULE. A marker whose counter is non-zero WAS earned by a build that has the counter,
// and must stay untouchable — otherwise this fix hands the operator a way to re-send outcomes the fleet
// already holds, for every device, which is the stampede all of this exists to prevent.
func TestAMarkerWithATerminalCountIsNeverReclassifiedAsAssumed(t *testing.T) {
	j := NewJournal()
	j.Begin("0.2.9", "0.2.8", time.Now().UTC())
	j.Enter(PhaseCompleted, time.Now().UTC()) // bumps TerminalSeq to 1
	j.MarkOutcomeReported()
	path := writeJournal(t, j)

	reloaded, err := LoadJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.ReportedOutcomeAssumed {
		t.Fatal("an earned marker was reclassified as assumed; every device could now be made to re-report")
	}
	if reloaded.ForgetAssumedOutcome() {
		t.Fatal("an earned marker became forgettable")
	}
}

// ★★ THE LANE THAT BREAKS THE COUNTER RULE (2026-08-13, thirtieth review). An OLD build wrote a
// pending_report and no terminal counter. The current build fills it in on load, flushes it to the outbox, and
// calls MarkOutcomeReported — and nothing on that path calls Enter, so the marker is EARNED with TerminalSeq
// still 0. The classification rule added in ae9af550 said that could not happen, so the next load reclassified
// a delivered outcome as an assumption and --report-outcome-again would send the fleet a second copy.
func TestAnOutcomeFlushedFromALegacyPendingReportIsNotAnAssumption(t *testing.T) {
	j := NewJournal()
	j.Begin("0.2.9", "0.2.8", time.Now().UTC())
	j.Enter(PhaseCompleted, time.Now().UTC())
	// The state a pre-counter build leaves: a terminal phase and a pending report, with no counter.
	j.TerminalSeq = 0
	j.MarkReportPending(Report{ID: "aue_legacy", Status: "installed", At: time.Now().UTC().Format(time.RFC3339)})
	path := writeJournal(t, j)

	loaded, err := LoadJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.PendingReport == nil {
		t.Fatal("the legacy pending report was dropped on load")
	}
	// What the flush lane does once the outbox has it.
	loaded.ClearReportPending()
	loaded.MarkOutcomeReported()
	if err := loaded.Save(path); err != nil {
		t.Fatal(err)
	}

	after, err := LoadJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if after.ReportedOutcomeAssumed {
		t.Fatal("an outcome that actually reached the outbox was reclassified as an assumption — " +
			"--report-outcome-again would now send the fleet a second copy of it")
	}
	if after.ForgetAssumedOutcome() {
		t.Fatal("the earned marker was forgettable, which is the same double report by another route")
	}
	if after.OwesOutcomeReport() {
		t.Fatal("the outcome became owed again after it was delivered")
	}
}

// ★ AND THE OTHER DIRECTION (carry-over #1, open since the assumed flag was introduced). A marker that was
// ASSUMED and is then genuinely reported must stop being an assumption, or ForgetAssumedOutcome clears
// something the fleet really did receive.
func TestReportingForRealClearsAnEarlierAssumption(t *testing.T) {
	j := NewJournal()
	j.Begin("0.1.4", "0.1.3", time.Now().UTC())
	j.Enter(PhaseRolledBack, time.Now().UTC())
	j.TerminalSeq = 0
	path := writeJournal(t, j)

	loaded, err := LoadJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.ReportedOutcomeAssumed {
		t.Fatal("setup: the shim did not adopt")
	}
	loaded.MarkOutcomeReported()
	if loaded.ReportedOutcomeAssumed {
		t.Fatal("the marker is still labelled an assumption after a real report, so it can be forgotten and sent again")
	}
	if loaded.ForgetAssumedOutcome() {
		t.Fatal("a marker earned after an assumption was still forgettable")
	}
}

// ★★ THE COMMAND TAKES THE DEVICE LOCK (2026-08-13, thirtieth review #16 and carry-over #13). It existed twice,
// verbatim, and neither copy locked — while the service tick that writes the same journal does. Both read the
// same file and both write it, and the write that lands second wins; what is at stake is precisely whether an
// outcome is owed, so losing that race sends the fleet a duplicate or drops the report the operator was trying
// to recover.
func TestForgettingAnAssumptionRefusesWhileAnUpdateHoldsTheDevice(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "journal.json")

	j := NewJournal()
	j.Begin("0.1.4", "0.1.3", time.Now().UTC())
	j.Enter(PhaseRolledBack, time.Now().UTC())
	j.TerminalSeq = 0
	if err := j.Save(path); err != nil {
		t.Fatal(err)
	}

	held, err := LockDevice(DeviceLockPath(path))
	if err != nil {
		t.Fatalf("take the lock the service would hold: %v", err)
	}
	var out, errOut bytes.Buffer
	if code := ForgetAssumedOutcomeCommand(path, &out, &errOut); code == 0 {
		t.Fatal("the command edited the journal while an update held the device")
	}
	if !strings.Contains(errOut.String(), "in progress") {
		t.Fatalf("the operator must be told why, got %q", errOut.String())
	}
	held.Release()

	// And with the device free it does its job.
	out.Reset()
	errOut.Reset()
	if code := ForgetAssumedOutcomeCommand(path, &out, &errOut); code != 0 {
		t.Fatalf("code=%d err=%q", code, errOut.String())
	}
	if !strings.Contains(out.String(), "owes the fleet") {
		t.Fatalf("got %q", out.String())
	}
	after, err := LoadJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if !after.OwesOutcomeReport() {
		t.Fatal("the outcome is not owed again, so the command did nothing that lasts")
	}
}
