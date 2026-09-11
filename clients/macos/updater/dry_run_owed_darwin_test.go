//go:build darwin

package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentupdate"
)

// dry_run_owed_darwin_test.go — a rehearsal on a Mac that owes the fleet an outcome must SAY SO, and the
// answer must not depend on which line noticed.
//
// ★ THE SAME FINDING LANDED ON BOTH PLATFORMS (2026-08-12). Two blocks ask "does this journal owe an
// outcome": one before the manifest fetch, one after Run. The first carried `&& !u.dryRun` and the second did
// not, so the same rehearsal, on the same Mac, over the same journal, told the operator or said nothing at all
// depending on where the fact was spotted first. The flag was redundant against persist() — which is the whole
// point of wrapping the writes once — so it is gone.
//
// The assertion is on the OUTPUT an operator reads and on the DISK they would find afterwards, not on the
// guard: this keeps holding if the blocks move again.

// owedRig is passRig plus the state a crash between the terminal save and the report leaves behind: a terminal
// journal whose reported_outcome belongs to an EARLIER outcome. A journal with no reported_outcome at all is
// not this case — it is a pre-upgrade journal, and it is deliberately read as already reported.
func owedRig(t *testing.T, running string) *updater {
	t.Helper()
	u := passRig(t, running)
	j, err := agentupdate.LoadJournal(u.journalPath)
	if err != nil {
		t.Fatal(err)
	}
	j.Enter(agentupdate.PhaseFailed, time.Now().UTC().Add(-time.Minute))
	j.LastFailureReason = "the installer exited non-zero"
	// The outcome this device DID report, one version ago. Anything that is not the current fingerprint leaves
	// the current one owed.
	j.ReportedOutcome = "completed|0.2.8|1"
	if err := j.Save(u.journalPath); err != nil {
		t.Fatal(err)
	}
	return u
}

func TestARehearsalSaysWhatItWouldHaveQueuedForAnOutcomeOwedBeforeTheFetch(t *testing.T) {
	u := owedRig(t, "0.2.9")
	u.dryRun = true
	before, err := os.ReadFile(u.journalPath)
	if err != nil {
		t.Fatal(err)
	}

	res := u.pass(time.Now().UTC())

	said := strings.Join(res.notes, "\n")
	if !strings.Contains(said, "would have queued") {
		t.Fatalf("a rehearsal over a journal that owes the fleet an outcome said nothing about it.\n"+
			"This is the asymmetry itself: an operator runs --dry-run to find out what this box would do, and "+
			"the one fact worth surfacing — an outcome the fleet never received — was reported only when a "+
			"later line happened to notice it first.\nnotes:\n%s", said)
	}

	// And it is still a rehearsal.
	after, err := os.ReadFile(u.journalPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("the rehearsal wrote the journal:\n before %s\n after  %s", before, after)
	}
	if entries, _ := os.ReadDir(agentupdate.ReportsDir(u.journalPath)); len(entries) != 0 {
		t.Fatalf("the rehearsal put %d outcome(s) in the outbox; the extension would ship them and the Edge "+
			"would count them", len(entries))
	}
}

// The other half: a rehearsal must not STOP on a box that is fine. The guard that remains on the "an outcome is
// still owed, so this pass stops" branch changes control flow rather than suppressing a write, which is why it
// keeps its flag — remove it and every rehearsal over an owed outcome would report nothing beyond the stop.
func TestARehearsalDoesNotStopOnAnOwedOutcome(t *testing.T) {
	u := owedRig(t, "0.2.9")
	u.dryRun = true

	res := u.pass(time.Now().UTC())

	if res.action == "blocked" {
		t.Fatalf("the rehearsal stopped at the owed outcome (%s), so it never reached the decision the "+
			"operator ran it for", res.reason)
	}
}

// And the real pass over the same journal still delivers it, or the two tests above would pass against a build
// that had simply lost the ability to notice.
func TestARealPassDeliversAnOutcomeOwedBeforeTheFetch(t *testing.T) {
	u := owedRig(t, "0.2.9")

	u.pass(time.Now().UTC())

	if n := agentupdate.PendingReports(agentupdate.ReportsDir(u.journalPath)); n == 0 {
		t.Fatal("a real pass left the owed outcome unqueued: the fleet view would never learn this device failed")
	}
}
