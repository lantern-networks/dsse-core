//go:build darwin

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentupdate"
)

// dry_run_darwin_test.go — a rehearsal must reach every decision and change NOTHING.
//
// ★ IT DID NOT (2026-08-12, found on win-dev-1 and confirmed here). `--dry-run`'s own help says "the journal is
// not written", and three writes escaped it — the worst being the accepted-plan floor, which is a ONE-WAY
// replay defence: a rehearsal against a plan slightly ahead of the fleet's current one FROZE the device on its
// next real pass, against a control plane doing nothing wrong.
//
// These test the guards rather than a whole pass, and say so: they pin that the mechanism refuses to write,
// not that every future call site remembers to use it.

func TestADryRunWritesNoJournal(t *testing.T) {
	dir := t.TempDir()
	u := &updater{journalPath: filepath.Join(dir, "journal.json"), dryRun: true}
	j := agentupdate.NewJournal()
	j.AcceptPlanFloor(time.Now().UTC())

	var notes []string
	if u.persist(j, "the accepted-plan floor", &notes) {
		t.Fatalf("a dry run reported that it had written the journal")
	}
	if _, err := os.Stat(u.journalPath); !os.IsNotExist(err) {
		t.Fatalf("a dry run wrote the journal: the one-way plan floor would freeze this device on its next pass")
	}
	if len(notes) == 0 || !strings.Contains(notes[0], "rehearsal") {
		t.Fatalf("a dry run wrote nothing and said nothing: %v", notes)
	}
}

func TestADryRunQueuesNoOutcome(t *testing.T) {
	dir := t.TempDir()
	u := &updater{journalPath: filepath.Join(dir, "journal.json"), dryRun: true}
	var notes []string
	if u.queue(agentupdate.NewJournal(), agentupdate.ReportInstalled, "0.2.9", "landed", time.Now(), &notes) {
		t.Fatalf("a dry run reported that it had queued an outcome")
	}
	if n := agentupdate.PendingReports(agentupdate.ReportsDir(u.journalPath)); n != 0 {
		t.Fatalf("a dry run put %d outcome(s) in front of the fleet", n)
	}
}

// And the same calls WITHOUT the flag must still write, or the test above would pass against a build that
// simply lost the ability to record anything.
func TestARealPassStillWrites(t *testing.T) {
	dir := t.TempDir()
	u := &updater{journalPath: filepath.Join(dir, "journal.json")}
	var notes []string
	if !u.persist(agentupdate.NewJournal(), "the accepted-plan floor", &notes) {
		t.Fatalf("a real pass could not write the journal: %v", notes)
	}
	if _, err := os.Stat(u.journalPath); err != nil {
		t.Fatalf("a real pass wrote no journal: %v", err)
	}
	if !u.queue(agentupdate.NewJournal(), agentupdate.ReportInstalled, "0.2.9", "landed", time.Now(), &notes) {
		t.Fatalf("a real pass could not queue an outcome: %v", notes)
	}
	if n := agentupdate.PendingReports(agentupdate.ReportsDir(u.journalPath)); n != 1 {
		t.Fatalf("a real pass queued %d outcomes, want 1", n)
	}
}
