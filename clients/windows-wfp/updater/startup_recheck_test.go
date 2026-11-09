package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/agentupdate"
)

// A refusal standing at start is looked at again a bounded number of times; none stands, nothing is scheduled.
func TestAStandingRefusalIsRecheckedSoonAfterStartAndNotForever(t *testing.T) {
	dir := t.TempDir()
	r := startupRecheck{reportsDir: dir}
	if r.next() != nil {
		t.Fatal("an early pass was scheduled with no refusal standing")
	}
	if err := os.WriteFile(filepath.Join(dir, "last-refusal"), []byte("f"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !agentupdate.RefusalStands(dir) {
		t.Fatal("fixture: no refusal stands")
	}
	for i := range startupRecheckDelays {
		if r.next() == nil {
			t.Fatalf("early pass %d was not scheduled while a refusal stands", i+1)
		}
	}
	if r.next() != nil {
		t.Fatal("early passes continued past the bound; a genuinely refused device would be polled forever")
	}
}

// The scheduler only helps if the service loop uses it; the loop is Windows-only, so its source is checked.
func TestTheServiceLoopUsesTheStartupRecheck(t *testing.T) {
	b, err := os.ReadFile("main_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{"early := startupRecheck{reportsDir: agentupdate.ReportsDir(s.u.deps.JournalPath)}",
		"case <-recheck:", "recheck = early.next()"} {
		if !strings.Contains(s, want) {
			t.Errorf("service loop is missing %q", want)
		}
	}
}
