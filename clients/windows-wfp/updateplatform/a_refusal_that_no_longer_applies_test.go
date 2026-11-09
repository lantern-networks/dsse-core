package updateplatform

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentupdate"
)

// Found 2026-11-04 upgrading a Windows device from 0.4.0 to 0.4.1: the new updater refused once before the
// installer handed it the update-signing keys, then ran with them and found nothing published. Nothing was
// reported on that path, so the Devices screen said "refusing the update" for as long as anyone looked.
func TestARefusalThatNoLongerAppliesIsClearedOnce(t *testing.T) {
	stagedInto(t)
	journal := filepath.Join(t.TempDir(), "journal.json")
	deps := func(src fakeSource) TickDeps {
		return TickDeps{
			Source:      src,
			Platform:    &fakePlatform{running: "0.4.1"},
			Config:      agentupdate.Config{Platform: agentupdate.PlatformWindows, Arch: agentupdate.ArchAMD64},
			JournalPath: journal,
			Load:        func(string) (*agentupdate.Journal, error) { return agentupdate.NewJournal(), nil },
			Save:        func(*agentupdate.Journal, string) error { return nil },
		}
	}
	now := time.Now().UTC()

	// The refusal: no keys yet.
	res, _ := Tick(context.Background(), deps(fakeSource{err: errors.New("no trusted update-signing keys are configured")}), now)
	if len(res.Reports) != 1 || res.Reports[0].Status != agentupdate.ReportRefused {
		t.Fatalf("the refusal was not reported: %+v", res.Reports)
	}
	dir := agentupdate.ReportsDir(journal)
	if !agentupdate.RefusalStands(dir) {
		t.Fatal("no refusal marker after reporting one")
	}

	// The keys arrive; nothing is published. The fleet is told, once, that the refusal no longer applies.
	res, err := Tick(context.Background(), deps(fakeSource{err: ErrNoManifest}), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Reports) != 1 || res.Reports[0].Status != agentupdate.ReportInstalled || !res.Reports[0].RefusalCleared ||
		res.Reports[0].RunningVersion != "0.4.1" || res.Reports[0].TargetVersion != "" {
		t.Fatalf("the cleared refusal was not reported as installed 0.4.1 with no target: %+v", res.Reports)
	}
	if agentupdate.RefusalStands(dir) {
		t.Fatal("the refusal marker outlived the report that cleared it")
	}
	if n := agentupdate.PendingReports(dir); n != 2 {
		t.Fatalf("outbox holds %d reports; want the refusal and the clearing", n)
	}

	// And only once: the next quiet pass sends nothing.
	res, _ = Tick(context.Background(), deps(fakeSource{err: ErrNoManifest}), now.Add(2*time.Minute))
	if len(res.Reports) != 0 {
		t.Fatalf("a quiet pass with no standing refusal reported %+v", res.Reports)
	}
}

// A device that never refused stays quiet, as before.
func TestNoRefusalNothingToClear(t *testing.T) {
	stagedInto(t)
	res, err := Tick(context.Background(), TickDeps{
		Source:      fakeSource{err: ErrNoManifest},
		Platform:    &fakePlatform{running: "0.4.1"},
		Config:      agentupdate.Config{Platform: agentupdate.PlatformWindows, Arch: agentupdate.ArchAMD64},
		JournalPath: filepath.Join(t.TempDir(), "journal.json"),
		Load:        func(string) (*agentupdate.Journal, error) { return agentupdate.NewJournal(), nil },
		Save:        func(*agentupdate.Journal, string) error { return nil },
	}, time.Now().UTC())
	if err != nil || len(res.Reports) != 0 {
		t.Fatalf("reports = %+v, err = %v; want none", res.Reports, err)
	}
}
