package main

import (
	"errors"
	"testing"
)

// fakeUpdater stands in for the service manager and the marker file. Failures are injected per call.
type fakeUpdater struct {
	marker               string
	markerUnreadable     bool
	failWrite            map[string]bool
	changes              bool
	running              bool
	failStop, failStart  bool
	stops, starts, apply int
}

func (f *fakeUpdater) ReadMarker() (string, error) {
	if f.markerUnreadable {
		return "", errors.New("access denied")
	}
	return f.marker, nil
}
func (f *fakeUpdater) WriteMarker(s string) error {
	if f.failWrite[s] {
		return errors.New("disk full")
	}
	f.marker = s
	return nil
}
func (f *fakeUpdater) ClearMarker() error { f.marker = ""; return nil }
func (f *fakeUpdater) ApplyConditions() (bool, []string, error) {
	f.apply++
	c := f.changes
	f.changes = false // written once; a rerun finds them in place
	return c, nil, nil
}
func (f *fakeUpdater) Running() (bool, error) { return f.running, nil }
func (f *fakeUpdater) Stop() error {
	f.stops++
	if f.failStop {
		return errors.New("stop failed")
	}
	f.running = false
	return nil
}
func (f *fakeUpdater) Start() error {
	f.starts++
	if f.failStart {
		return errors.New("start failed")
	}
	f.running = true
	return nil
}

func TestUpdaterRestartsOnceWhenConditionsChange(t *testing.T) {
	f := &fakeUpdater{changes: true, running: true}
	if _, err := putUpdaterConditionsInForce(f); err != nil {
		t.Fatal(err)
	}
	if f.stops != 1 || f.starts != 1 || !f.running || f.marker != "" {
		t.Fatalf("stops=%d starts=%d running=%v marker=%q", f.stops, f.starts, f.running, f.marker)
	}
}

func TestNothingChangedMeansNoRestart(t *testing.T) {
	f := &fakeUpdater{running: true}
	if _, err := putUpdaterConditionsInForce(f); err != nil {
		t.Fatal(err)
	}
	if f.stops != 0 || f.starts != 0 || f.marker != "" {
		t.Fatalf("an unchanged updater was restarted: stops=%d starts=%d marker=%q", f.stops, f.starts, f.marker)
	}
}

// F2, first half: the configuration was written and the stop failed. The rerun must restart.
func TestStopFailureIsCompletedByARerun(t *testing.T) {
	f := &fakeUpdater{changes: true, running: true, failStop: true}
	if _, err := putUpdaterConditionsInForce(f); err == nil {
		t.Fatal("a failed stop was reported as success")
	}
	f.failStop = false
	if _, err := putUpdaterConditionsInForce(f); err != nil {
		t.Fatal(err)
	}
	if !f.running || f.starts != 1 || f.marker != "" {
		t.Fatalf("rerun did not finish the restart: running=%v starts=%d marker=%q", f.running, f.starts, f.marker)
	}
}

// F2, second half (third review): the stop succeeded and the start failed. The rerun finds the service stopped and
// must still start it, because this program stopped it.
func TestStartFailureAfterOurStopIsCompletedByARerun(t *testing.T) {
	f := &fakeUpdater{changes: true, running: true, failStart: true}
	if _, err := putUpdaterConditionsInForce(f); err == nil {
		t.Fatal("a failed start was reported as success")
	}
	if f.running || f.marker != updaterMarkerStopped {
		t.Fatalf("after the failed start: running=%v marker=%q", f.running, f.marker)
	}
	f.failStart = false
	if _, err := putUpdaterConditionsInForce(f); err != nil {
		t.Fatal(err)
	}
	if !f.running || f.marker != "" {
		t.Fatalf("rerun left DsseUpdater stopped: running=%v marker=%q starts=%d", f.running, f.marker, f.starts)
	}
	// And a start that keeps failing keeps the debt.
	g := &fakeUpdater{marker: updaterMarkerStopped, failStart: true}
	if _, err := putUpdaterConditionsInForce(g); err == nil || g.marker != updaterMarkerStopped {
		t.Fatalf("a still-failing start cleared the record: err=%v marker=%q", err, g.marker)
	}
}

// A service an administrator stopped, with no record that this program stopped it, stays stopped.
func TestAdministratorStoppedUpdaterIsLeftStopped(t *testing.T) {
	f := &fakeUpdater{changes: true, running: false}
	if _, err := putUpdaterConditionsInForce(f); err != nil {
		t.Fatal(err)
	}
	if f.running || f.starts != 0 || f.marker != "" {
		t.Fatalf("an administrator's stop was overridden: running=%v starts=%d", f.running, f.starts)
	}
	g := &fakeUpdater{marker: updaterMarkerIntent, running: false}
	if _, err := putUpdaterConditionsInForce(g); err != nil {
		t.Fatal(err)
	}
	if g.running || g.starts != 0 {
		t.Fatal("an intent record started a service this program never stopped")
	}
}

// The record cannot be written before the change: nothing is changed.
func TestUnwritableRecordChangesNothing(t *testing.T) {
	f := &fakeUpdater{changes: true, running: true, failWrite: map[string]bool{updaterMarkerIntent: true}}
	if _, err := putUpdaterConditionsInForce(f); err == nil {
		t.Fatal("an unwritable record was reported as success")
	}
	if f.apply != 0 || f.stops != 0 {
		t.Fatalf("conditions were changed without a record: apply=%d stops=%d", f.apply, f.stops)
	}
	// The record of the stop cannot be written: the service is not stopped, and the intent stays for a rerun.
	g := &fakeUpdater{changes: true, running: true, failWrite: map[string]bool{updaterMarkerStopped: true}}
	if _, err := putUpdaterConditionsInForce(g); err == nil {
		t.Fatal("an unwritable stop record was reported as success")
	}
	if g.stops != 0 || g.marker != updaterMarkerIntent {
		t.Fatalf("stopped without a record of it: stops=%d marker=%q", g.stops, g.marker)
	}
	g.failWrite = nil
	if _, err := putUpdaterConditionsInForce(g); err != nil {
		t.Fatal(err)
	}
	if !g.running || g.stops != 1 || g.starts != 1 || g.marker != "" {
		t.Fatalf("rerun did not complete the owed restart: stops=%d starts=%d marker=%q", g.stops, g.starts, g.marker)
	}
}

// A record that cannot be read is not an absent one.
func TestUnreadableRecordIsAnError(t *testing.T) {
	f := &fakeUpdater{markerUnreadable: true, changes: true, running: true}
	if _, err := putUpdaterConditionsInForce(f); err == nil {
		t.Fatal("an unreadable record was treated as absent")
	}
	if f.apply != 0 {
		t.Fatal("conditions were changed while the record could not be read")
	}
	g := &fakeUpdater{marker: "something-else"}
	if _, err := putUpdaterConditionsInForce(g); err == nil {
		t.Fatal("an unknown record was accepted")
	}
}
