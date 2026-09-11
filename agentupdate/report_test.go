package agentupdate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func reportAt(t *testing.T, dir string, at time.Time, status, target string) {
	t.Helper()
	r := ReportFromJournal(&Journal{TargetVersion: target}, status, "", at)
	if err := AppendReport(dir, r); err != nil {
		t.Fatalf("append: %v", err)
	}
}

// Reports go out OLDEST FIRST, because "failed, then installed" and "installed, then failed" are different
// stories about the same device.
func TestReportsDrainInOrder(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "reports")
	base := time.Date(2026, 8, 12, 1, 0, 0, 0, time.UTC)
	reportAt(t, dir, base, ReportFailed, "0.2.5")
	reportAt(t, dir, base.Add(time.Minute), ReportInstalled, "0.2.6")
	reportAt(t, dir, base.Add(2*time.Minute), ReportRolledBack, "0.2.4")

	var got []string
	sent, corrupt, err := DrainReports(dir, func(r Report) error {
		got = append(got, r.Status+":"+r.TargetVersion)
		return nil
	})
	if err != nil || corrupt != 0 || sent != 3 {
		t.Fatalf("drain: sent=%d corrupt=%d err=%v", sent, corrupt, err)
	}
	want := []string{"failed:0.2.5", "installed:0.2.6", "rolled_back:0.2.4"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("out of order: %v, want %v", got, want)
		}
	}
	if n := PendingReports(dir); n != 0 {
		t.Fatalf("%d report(s) remain after a clean drain", n)
	}
}

// ★ A REPORT THE EDGE DID NOT ACCEPT IS NOT DELIVERED. Stopping at the failure keeps order AND keeps the
// event: a drain that skipped ahead would silently reorder this device's history, and one that deleted on
// error would lose the outcome entirely.
func TestADrainStopsAtTheFirstFailureAndKeepsEverythingAfterIt(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "reports")
	base := time.Date(2026, 8, 12, 1, 0, 0, 0, time.UTC)
	for i, st := range []string{ReportFailed, ReportInstalled, ReportRolledBack} {
		reportAt(t, dir, base.Add(time.Duration(i)*time.Minute), st, fmt.Sprintf("0.2.%d", i))
	}

	calls := 0
	sent, _, err := DrainReports(dir, func(Report) error {
		calls++
		if calls == 2 {
			return errors.New("the edge is unreachable")
		}
		return nil
	})
	if err == nil {
		t.Fatalf("a failing send was reported as success")
	}
	if sent != 1 {
		t.Fatalf("sent=%d, want 1 (the one that was accepted)", sent)
	}
	if n := PendingReports(dir); n != 2 {
		t.Fatalf("%d report(s) waiting, want 2 — the failed one and the one behind it", n)
	}
	// And the next drain resumes with the one that failed, not the one after it.
	var first string
	if _, _, derr := DrainReports(dir, func(r Report) error { //nolint:errcheck // asserted below
		if first == "" {
			first = r.TargetVersion
		}
		return nil
	}); derr != nil {
		t.Fatalf("second drain: %v", derr)
	}
	if first != "0.2.1" {
		t.Fatalf("the retry began at %q, skipping the report that failed", first)
	}
}

// ★ AN OFFLINE DEVICE MUST NOT COME BACK WITH A TIDY HISTORY THAT BEGINS IN THE MIDDLE. The cap is necessary;
// hiding that it was hit is not.
func TestDroppedReportsAreDeclaredOnTheNextOneThatGetsOut(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "reports")
	base := time.Date(2026, 8, 12, 1, 0, 0, 0, time.UTC)
	for i := 0; i < maxStoredReports+5; i++ {
		reportAt(t, dir, base.Add(time.Duration(i)*time.Second), ReportInstalled, "0.2.7")
	}
	if n := PendingReports(dir); n != maxStoredReports {
		t.Fatalf("the directory is unbounded: %d stored", n)
	}

	var firstDeclared int
	seen := 0
	if _, _, err := DrainReports(dir, func(r Report) error {
		if seen == 0 {
			firstDeclared = r.DroppedBefore
		}
		seen++
		return nil
	}); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if firstDeclared != 5 {
		t.Fatalf("the first report declared %d dropped, want 5", firstDeclared)
	}
	// Declared once, not on every report afterwards.
	reportAt(t, dir, base.Add(time.Hour), ReportInstalled, "0.2.8")
	if _, _, err := DrainReports(dir, func(r Report) error {
		if r.DroppedBefore != 0 {
			t.Fatalf("the same drop was declared twice (%d)", r.DroppedBefore)
		}
		return nil
	}); err != nil {
		t.Fatalf("second drain: %v", err)
	}
}

// A file that cannot be parsed must not block every report behind it forever.
func TestAnUnreadableReportIsCountedAndRemoved(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "reports")
	base := time.Date(2026, 8, 12, 1, 0, 0, 0, time.UTC)
	reportAt(t, dir, base, ReportInstalled, "0.2.7")
	if err := os.WriteFile(filepath.Join(dir, "20260812T0059Z-broken.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	sent, corrupt, err := DrainReports(dir, func(Report) error { return nil })
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if sent != 1 || corrupt != 1 {
		t.Fatalf("sent=%d corrupt=%d, want 1 and 1", sent, corrupt)
	}
	if n := PendingReports(dir); n != 0 {
		t.Fatalf("%d file(s) left behind", n)
	}
}

// A rollback and an update must not read the same in a fleet view.
func TestARollbackIsReportedAsOne(t *testing.T) {
	now := time.Now().UTC()
	j := &Journal{TargetVersion: "0.2.4", FromVersion: "0.2.5", AttemptKind: KindRollback}
	r := ReportFromJournal(j, ReportRolledBack, "operator", now)
	if r.Kind != "rollback" {
		t.Fatalf("a rollback was reported as %q", r.Kind)
	}
	if r.FromVersion != "0.2.5" || r.TargetVersion != "0.2.4" {
		t.Fatalf("the direction was lost: from=%q target=%q", r.FromVersion, r.TargetVersion)
	}
	u := ReportFromJournal(&Journal{TargetVersion: "0.2.7", FromVersion: "0.2.4"}, ReportInstalled, "", now)
	if u.Kind != "update" {
		t.Fatalf("an update was reported as %q", u.Kind)
	}
}

// ★ A REFUSAL REPEATS BY NATURE. Reporting it every tick would bury the fleet view in one device's repetition;
// not reporting it at all leaves the devices an operator most needs to see invisible. Once per distinct
// reason is the middle.
func TestARefusalIsReportedOncePerDistinctReason(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "reports")
	stage := RefusalFingerprint("0.2.5", "could not stage the artifact")
	refusal := func() Report {
		return ReportFromJournal(&Journal{TargetVersion: "0.2.5"}, ReportRefused, "could not stage",
			time.Now().UTC())
	}

	queued, err := AppendRefusal(dir, refusal(), stage)
	if err != nil || !queued {
		t.Fatalf("the first refusal was not queued: %v", err)
	}
	if q, _ := AppendRefusal(dir, refusal(), stage); q {
		t.Fatalf("the same refusal was queued twice — a device would send this every tick forever")
	}
	// A DIFFERENT refusal is a new event.
	if q, _ := AppendRefusal(dir, refusal(), RefusalFingerprint("0.2.5", "the manifest does not verify")); !q {
		t.Fatalf("a different refusal was suppressed as a repeat")
	}
	// And after something progresses, the same refusal counts again.
	ClearRefusal(dir)
	if q, _ := AppendRefusal(dir, refusal(), stage); !q {
		t.Fatalf("a refusal seen again after progress was suppressed")
	}
}

// ★ THE REPORT IS STORED BEFORE THE SUPPRESSION MARKER. The other order leaves a device permanently silent
// about a refusal it never managed to record: the marker says "reported", the outbox holds nothing, and every
// later tick matches the marker.
func TestARefusalIsStoredBeforeItIsSuppressed(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "reports")
	fp := RefusalFingerprint("0.2.5", "could not stage")
	r := ReportFromJournal(&Journal{TargetVersion: "0.2.5"}, ReportRefused, "could not stage", time.Now().UTC())
	if _, err := AppendRefusal(dir, r, fp); err != nil {
		t.Fatalf("append: %v", err)
	}
	if n := PendingReports(dir); n != 1 {
		t.Fatalf("the refusal was suppressed without being stored: %d waiting", n)
	}
	if !RefusalAlreadyReported(dir, fp) {
		t.Fatalf("the marker was not written after a successful store")
	}
}

// ★ EVERY OUTCOME GETS ITS OWN ID, even when a pass produces two from one timestamp. Sharing the id meant the
// second AppendReport renamed over the first: one outcome simply vanished.
func TestTwoOutcomesFromOneTimestampDoNotCollide(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "reports")
	now := time.Date(2026, 8, 12, 1, 0, 0, 0, time.UTC)
	a := ReportOutcome(&Journal{TargetVersion: "0.2.7"}, ReportInstalled, "0.2.7", "landed", now)
	b := ReportOutcome(&Journal{TargetVersion: "0.2.8"}, ReportRefused, "0.2.7", "could not stage", now)
	if a.ID == b.ID {
		t.Fatalf("two outcomes from one tick share an id (%s): one would overwrite the other", a.ID)
	}
	if err := AppendReport(dir, a); err != nil {
		t.Fatal(err)
	}
	if err := AppendReport(dir, b); err != nil {
		t.Fatal(err)
	}
	if n := PendingReports(dir); n != 2 {
		t.Fatalf("%d report(s) stored, want 2 — one overwrote the other", n)
	}
}

// ★ A DROP RECORDED WHILE A REPORT IS IN FLIGHT MUST NOT BE ERASED BY ITS DELIVERY. The ledger is claimed by
// rename, so the producer's next addition starts a new one.
func TestDropsRecordedDuringDeliveryAreNotLost(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "reports")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := addDropped(dir, 4); err != nil {
		t.Fatal(err)
	}
	reportAt(t, dir, time.Now().UTC(), ReportInstalled, "0.2.7")

	var declared int
	if _, _, err := DrainReports(dir, func(r Report) error {
		declared = r.DroppedBefore
		// The producer overflows again WHILE this send is in flight.
		return addDropped(dir, 3)
	}); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if declared != 4 {
		t.Fatalf("the report declared %d dropped, want 4", declared)
	}
	if n := readDropped(dir); n != 3 {
		t.Fatalf("the ledger holds %d, want 3 — drops recorded during delivery were erased", n)
	}
}

// And a report that was NOT accepted puts its claim back, rather than swallowing the count.
func TestAnUndeliveredDropClaimIsRestored(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "reports")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := addDropped(dir, 5); err != nil {
		t.Fatal(err)
	}
	reportAt(t, dir, time.Now().UTC(), ReportInstalled, "0.2.7")

	if _, _, err := DrainReports(dir, func(Report) error {
		return errors.New("the edge is unreachable")
	}); err == nil {
		t.Fatalf("a failing send was reported as success")
	}
	if n := readDropped(dir); n != 5 {
		t.Fatalf("the ledger holds %d, want 5 — an undelivered claim was swallowed", n)
	}
}

// The producers build reports from the JOURNAL, which is the only place from_version lives. Building them by
// hand is how that field ended up populated only by tests.
func TestReportOutcomeCarriesTheJournalsDirection(t *testing.T) {
	now := time.Now().UTC()
	j := &Journal{TargetVersion: "0.2.7", FromVersion: "0.2.4"}
	r := ReportOutcome(j, ReportInstalled, "0.2.7+2026", "landed", now)
	if r.FromVersion != "0.2.4" || r.TargetVersion != "0.2.7" {
		t.Fatalf("the direction was lost: from=%q target=%q", r.FromVersion, r.TargetVersion)
	}
	if r.RunningVersion != "0.2.7+2026" {
		t.Fatalf("the running version was lost: %q", r.RunningVersion)
	}
	if r.ID == "" {
		t.Fatalf("a report with no id cannot be retried idempotently")
	}
}

// ★★ GATE 4: A DEVICE MUST NOT HOLD ITSELF BACK FOR EVER OVER BOOKKEEPING (2026-08-13, thirty-first review
// #10). A pass stops while an outcome is owed, and a pending report was retried without limit — so a device
// that could not queue ONE outcome could never update again. Not late: never. The condition (a disk that
// filled once, an outbox that refused a report) outlives its own cause, and nothing in the fleet view tells
// such a device from one that is up to date.
func TestAnOutcomeThatCannotBeQueuedStopsHoldingTheDeviceBack(t *testing.T) {
	now := time.Now().UTC()
	j := NewJournal()
	j.Begin("0.3.0", "0.2.9", now)
	j.Enter(PhaseFailed, now)
	j.MarkReportPending(Report{ID: "aue_x", Status: ReportFailed, TargetVersion: "0.3.0",
		At: now.Format(time.RFC3339)})

	for attempt := 1; attempt < DefaultReportMaxAttempts; attempt++ {
		if j.RecordReportQueueFailure("no space left on device", DefaultReportMaxAttempts, now) {
			t.Fatalf("gave up after %d attempts; a transient full disk deserves several passes", attempt)
		}
		if j.PendingReport == nil {
			t.Fatalf("attempt %d dropped the report while still retrying it", attempt)
		}
	}

	if !j.RecordReportQueueFailure("no space left on device", DefaultReportMaxAttempts, now) {
		t.Fatal("the device is still holding an outcome it cannot queue, so it can never update again")
	}
	if j.PendingReport != nil {
		t.Fatal("the report is still pending, so the pass will keep stopping on it")
	}
	if j.OwesOutcomeReport() {
		t.Fatal("the outcome is still owed — the quarantine would be a comment rather than a release, and the " +
			"next pass would rebuild the same pending report from the same journal")
	}

	// ★ AND IT IS NOT DISCARDED SILENTLY. The fleet will never hear about this outcome, which must be
	// discoverable directly rather than by subtraction from a report that does not mention it.
	if len(j.Quarantined) != 1 || j.Quarantined[0].Status != ReportFailed {
		t.Fatalf("nothing recorded what was lost: %+v", j.Quarantined)
	}
	line := j.DescribeQuarantine()
	if !strings.Contains(line, "GAVE UP") || !strings.Contains(line, "0.3.0") {
		t.Fatalf("the operator-facing line does not say what was lost: %q", line)
	}
}

// A success resets the counter, or ten failures spread over a year would add up to a quarantine.
func TestASuccessfulQueueForgetsEarlierFailures(t *testing.T) {
	now := time.Now().UTC()
	j := NewJournal()
	j.Begin("0.3.0", "0.2.9", now)
	j.Enter(PhaseFailed, now)
	j.MarkReportPending(Report{ID: "aue_x", Status: ReportFailed, At: now.Format(time.RFC3339)})

	for i := 0; i < DefaultReportMaxAttempts-1; i++ {
		j.RecordReportQueueFailure("transient", DefaultReportMaxAttempts, now)
	}
	j.ClearReportQueueFailures()
	if j.PendingReportAttempts != 0 {
		t.Fatalf("attempts = %d", j.PendingReportAttempts)
	}
	if j.RecordReportQueueFailure("transient", DefaultReportMaxAttempts, now) {
		t.Fatal("one failure after a success quarantined the outcome")
	}
}

// The quarantine survives a restart: an operator reading --status tomorrow must still be told.
func TestTheQuarantineSurvivesAReload(t *testing.T) {
	now := time.Now().UTC()
	j := NewJournal()
	j.Begin("0.3.0", "0.2.9", now)
	j.Enter(PhaseFailed, now)
	j.MarkReportPending(Report{ID: "aue_x", Status: ReportFailed, TargetVersion: "0.3.0",
		At: now.Format(time.RFC3339)})
	for i := 0; i < DefaultReportMaxAttempts; i++ {
		j.RecordReportQueueFailure("no space left on device", DefaultReportMaxAttempts, now)
	}
	path := writeJournal(t, j)
	reloaded, err := LoadJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.Quarantined) != 1 {
		t.Fatalf("the record of what the fleet never heard did not survive: %+v", reloaded.Quarantined)
	}
}
