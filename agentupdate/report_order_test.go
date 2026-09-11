package agentupdate

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// report_order_test.go — the outbox ships in the order the outcomes happened, and the whole chain depends on
// it: DrainReports's order becomes the order the Edge receives them, which becomes their created_at, which is
// how the control plane breaks a tie between two outcomes from the same second.
//
// ★ THE ID DID NOT SORT (2026-08-12, sixteenth review). `aue_<nano>_<seq>` with unpadded fields puts `_9`
// after `_10` under every text sort in this file — so the ninth outcome shipped last, arrived last, and was
// served as the current one. Correcting the database tie-break did not touch it: the records were already
// arriving reversed.

func TestTenReportsFromOneTickDrainInTheOrderTheyHappened(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "reports")
	// ONE instant for all of them: this is the case the counter exists for, and the one that broke.
	now := time.Date(2026, 8, 12, 9, 0, 0, 0, time.UTC)

	want := []string{}
	for i := 1; i <= 12; i++ {
		r := Report{DeviceID: "d-1", TenantID: "t", Status: ReportFailed,
			TargetVersion: "0.2.9", Reason: "attempt " + itoa(i), At: now.Format(time.RFC3339)}
		r.ID = newReportID(now)
		if err := AppendReport(dir, r); err != nil {
			t.Fatal(err)
		}
		want = append(want, r.Reason)
	}

	got := []string{}
	if _, _, err := DrainReports(dir, func(r Report) error { got = append(got, r.Reason); return nil }); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("the outbox drained out of order.\n want %v\n got  %v\n"+
			"The Edge records them in the order they arrive and breaks a same-second tie by that order, so a "+
			"reversal here is the wrong outcome being shown as this device's current state.", want, got)
	}
}

// And the files an EARLIER build left behind — unpadded ids — must drain in their real order too, because a
// device that upgrades with a backlog has both shapes in the directory at once.
//
// ★ THE FIXTURE IS BUILT BY AppendReport (2026-08-12, seventeenth review). The first version of this test
// wrote `aue_<nano>_<seq>.json` by hand — a filename this code has never produced — so it exercised a parse
// that could not run against a real device and passed while the bug it named was untouched. The real name
// carries a timestamp prefix. Here the reports are written by the production path and then RENAMED to the
// unpadded id an older build would have given them, which is the only difference between the two builds.
func TestABacklogWrittenByAnEarlierBuildStillDrainsInOrder(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "reports")
	at := time.Date(2026, 8, 12, 9, 0, 0, 0, time.UTC)
	nano := at.UnixNano()

	for _, seq := range []int{9, 10, 11} {
		r := Report{DeviceID: "d-1", TenantID: "t", Status: ReportFailed, TargetVersion: "0.2.9",
			Reason: "attempt " + itoa(seq), At: at.Format(time.RFC3339)}
		r.ID = "aue_" + itoa64(nano) + "_" + itoa(seq) // the OLD, unpadded shape
		if err := AppendReport(dir, r); err != nil {
			t.Fatal(err)
		}
	}
	// Everything in the directory must be a name AppendReport actually writes, or this proves nothing.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.Contains(e.Name(), "-aue_") {
			t.Fatalf("fixture %q is not the shape AppendReport produces; the test would be exercising a parse "+
				"that never runs on a device", e.Name())
		}
	}

	got := []string{}
	if _, _, err := DrainReports(dir, func(r Report) error { got = append(got, r.Reason); return nil }); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "attempt 9,attempt 10,attempt 11" {
		t.Fatalf("a backlog from an earlier build drained as %v — a text sort puts _10 and _11 before _9, and "+
			"these are the files already sitting on devices", got)
	}
}

func itoa(i int) string     { return strconv.Itoa(i) }
func itoa64(i int64) string { return strconv.FormatInt(i, 10) }
