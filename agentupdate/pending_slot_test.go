package agentupdate

import (
	"testing"
	"time"
)

// ★★ TWO OUTCOMES, ONE SLOT — AND THE ONE THAT DOES NOT FIT IS NOW COUNTED (2026-08-14, thirty-first review).
// The callers guarded on `PendingReport == nil` and dropped the newer outcome. Correct about WHICH to keep: the
// older one has been owed longer, and the newer failure is usually a consequence of the same trouble. Silent
// about the loss, which is the defect — a device that discarded an outcome and a device that never had one
// were the same journal, so the fleet's picture was short by one with nothing anywhere saying so.
func TestTheOutcomeThatDoesNotFitIsRecordedRatherThanDropped(t *testing.T) {
	now := time.Date(2026, 8, 14, 9, 0, 0, 0, time.UTC)
	j := &Journal{}

	first := Report{ID: "r1", Status: ReportFailed, TargetVersion: "0.2.4"}
	if !j.MarkReportPendingIfFree(first) {
		t.Fatal("the first outcome did not take an empty slot")
	}
	if j.DroppedOwedOutcomes != 0 {
		t.Fatalf("a slot that was free counted a drop: %d", j.DroppedOwedOutcomes)
	}

	second := Report{ID: "r2", Status: ReportFailed, TargetVersion: "0.2.5"}
	if j.MarkReportPendingIfFree(second) {
		t.Fatal("the second outcome overwrote a slot that was already owed — that loses the older one")
	}
	if j.PendingReport == nil || j.PendingReport.ID != "r1" {
		t.Fatalf("the slot no longer holds the outcome that had been owed longer: %+v", j.PendingReport)
	}
	if j.DroppedOwedOutcomes != 1 {
		t.Fatalf("dropped %d, want 1 — a discarded outcome that is not counted is indistinguishable from one "+
			"that never existed", j.DroppedOwedOutcomes)
	}
	if j.LastDroppedOwedOutcome == "" {
		t.Fatal("the journal counts the loss but cannot say WHAT was lost, so --status can only report a number")
	}

	// A third keeps counting: the shortfall is a running total, not a boolean.
	j.MarkReportPendingIfFree(Report{ID: "r3", Status: ReportFailed, TargetVersion: "0.2.6"})
	if j.DroppedOwedOutcomes != 2 {
		t.Fatalf("dropped %d after two failures to fit, want 2", j.DroppedOwedOutcomes)
	}
	_ = now
}

// Once the slot is drained, the next outcome takes it and nothing is counted — the counter must record real
// losses only, or it becomes noise on every healthy device.
func TestADrainedSlotTakesTheNextOutcomeWithoutCounting(t *testing.T) {
	j := &Journal{}
	j.MarkReportPendingIfFree(Report{ID: "r1", Status: ReportFailed})
	j.ClearReportPending()
	if !j.MarkReportPendingIfFree(Report{ID: "r2", Status: ReportFailed}) {
		t.Fatal("a drained slot refused the next outcome")
	}
	if j.DroppedOwedOutcomes != 0 {
		t.Fatalf("counted %d drops on a device that lost nothing", j.DroppedOwedOutcomes)
	}
}
