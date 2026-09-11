package agentupdate

// report_quarantine.go — when an outcome cannot be queued, how many times is it worth trying, and what happens
// after that.

import (
	"fmt"
	"strings"
	"time"
)

// DefaultReportMaxAttempts is how many consecutive failures to QUEUE one outcome are worth suffering before the
// device stops holding itself back over it.
//
// Ten, not three: queueing is a local file append, so a failure is a full disk, a permissions change, or an
// unwritable directory — conditions that are often transient and always worth several passes at half-hourly
// intervals. Three would quarantine a laptop that was briefly full.
const DefaultReportMaxAttempts = 10

// RecordReportQueueFailure counts a failure to put the owed outcome in the outbox, and reports whether the
// device has now given up on it.
//
// ★★ THE MECHANISM DID NOT EXIST (2026-08-13, thirty-first review #10, gate 4). A pending report was retried
// for ever, and a pass STOPS while an outcome is owed — so a device that could not queue one outcome could
// never update again. Not "reported late": never. The condition that produced it (a disk that filled once, a
// report the store refused) outlives its own cause, and nothing in the fleet view distinguishes such a device
// from one that is simply up to date.
//
// This is the self-jam family the release-channel findings kept producing, in its general form: a device
// holding itself back for ever over bookkeeping it cannot complete.
//
// ★ AND THE OUTCOME IS NOT DISCARDED SILENTLY. It is moved into Quarantined, which persists, is printed by
// --status, and names what was lost. The trade is stated rather than hidden: an outcome the fleet never hears
// about is bad, and a device that can never update again is worse — the first is a gap in a report, the second
// is an endpoint that stops receiving security fixes. This product's rule that no record is worse than a
// duplicate is about records it CAN write; this is the case where it cannot.
func (j *Journal) RecordReportQueueFailure(reason string, maxAttempts int, now time.Time) (quarantined bool) {
	if j == nil || j.PendingReport == nil {
		return false
	}
	if maxAttempts <= 0 {
		maxAttempts = DefaultReportMaxAttempts
	}
	j.PendingReportAttempts++
	if j.PendingReportAttempts < maxAttempts {
		return false
	}

	lost := j.PendingReport.Report
	label := strings.TrimSpace(lost.ID)
	if label == "" {
		label = strings.TrimSpace(lost.Status)
	}
	j.Quarantined = append(j.Quarantined, QuarantinedReport{
		ID:       label,
		Status:   strings.TrimSpace(lost.Status),
		Version:  strings.TrimSpace(lost.TargetVersion),
		At:       now.UTC().Format(time.RFC3339),
		Attempts: j.PendingReportAttempts,
		Reason:   strings.TrimSpace(reason),
	})
	// ★ The MARKER is set as well, so OwesOutcomeReport stops being true for this terminal state. Without it the
	// next pass would rebuild the same pending report from the same journal and the device would be held again —
	// the quarantine would be a comment rather than a release.
	j.ReportedOutcome = j.OutcomeFingerprint()
	j.ReportedOutcomeEarned = false
	j.ReportedOutcomeAssumed = false
	j.PendingReport = nil
	j.PendingReportAttempts = 0
	return true
}

// ClearReportQueueFailures resets the counter after a successful queue, so ten failures spread over a year do
// not add up to a quarantine.
func (j *Journal) ClearReportQueueFailures() {
	if j != nil {
		j.PendingReportAttempts = 0
	}
}

// DescribeQuarantine is the one line --status needs: what this device gave up telling the fleet.
func (j *Journal) DescribeQuarantine() string {
	if j == nil || len(j.Quarantined) == 0 {
		return ""
	}
	parts := make([]string, 0, len(j.Quarantined))
	for _, q := range j.Quarantined {
		parts = append(parts, fmt.Sprintf("%s (%s, %d attempts, %s)", q.Status, q.Version, q.Attempts, q.Reason))
	}
	return fmt.Sprintf("★ %d outcome(s) this device GAVE UP reporting and the fleet will never hear: %s",
		len(j.Quarantined), strings.Join(parts, "; "))
}
