package edgeplane

import (
	"testing"
	"time"
)

func TestEgressFailureCoalescerReportsFirstFailureImmediately(t *testing.T) {
	now := time.Now()
	c := newEgressFailureCoalescer(30*time.Second, func() time.Time { return now })
	report, suppressed := c.Observe("host|443")
	if !report || suppressed != 0 {
		t.Fatalf("first failure: report=%v suppressed=%d, want true/0 — the signal must never be delayed", report, suppressed)
	}
}

func TestEgressFailureCoalescerSuppressesRepeatsWithinTheWindow(t *testing.T) {
	now := time.Now()
	c := newEgressFailureCoalescer(30*time.Second, func() time.Time { return now })
	c.Observe("host|443")
	for i := 0; i < 400; i++ {
		if report, _ := c.Observe("host|443"); report {
			t.Fatalf("repeat %d reported inside the window; a client retry loop would set the log rate", i)
		}
	}
}

// The count is the information a storm carries: "still broken, N times". Losing it would make coalescing a
// silent drop rather than a summary.
func TestEgressFailureCoalescerSummarisesSuppressedCountWhenTheWindowCloses(t *testing.T) {
	now := time.Now()
	c := newEgressFailureCoalescer(30*time.Second, func() time.Time { return now })
	c.Observe("host|443")
	for i := 0; i < 5; i++ {
		c.Observe("host|443")
	}
	now = now.Add(31 * time.Second)
	report, suppressed := c.Observe("host|443")
	if !report || suppressed != 5 {
		t.Fatalf("window close: report=%v suppressed=%d, want true/5", report, suppressed)
	}
}

// A different target is a different fact — one broken host must never mask another.
func TestEgressFailureCoalescerReportsEachTargetIndependently(t *testing.T) {
	now := time.Now()
	c := newEgressFailureCoalescer(30*time.Second, func() time.Time { return now })
	c.Observe("host-a|443")
	if report, _ := c.Observe("host-b|443"); !report {
		t.Fatal("a second target was suppressed by the first target's window")
	}
}

// After recovery the next failure is news again, not a "repeat" of a resolved storm.
func TestEgressFailureCoalescerForgetMakesTheNextFailureReportable(t *testing.T) {
	now := time.Now()
	c := newEgressFailureCoalescer(30*time.Second, func() time.Time { return now })
	c.Observe("host|443")
	if report, _ := c.Observe("host|443"); report {
		t.Fatal("repeat reported inside the window")
	}
	c.Forget("host|443")
	if report, suppressed := c.Observe("host|443"); !report || suppressed != 0 {
		t.Fatalf("after recovery: report=%v suppressed=%d, want true/0", report, suppressed)
	}
}
