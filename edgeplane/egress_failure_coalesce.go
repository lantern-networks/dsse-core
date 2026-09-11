package edgeplane

import (
	"sync"
	"time"
)

// egress_failure_coalesce.go — a same-target coalescer for repeated egress failures (the design's "can be hot
// under a broken connector, so rate-limit").
//
// steer_mux_egress_failed is a GENUINE error and must stay at ERROR: it means a steered flow could not reach its
// destination. But its rate is set by the CLIENT, not by the operator — a browser retrying one unreachable host
// emits an ERROR per attempt. Measured live: five identical lines for the same IPv6 literal within one second.
//
// That breaks Plane A's contract in the way that actually costs you an incident: the log is not merely noisy, it
// TRAINS the operator to ignore the line. Then the one egress failure that mattered scrolls past unread.
//
// So: report the first failure for a target immediately (never delay the signal), suppress identical repeats for
// a window, and emit one summary carrying the suppressed count when the window closes. Nothing is lost — the
// count is the information a storm actually carries ("still broken, 400 times") — and a NEW target is always
// reported at once.

const EgressFailureCoalesceWindow = 30 * time.Second

type egressFailureCoalescerEntry struct {
	firstAt    time.Time
	suppressed int
}

type egressFailureCoalescer struct {
	mu      sync.Mutex
	window  time.Duration
	entries map[string]*egressFailureCoalescerEntry
	now     func() time.Time
}

func newEgressFailureCoalescer(window time.Duration, now func() time.Time) *egressFailureCoalescer {
	if window <= 0 {
		window = EgressFailureCoalesceWindow
	}
	if now == nil {
		now = time.Now
	}
	return &egressFailureCoalescer{window: window, entries: map[string]*egressFailureCoalescerEntry{}, now: now}
}

// observe reports whether this failure should be logged now, and how many identical failures were suppressed
// since the last report. report=true with suppressed=0 is a first/new failure; report=true with suppressed>0 is
// the window's summary.
func (c *egressFailureCoalescer) Observe(key string) (report bool, suppressed int) {
	if c == nil {
		return true, 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	entry, ok := c.entries[key]
	if !ok {
		c.entries[key] = &egressFailureCoalescerEntry{firstAt: now}
		return true, 0
	}
	if now.Sub(entry.firstAt) >= c.window {
		n := entry.suppressed
		entry.firstAt = now
		entry.suppressed = 0
		return true, n
	}
	entry.suppressed++
	return false, 0
}

// forget drops a target's state — call when a target starts working again so its next failure is reported
// immediately rather than being swallowed by a stale window.
func (c *egressFailureCoalescer) Forget(key string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	delete(c.entries, key)
	c.mu.Unlock()
}

var SteerEgressFailureCoalescer = newEgressFailureCoalescer(EgressFailureCoalesceWindow, nil)
