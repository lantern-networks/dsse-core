package accessdecision

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// The store is a RECENT-decision cache bounded by IDLE time (time-to-idle): a decision is kept alive by activity
// (Upsert of the same id, or a Get validating a same-flow event) and evicted only after it has gone quiet for
// ttl. These lock in that behaviour with an injected clock — the count-only "50000 accumulate in a 2-machine
// lab" bug is fixed WITHOUT cutting off a still-active long-lived flow (an hour-long download/stream).
func TestStoreTTLEvictsByIdle(t *testing.T) {
	var clock time.Time
	s := NewStoreWithTTL(1_000_000, 30*time.Minute) // count cap huge so ONLY the idle window can evict
	s.now = func() time.Time { return clock }
	base := time.Date(2026, 7, 11, 0, 0, 0, 0, time.UTC)

	clock = base
	s.Upsert(model.AccessDecision{ID: "d1"})
	clock = base.Add(10 * time.Minute)
	s.Upsert(model.AccessDecision{ID: "d2"})
	if s.Count() != 2 {
		t.Fatalf("both recent decisions retained, got %d", s.Count())
	}

	// d1 has had no activity for 31m (> 30m ttl); d2 for 21m. The next Upsert must expire only d1.
	clock = base.Add(31 * time.Minute)
	s.Upsert(model.AccessDecision{ID: "d3"})
	if _, ok := peek(s, "d1"); ok {
		t.Errorf("d1 (idle 31m > 30m ttl) must be evicted")
	}
	if _, ok := peek(s, "d2"); !ok {
		t.Errorf("d2 (idle 21m < ttl) must be retained")
	}
	if _, ok := peek(s, "d3"); !ok {
		t.Errorf("d3 (fresh) must be retained")
	}
	if s.Count() != 2 {
		t.Fatalf("count = %d, want 2 (d2,d3)", s.Count())
	}

	// Far in the future with no activity: even a single Upsert drains everything idle past the window.
	clock = base.Add(10 * time.Hour)
	s.Upsert(model.AccessDecision{ID: "d4"})
	if s.Count() != 1 {
		t.Fatalf("count = %d, want 1 (only d4 within window)", s.Count())
	}
	if _, ok := peek(s, "d4"); !ok {
		t.Errorf("d4 (fresh) must be retained")
	}
}

// TestStoreTTLKeepsActivelyReferencedDecision is the regression guard for the long-lived-flow case: a decision
// that keeps being referenced (an hour-long download whose inspection/tool-call events keep validating against
// it, each a Get) must survive far past its creation age — idle, not absolute-age, expiry. It must still expire
// once the flow finally goes quiet.
func TestStoreTTLKeepsActivelyReferencedDecision(t *testing.T) {
	var clock time.Time
	s := NewStoreWithTTL(1_000_000, 30*time.Minute)
	s.now = func() time.Time { return clock }
	base := time.Date(2026, 7, 11, 0, 0, 0, 0, time.UTC)

	clock = base
	s.Upsert(model.AccessDecision{ID: "flow"}) // long download starts

	// A same-flow event references the decision every 20 minutes for two hours (each Get is activity).
	for m := 20; m <= 120; m += 20 {
		clock = base.Add(time.Duration(m) * time.Minute)
		if _, ok := s.Get("flow"); !ok {
			t.Fatalf("at +%dm the actively-referenced decision was evicted (idle expiry cut off a live flow)", m)
		}
	}

	// Now the flow goes quiet. 31 minutes after the LAST reference (last Get at +120m), the next Upsert expires it.
	clock = base.Add(151 * time.Minute)
	s.Upsert(model.AccessDecision{ID: "other"})
	if _, ok := peek(s, "flow"); ok {
		t.Errorf("flow decision idle 31m after its last reference must finally be evicted")
	}
}

// TestStorePinnedSurvivesLongInFlightThenGraceAfterComplete is the core of the timeout design: a decision whose
// request is in flight is never evicted (no wall-clock ceiling — models a thin-bandwidth multi-hour download),
// and only after MarkComplete does the event-tail grace (ttl from completion) start.
func TestStorePinnedSurvivesLongInFlightThenGraceAfterComplete(t *testing.T) {
	var clock time.Time
	s := NewStoreWithTTL(10, 3*time.Minute)
	s.now = func() time.Time { return clock }
	base := time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)

	clock = base
	s.MarkInFlight(model.AccessDecision{ID: "dl"}) // long download starts (pinned)
	if s.InFlightCount() != 1 {
		t.Fatalf("InFlightCount = %d, want 1", s.InFlightCount())
	}

	// 10 hours in flight, with unrelated traffic churning the unpinned set the whole time — the pin must persist.
	for h := 1; h <= 10; h++ {
		clock = base.Add(time.Duration(h) * time.Hour)
		s.Upsert(model.AccessDecision{ID: "noise"}) // triggers eviction passes
		if _, ok := peek(s, "dl"); !ok {
			t.Fatalf("at +%dh the in-flight decision was evicted (a live flow must never be cut)", h)
		}
	}

	// Request completes. Grace runs from completion, not from creation 10h ago.
	clock = base.Add(10 * time.Hour)
	s.MarkComplete("dl")
	if s.InFlightCount() != 0 {
		t.Fatalf("InFlightCount = %d, want 0 after complete", s.InFlightCount())
	}
	if _, ok := peek(s, "dl"); !ok {
		t.Fatalf("just-completed decision must remain for the grace window")
	}
	// A same-flow event 2 min after completion still finds it (within 3-min grace) and refreshes it.
	clock = base.Add(10*time.Hour + 2*time.Minute)
	if _, ok := s.Get("dl"); !ok {
		t.Fatalf("same-flow event within grace must find the decision")
	}
	// 3m1s after the LAST activity (the Get), it is finally evicted.
	clock = base.Add(10*time.Hour + 2*time.Minute + 3*time.Minute + time.Second)
	s.Upsert(model.AccessDecision{ID: "noise2"})
	if _, ok := peek(s, "dl"); ok {
		t.Fatalf("decision idle past the grace after completion must be evicted")
	}
}

// TestStorePinnedUncountedByCapacity proves capacity bounds only the UNPINNED set; pinned (live) flows are never
// dropped to satisfy the cap, and are not counted toward it.
func TestStorePinnedUncountedByCapacity(t *testing.T) {
	s := NewStore(2) // unpinned cap = 2, no ttl
	s.MarkInFlight(model.AccessDecision{ID: "p1"})
	s.MarkInFlight(model.AccessDecision{ID: "p2"})
	s.MarkInFlight(model.AccessDecision{ID: "p3"}) // 3 pinned, all exempt from the cap of 2
	for _, id := range []string{"u1", "u2", "u3", "u4"} {
		s.Upsert(model.AccessDecision{ID: id}) // unpinned, cap 2 => only last two survive
	}
	if s.InFlightCount() != 3 {
		t.Fatalf("InFlightCount = %d, want 3 (pins never dropped by the cap)", s.InFlightCount())
	}
	for _, id := range []string{"p1", "p2", "p3"} {
		if _, ok := peek(s, id); !ok {
			t.Errorf("pinned %s must survive cap pressure", id)
		}
	}
	if _, ok := peek(s, "u1"); ok {
		t.Errorf("unpinned u1 must be evicted by the cap")
	}
	if _, ok := peek(s, "u4"); !ok {
		t.Errorf("newest unpinned u4 must survive")
	}
	if s.Count() != 5 { // 3 pinned + 2 unpinned
		t.Fatalf("Count = %d, want 5 (3 pinned + 2 unpinned)", s.Count())
	}
}

func TestStoreCountBackstopStillBoundsWhenTTLDisabled(t *testing.T) {
	s := NewStore(3) // ttl=0 => count-only (back-compat)
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		s.Upsert(model.AccessDecision{ID: id})
	}
	if s.Count() != 3 {
		t.Fatalf("count = %d, want 3 (FIFO backstop)", s.Count())
	}
	if _, ok := peek(s, "a"); ok {
		t.Errorf("least-recently-active 'a' must be evicted by the count cap")
	}
	if _, ok := peek(s, "e"); !ok {
		t.Errorf("newest 'e' must be retained")
	}
}

// peek reads a decision WITHOUT the activity refresh Get performs, so assertions about eviction do not themselves
// keep an entry alive.
func peek(s *Store, id string) (model.AccessDecision, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	node, ok := s.entries[id]
	if !ok {
		return model.AccessDecision{}, false
	}
	return node.dec, true
}
