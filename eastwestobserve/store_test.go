package eastwestobserve

import (
	"testing"
	"time"
)

func TestObserveUpsertAndCount(t *testing.T) {
	s := NewStore()
	t0 := time.Date(2026, 7, 14, 10, 0, 0, 0, time.UTC)

	o1 := s.Observe("t1", "mac-dev-1", "alice", "10.20.0.10", "ssh", 22, t0)
	if o1.Count != 1 || o1.Source != "mac-dev-1" || o1.ServiceFamily != "ssh" || o1.FirstSeen == "" {
		t.Fatalf("first observe: %+v", o1)
	}
	if o1.User != "alice" || !o1.Human() {
		t.Fatalf("observe must record the logged-in user (human): %+v", o1)
	}
	// Same flow again -> upsert (count++, lastSeen refreshed).
	t1 := t0.Add(time.Minute)
	o2 := s.Observe("t1", "mac-dev-1", "alice", "10.20.0.10", "ssh", 22, t1)
	if o2.ObservationID != o1.ObservationID {
		t.Fatalf("same flow must upsert one record: %s vs %s", o2.ObservationID, o1.ObservationID)
	}
	if o2.Count != 2 || o2.FirstSeen != o1.FirstSeen || o2.LastSeen != t1.Format(time.RFC3339) {
		t.Fatalf("upsert: %+v", o2)
	}
	if got := s.List("t1"); len(got) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(got))
	}
}

func TestObserveUserReattribution(t *testing.T) {
	// The same device→dest flow re-attributes to whoever last made it: human (alice) then unattended (empty) →
	// the flow reads as SYSTEM. This is the human-vs-system signal the operator needs.
	s := NewStore()
	base := time.Date(2026, 7, 14, 10, 0, 0, 0, time.UTC)
	h := s.Observe("t1", "mac-dev-1", "alice", "10.20.0.10", "ssh", 22, base)
	if !h.Human() {
		t.Fatalf("first sighting with a user must be human")
	}
	sys := s.Observe("t1", "mac-dev-1", "", "10.20.0.10", "ssh", 22, base.Add(time.Minute))
	if sys.ObservationID != h.ObservationID {
		t.Fatalf("same flow key must upsert one record")
	}
	if sys.User != "" || sys.Human() {
		t.Fatalf("re-attribution to no user must flip the flow to system: %+v", sys)
	}
}

func TestObserveSourceDefaultsToAny(t *testing.T) {
	s := NewStore()
	o := s.Observe("t1", "", "", "10.20.0.20", "smb", 445, time.Now())
	if o.Source != SourceAny {
		t.Fatalf("empty source must record %q, got %q", SourceAny, o.Source)
	}
	if o.User != "" || o.Human() {
		t.Fatalf("no logged-in user must be system (not human): %+v", o)
	}
	// A different source to the same dest is a DISTINCT flow (source axis).
	o2 := s.Observe("t1", "win-dev-1", "", "10.20.0.20", "smb", 445, time.Now())
	if o2.ObservationID == o.ObservationID {
		t.Fatalf("different source must be a distinct observation")
	}
	if len(s.List("t1")) != 2 {
		t.Fatalf("expected 2 distinct flows")
	}
}

// memPersister is an in-memory blobstore.Persister for tests.
type memPersister struct{ data []byte }

func (m *memPersister) Load() ([]byte, error) { return m.data, nil }
func (m *memPersister) Save(d []byte) error   { m.data = append([]byte(nil), d...); return nil }

func TestPersistAndRehydrate(t *testing.T) {
	p := &memPersister{}
	s1 := NewStore()
	if err := s1.SetPersister(p, 0); err != nil {
		t.Fatalf("SetPersister: %v", err)
	}
	s1.Observe("t1", "mac-dev-1", "alice", "10.20.0.10", "ssh", 22, time.Now())
	s1.Observe("t1", "win-dev-1", "", "10.20.0.20", "smb", 445, time.Now())
	if err := s1.PersistIfDirty(); err != nil {
		t.Fatalf("PersistIfDirty: %v", err)
	}
	if len(p.data) == 0 {
		t.Fatalf("nothing was persisted")
	}

	// A fresh store attached to the SAME persister rehydrates the inventory (survives a "restart").
	s2 := NewStore()
	if err := s2.SetPersister(p, 0); err != nil {
		t.Fatalf("rehydrate: %v", err)
	}
	got := s2.List("t1")
	if len(got) != 2 {
		t.Fatalf("rehydrated %d flows, want 2", len(got))
	}
	if _, ok := s2.Get("t1", ObservationKey("mac-dev-1", "10.20.0.10", "ssh", 22)); !ok {
		t.Fatalf("rehydrated store missing the ssh flow")
	}
}

func TestRetentionPrunesOldOnLoad(t *testing.T) {
	p := &memPersister{}
	// ★ RELATIVE TO THE REAL CLOCK, because pruning is (2026-08-14). This fixture used a fixed 2026-07-14 while
	// SetPersister prunes against time.Now(), so the "fresh" flow aged out on its own: the test passed for a
	// month and then failed on the day real time crossed 30 days past the hardcoded date, in a push that had
	// nothing to do with it. A test whose subject is a retention WINDOW must express both flows as offsets from
	// the same clock the code reads, or it is measuring the calendar.
	now := time.Now().UTC()
	s1 := NewStore()
	_ = s1.SetPersister(p, 0)
	s1.Observe("t1", "d-old", "", "10.0.0.1", "ssh", 22, now.Add(-40*24*time.Hour)) // 40 days old
	s1.Observe("t1", "d-new", "", "10.0.0.2", "ssh", 22, now.Add(-1*time.Hour))     // fresh
	_ = s1.PersistIfDirty()

	// Load with a 30-day retention → the 40-day-old flow is pruned, the fresh one kept.
	s2 := NewStore()
	_ = s2.SetPersister(p, 30*24*time.Hour)
	got := s2.List("t1")
	if len(got) != 1 || got[0].Source != "d-new" {
		t.Fatalf("retention: expected only the fresh flow, got %+v", got)
	}
}

func TestGetReturnsObservationForAdoption(t *testing.T) {
	s := NewStore()
	o := s.Observe("t1", "win-dev-1", "bob", "10.20.0.10", "ssh", 22, time.Now())
	got, ok := s.Get("t1", o.ObservationID)
	if !ok {
		t.Fatalf("Get must find the observed flow")
	}
	if got.Destination != "10.20.0.10" || got.Port != 22 || got.ServiceFamily != "ssh" {
		t.Fatalf("Get returned wrong flow: %+v", got)
	}
	if _, ok := s.Get("t1", "ewobs-nope"); ok {
		t.Fatalf("Get must report ok=false for an unknown id")
	}
	if _, ok := s.Get("other-tenant", o.ObservationID); ok {
		t.Fatalf("Get must be tenant-scoped")
	}
}

func TestObserveRejectsEmptyTenantOrDest(t *testing.T) {
	s := NewStore()
	if got := s.Observe("", "d", "", "10.0.0.1", "ssh", 22, time.Now()); got.ObservationID != "" {
		t.Fatalf("empty tenant must be rejected")
	}
	if got := s.Observe("t1", "d", "", "", "ssh", 22, time.Now()); got.ObservationID != "" {
		t.Fatalf("empty destination must be rejected")
	}
	if len(s.List("t1")) != 0 {
		t.Fatalf("nothing should have been recorded")
	}
}

func TestConvergenceOf(t *testing.T) {
	s := NewStore()
	base := time.Date(2026, 7, 14, 9, 0, 0, 0, time.UTC)
	s.Observe("t1", "d1", "", "10.0.0.1", "ssh", 22, base)
	s.Observe("t1", "d2", "", "10.0.0.2", "smb", 445, base.Add(time.Hour))
	s.Observe("t1", "d3", "", "10.0.0.3", "rdp", 3389, base.Add(2*time.Hour))

	// Predicate: everything EXCEPT the rdp flow is covered by an authored rule.
	covered := func(o FlowObservation) bool { return o.ServiceFamily != "rdp" }
	c := ConvergenceOf(s.List("t1"), covered)
	if c.TotalFlows != 3 || c.CoveredFlows != 2 || c.UncoveredFlows != 1 {
		t.Fatalf("counts: %+v", c)
	}
	if c.CoveragePercent < 66.6 || c.CoveragePercent > 66.7 {
		t.Fatalf("coverage%%: %v", c.CoveragePercent)
	}
	if c.NewestUncoveredFirstSeen != base.Add(2*time.Hour).Format(time.RFC3339) {
		t.Fatalf("newest uncovered first-seen: %q", c.NewestUncoveredFirstSeen)
	}

	// After the rdp flow is adopted into a rule, the predicate covers everything -> converged (0 uncovered / 100%).
	allCovered := func(FlowObservation) bool { return true }
	c = ConvergenceOf(s.List("t1"), allCovered)
	if c.UncoveredFlows != 0 || c.CoveragePercent != 100 || c.NewestUncoveredFirstSeen != "" {
		t.Fatalf("after adoption, converged: %+v", c)
	}
}
