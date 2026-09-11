package usagemeter

import "testing"

// TestRecordIndexDedupAndAppend locks in the O(1) index behavior: a record with a reused (tenant,id) replaces in
// place; unique-id records each append; a record with no id appends untracked. (The fix replaced an O(N) scan.)
func TestRecordIndexDedupAndAppend(t *testing.T) {
	s := NewUsageMeterStore()

	// Same (tenant,id) twice -> one record, replaced in place.
	s.Record(UsageMeterRecord{ID: "a", TenantID: "t1", Quantity: 1})
	s.Record(UsageMeterRecord{ID: "a", TenantID: "t1", Quantity: 9})
	if got := len(s.records); got != 1 {
		t.Fatalf("reused id: len=%d want 1", got)
	}
	if s.records[0].Quantity != 9 {
		t.Fatalf("reused id not replaced in place: quantity=%v want 9", s.records[0].Quantity)
	}

	// Unique ids each append.
	s.Record(UsageMeterRecord{ID: "b", TenantID: "t1"})
	s.Record(UsageMeterRecord{ID: "c", TenantID: "t1"})
	// Same id, DIFFERENT tenant -> distinct key -> appends.
	s.Record(UsageMeterRecord{ID: "a", TenantID: "t2"})
	// No id -> appended untracked.
	s.Record(UsageMeterRecord{TenantID: "t1"})
	if got := len(s.records); got != 5 {
		t.Fatalf("len=%d want 5", got)
	}

	// The index resolves the right slot for a later replace.
	s.Record(UsageMeterRecord{ID: "b", TenantID: "t1", Quantity: 42})
	if got := len(s.records); got != 5 {
		t.Fatalf("replace should not grow: len=%d want 5", got)
	}
	for _, r := range s.records {
		if r.ID == "b" && r.TenantID == "t1" && r.Quantity != 42 {
			t.Fatalf("b not replaced: quantity=%v want 42", r.Quantity)
		}
	}
}

// TestFIFOCapBoundsMemoryAndKeepsIndexConsistent locks in the in-memory FIFO bound: a capacity-bounded store
// trims oldest records past the high-watermark (down to 3/4) yet the index still resolves a kept record for an
// O(1) in-place replace (no duplicate append after eviction rebuilt the map). capacity<=0 stays unbounded.
func TestFIFOCapBoundsMemoryAndKeepsIndexConsistent(t *testing.T) {
	s := NewUsageMeterStoreWithCapacity(100)
	for i := 0; i < 1000; i++ {
		s.Record(UsageMeterRecord{ID: string(rune('a'+i%26)) + "-" + itoa(i), TenantID: "t1"})
	}
	if got := len(s.records); got > 100 {
		t.Fatalf("FIFO cap not enforced: len=%d want <=100", got)
	}
	if len(s.index) != len(idIndexed(s.records)) {
		t.Fatalf("index out of sync after eviction: index=%d indexed-records=%d", len(s.index), len(idIndexed(s.records)))
	}
	// A kept record's id must still replace in place (index survived the rebuild), not append.
	last := s.records[len(s.records)-1]
	before := len(s.records)
	s.Record(UsageMeterRecord{ID: last.ID, TenantID: last.TenantID, Quantity: 7})
	if len(s.records) != before {
		t.Fatalf("post-eviction index lost: replace appended (len %d -> %d)", before, len(s.records))
	}

	// capacity<=0 is unbounded (back-compat).
	u := NewUsageMeterStore()
	for i := 0; i < 500; i++ {
		u.Record(UsageMeterRecord{ID: itoa(i), TenantID: "t1"})
	}
	if len(u.records) != 500 {
		t.Fatalf("unbounded store dropped records: len=%d want 500", len(u.records))
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func idIndexed(records []UsageMeterRecord) []UsageMeterRecord {
	out := records[:0:0]
	for _, r := range records {
		if r.ID != "" && r.TenantID != "" {
			out = append(out, r)
		}
	}
	return out
}

// TestNewStoreSeedsIndex ensures seeded records are dedup-indexed (a later same-id Record replaces, not appends).
func TestNewStoreSeedsIndex(t *testing.T) {
	s := NewUsageMeterStore(UsageMeterRecord{ID: "seed", TenantID: "t1", Quantity: 1})
	s.Record(UsageMeterRecord{ID: "seed", TenantID: "t1", Quantity: 7})
	if got := len(s.records); got != 1 {
		t.Fatalf("seeded id replace: len=%d want 1", got)
	}
	if s.records[0].Quantity != 7 {
		t.Fatalf("seeded record not replaced: quantity=%v want 7", s.records[0].Quantity)
	}
}
