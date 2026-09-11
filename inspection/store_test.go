package inspection

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// memPersister is an in-memory blobstore.Persister for testing durability.
type memPersister struct{ data []byte }

func (m *memPersister) Load() ([]byte, error) { return m.data, nil }
func (m *memPersister) Save(b []byte) error   { m.data = append([]byte(nil), b...); return nil }

func TestInspectionStorePersistence(t *testing.T) {
	p := &memPersister{}
	now := time.Now().UTC()

	// First store: attach persister, record two findings, flush.
	s1 := NewStore(0)
	if err := s1.SetPersister(p, 90*24*time.Hour); err != nil {
		t.Fatalf("SetPersister: %v", err)
	}
	s1.Upsert(model.InspectionEvent{ID: "e1", TenantID: "acme", Timestamp: now.Format(time.RFC3339)})
	s1.Upsert(model.InspectionEvent{ID: "e2", TenantID: "acme", Timestamp: now.Format(time.RFC3339)})
	if err := s1.PersistIfDirty(); err != nil {
		t.Fatalf("PersistIfDirty: %v", err)
	}

	// Second store simulates a restart: rehydrate from the same persister.
	s2 := NewStore(0)
	if err := s2.SetPersister(p, 90*24*time.Hour); err != nil {
		t.Fatalf("SetPersister (rehydrate): %v", err)
	}
	if got := s2.ListByTenant("acme"); len(got) != 2 {
		t.Fatalf("after restart ListByTenant(acme) = %d, want 2 (findings did not survive)", len(got))
	}
	if _, ok := s2.Get("e1"); !ok {
		t.Fatal("e1 did not survive restart")
	}
}

func TestInspectionStoreRetentionPrune(t *testing.T) {
	p := &memPersister{}
	now := time.Now().UTC()
	s1 := NewStore(0)
	if err := s1.SetPersister(p, 24*time.Hour); err != nil {
		t.Fatalf("SetPersister: %v", err)
	}
	s1.Upsert(model.InspectionEvent{ID: "old", TenantID: "acme", Timestamp: now.Add(-48 * time.Hour).Format(time.RFC3339)})
	s1.Upsert(model.InspectionEvent{ID: "new", TenantID: "acme", Timestamp: now.Format(time.RFC3339)})
	if err := s1.PersistIfDirty(); err != nil { // prunes the >24h-old event before saving
		t.Fatalf("PersistIfDirty: %v", err)
	}
	if _, ok := s1.Get("old"); ok {
		t.Fatal("event older than retention should have been pruned")
	}
	if _, ok := s1.Get("new"); !ok {
		t.Fatal("recent event must be kept")
	}
}

func TestInspectionStore(t *testing.T) {
	s := NewStore(2)
	mk := func(id, tenant string) model.InspectionEvent { return model.InspectionEvent{ID: id, TenantID: tenant} }
	s.Upsert(mk("e1", "acme"))
	s.Upsert(mk("e2", "acme"))
	if _, ok := s.Get("e1"); !ok {
		t.Fatal("e1 should be retrievable")
	}
	if got := s.ListByTenant("acme"); len(got) != 2 {
		t.Fatalf("ListByTenant(acme) = %d, want 2", len(got))
	}
	if got := s.ListByTenant("other"); len(got) != 0 {
		t.Fatalf("ListByTenant(other) = %d, want 0", len(got))
	}
	s.Upsert(mk("e3", "acme")) // capacity 2 -> oldest evicted
	if s.Count() > s.Capacity() {
		t.Fatalf("count %d exceeds capacity %d", s.Count(), s.Capacity())
	}
}
