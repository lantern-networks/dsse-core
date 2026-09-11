package accessdecision

import (
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

func TestStore(t *testing.T) {
	s := NewStore(2)
	s.Upsert(model.AccessDecision{ID: "d1", TenantID: "acme"})
	s.Upsert(model.AccessDecision{ID: "d2", TenantID: "acme"})
	if _, ok := s.Get("d1"); !ok {
		t.Fatal("d1 should be retrievable")
	}
	if got := s.SnapshotByTenant("acme"); len(got) != 2 {
		t.Fatalf("SnapshotByTenant(acme) = %d, want 2", len(got))
	}
	if got := s.SnapshotByTenant("other"); len(got) != 0 {
		t.Fatalf("another tenant must be isolated, got %d", len(got))
	}
	s.Upsert(model.AccessDecision{ID: "d3", TenantID: "acme"}) // capacity 2 -> oldest evicted
	if s.Count() > s.Capacity() {
		t.Fatalf("count %d exceeds capacity %d", s.Count(), s.Capacity())
	}
}
