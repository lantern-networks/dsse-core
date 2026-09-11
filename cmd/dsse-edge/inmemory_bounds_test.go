package main

import (
	"fmt"
	"testing"
	"time"

	inspection "github.com/lantern-networks/dsse-core/inspection"

	"github.com/lantern-networks/dsse-core/model"
)

func TestEvictFIFOBoundsAndUnbounded(t *testing.T) {
	// capacity 0 => never evicts
	called := false
	out := evictFIFO([]string{"a", "b"}, 2, 0, func(string) { called = true })
	if called || len(out) != 2 {
		t.Fatal("capacity 0 must be unbounded (no eviction)")
	}
	// capacity 2, live 4 => evict the 2 oldest
	evicted := []string{}
	out = evictFIFO([]string{"a", "b", "c", "d"}, 4, 2, func(k string) { evicted = append(evicted, k) })
	if len(out) != 2 || out[0] != "c" || len(evicted) != 2 || evicted[0] != "a" || evicted[1] != "b" {
		t.Fatalf("FIFO eviction wrong: order=%v evicted=%v", out, evicted)
	}
}

func TestInspectionEventStoreIsBounded(t *testing.T) {
	s := inspection.NewStore(3)
	for i := 0; i < 10; i++ {
		s.Upsert(model.InspectionEvent{ID: fmt.Sprintf("e%d", i)})
	}
	if s.Count() != 3 {
		t.Fatalf("store must be capped at 3, got %d (OOM risk not fixed)", s.Count())
	}
	if _, ok := s.Get("e9"); !ok {
		t.Fatal("newest must be retained")
	}
	if _, ok := s.Get("e0"); ok {
		t.Fatal("oldest must be evicted (FIFO)")
	}
}

func TestExportJobStoreIsBounded(t *testing.T) {
	s := &adminExportJobStore{jobs: map[string]adminExportJob{}, capacity: 2}
	for i := 0; i < 5; i++ {
		s.Create(adminExportJobRequest{}, "t1", "p1", time.Now())
	}
	if len(s.jobs) != 2 {
		t.Fatalf("export jobs must be capped at 2, got %d", len(s.jobs))
	}
}

func TestEventStoreConstructorsSetCapacity(t *testing.T) {
	if newInspectionEventStore().Capacity() != inMemoryEventStoreDefaultCapacity ||
		newHumanApprovalEventStore().Capacity() != inMemoryEventStoreDefaultCapacity ||
		newDelegatedAccessGrantStore().Capacity() != inMemoryEventStoreDefaultCapacity ||
		newAdminExportJobStore().capacity != inMemoryEventStoreDefaultCapacity {
		t.Fatal("constructors must set the default in-memory bound")
	}
}
