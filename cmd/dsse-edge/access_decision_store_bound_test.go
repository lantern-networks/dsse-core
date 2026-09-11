package main

import (
	"fmt"
	"testing"

	accessdecision "github.com/lantern-networks/dsse-core/accessdecision"

	"github.com/lantern-networks/dsse-core/model"
)

// TestAccessDecisionStoreBoundedEviction verifies the FIFO capacity bound: the store never
// grows past capacity, the oldest-inserted decisions are evicted first, and a just-inserted decision
// (the same-flow validation window) is always still present.
func TestAccessDecisionStoreBoundedEviction(t *testing.T) {
	store := accessdecision.NewStore(100)
	for i := 0; i < 1000; i++ {
		store.Upsert(model.AccessDecision{ID: fmt.Sprintf("dec_%04d", i), TenantID: "t"})
		// The decision just written must always be retrievable (same-flow readers depend on this).
		if _, ok := store.Get(fmt.Sprintf("dec_%04d", i)); !ok {
			t.Fatalf("just-inserted dec_%04d not found", i)
		}
	}
	if got := store.Count(); got != 100 {
		t.Fatalf("Count = %d, want capacity 100", got)
	}
	// Oldest must be evicted, newest retained.
	if _, ok := store.Get("dec_0000"); ok {
		t.Fatalf("oldest dec_0000 should have been evicted")
	}
	if _, ok := store.Get("dec_0999"); !ok {
		t.Fatalf("newest dec_0999 should be retained")
	}
	// The most recent 100 (dec_0900..dec_0999) should all be present.
	for i := 900; i < 1000; i++ {
		if _, ok := store.Get(fmt.Sprintf("dec_%04d", i)); !ok {
			t.Fatalf("recent dec_%04d should be retained", i)
		}
	}
}

// TestAccessDecisionStoreUnboundedWhenZeroCapacity confirms capacity==0 keeps the prior unbounded
// behavior (direct-construction tests rely on this).
func TestAccessDecisionStoreUnboundedWhenZeroCapacity(t *testing.T) {
	store := accessdecision.NewStore(0) // capacity 0
	for i := 0; i < 500; i++ {
		store.Upsert(model.AccessDecision{ID: fmt.Sprintf("dec_%04d", i), TenantID: "t"})
	}
	if got := store.Count(); got != 500 {
		t.Fatalf("Count = %d, want 500 (unbounded)", got)
	}
}

// TestAccessDecisionStoreUpsertExistingNoDoubleCount confirms re-upserting an existing ID updates in
// place without inflating order/eviction bookkeeping.
func TestAccessDecisionStoreUpsertExistingNoDoubleCount(t *testing.T) {
	store := accessdecision.NewStore(10)
	for i := 0; i < 50; i++ {
		store.Upsert(model.AccessDecision{ID: "dec_same", TenantID: "t", Timestamp: fmt.Sprintf("v%d", i)})
	}
	if got := store.Count(); got != 1 {
		t.Fatalf("Count = %d, want 1 for repeated same-ID upsert", got)
	}
	if _, ok := store.Get("dec_same"); !ok {
		t.Fatalf("dec_same should be present")
	}
}
