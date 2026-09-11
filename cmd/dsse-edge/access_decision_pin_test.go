package main

import (
	"fmt"
	"testing"

	accessdecision "github.com/lantern-networks/dsse-core/accessdecision"
	"github.com/lantern-networks/dsse-core/model"
)

// TestInspectionEventValidationRespectsInFlightPin ties the store's in-flight pin to its real hot-path consumer:
// a same-flow inspection event validating against an IN-FLIGHT decision must succeed even while the unpinned set
// churns hard (a long download whose request is still open), and must be rejected only once the request has
// completed and the decision has aged out. Time-independent — it drives eviction via the (unpinned-only) count
// cap, not the clock.
func TestInspectionEventValidationRespectsInFlightPin(t *testing.T) {
	const tenant = "tenant_pin"
	store := accessdecision.NewStore(1) // unpinned cap = 1; pins are exempt

	store.MarkInFlight(model.AccessDecision{ID: "flow", TenantID: tenant}) // request in flight
	for i := 0; i < 20; i++ {                                              // heavy unrelated churn under the cap
		store.Upsert(model.AccessDecision{ID: fmt.Sprintf("noise_%d", i), TenantID: tenant})
	}
	if store.InFlightCount() != 1 {
		t.Fatalf("InFlightCount = %d, want 1", store.InFlightCount())
	}

	ev := model.InspectionEvent{TenantID: tenant, AccessDecisionID: stringPtr("flow")}
	if err := validateInspectionEventReferences(ev, tenant, store); err != nil {
		t.Fatalf("a same-flow event on an in-flight decision must validate (never cut a live flow), got: %v", err)
	}

	// Request completes → the decision becomes evictable → the count cap pushes it out.
	store.MarkComplete("flow")
	if store.InFlightCount() != 0 {
		t.Fatalf("InFlightCount = %d, want 0 after complete", store.InFlightCount())
	}
	for i := 0; i < 3; i++ {
		store.Upsert(model.AccessDecision{ID: fmt.Sprintf("after_%d", i), TenantID: tenant})
	}
	if err := validateInspectionEventReferences(ev, tenant, store); err == nil {
		t.Fatalf("after completion + eviction the same-flow event must be rejected (access decision absent)")
	}
}
