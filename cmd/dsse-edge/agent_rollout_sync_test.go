package main

import (
	"testing"

	"github.com/lantern-networks/dsse-core/agentrollout"
)

// ★★★ AN EDGE TOLD ABOUT ONE ORGANIZATION HELD EVERY OTHER ONE FOR EVER (2026-08-28).
//
// A pulling Edge fetched a single plan — its own enforcement tenant's — and did the honest thing with it: a
// device of any other organization was HELD, because "I have not been told whether that fleet is halted" must
// not read like "it is not halted". Safe, and permanent: those fleets were never told anything, so they never
// moved, and nothing on any screen said why.
func TestTheCacheAnswersEachOrganizationFromItsOwnPlan(t *testing.T) {
	c := &agentRolloutCache{}
	if _, known := c.planFor("tenant_a"); known {
		t.Fatal("an Edge that has pulled nothing claimed to know an organization's plan — that is the direction " +
			"that releases a fleet somebody stopped")
	}
	c.setAll(map[string]agentrollout.AgentRolloutPlan{
		"tenant_a": {Frozen: true, Reason: "0.3.0 bricked the pilot ring"},
		"tenant_b": {DesiredVersion: "0.2.9"},
	}, "tenant_a")

	a, known := c.planFor("tenant_a")
	if !known || !a.Frozen {
		t.Fatalf("this edge's own organization: known=%v frozen=%v", known, a.Frozen)
	}
	b, known := c.planFor("tenant_b")
	if !known || b.DesiredVersion != "0.2.9" {
		t.Fatalf("another organization on the same edge: known=%v version=%q — before this it was held for ever",
			known, b.DesiredVersion)
	}
	// ★ AND AN ORGANIZATION NOBODY MENTIONED IS STILL UNKNOWN, which is what keeps the hold meaningful.
	if _, known := c.planFor("tenant_never_mentioned"); known {
		t.Fatal("an organization the control plane said nothing about was answered as known")
	}

	// The single-plan answer of an older control plane speaks for its own organization and nobody else's.
	old := &agentRolloutCache{}
	old.setForTenant("tenant_a", agentrollout.AgentRolloutPlan{Frozen: true})
	if _, known := old.planFor("tenant_b"); known {
		t.Fatal("one organization's plan was handed out as another's — the cross-tenant halt this cache's own " +
			"history is about")
	}
}
