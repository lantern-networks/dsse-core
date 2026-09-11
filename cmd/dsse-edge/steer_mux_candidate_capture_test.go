package main

import (
	"context"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
	policycandidate "github.com/lantern-networks/dsse-core/policycandidate"
)

// The steer-mux OPEN path records a default-denied destination as an adoptable candidate.
//
// It had no capture at all until 2026-08-05, which governs every steered NON-https flow: a destination no rule
// covered was refused and then forgotten, so an operator had nothing leading from "this was blocked" to "here
// is the rule to write". Measured live: 62 denies to one address produced zero candidates. This asserts the
// GATE the capture hangs on, which is the part that was wrong — it must fire on a default deny, must not fire
// on a rule-authored deny, and must not fire on an allow.
func TestSteerMuxCandidateCaptureGate(t *testing.T) {
	deny := func(reasonCodes []string, matched []string) model.AccessDecision {
		return model.AccessDecision{Decision: "deny", ReasonCodes: reasonCodes, MatchedConditions: matched}
	}
	cases := []struct {
		name string
		dec  model.AccessDecision
		want bool
	}{
		{"unmatched deny is adoptable", deny([]string{"no_policy_match"}, nil), true},
		{"a rule an operator WROTE is not a gap to adopt", deny([]string{"policy_deny"}, []string{"fqdn"}), false},
		{"an allow is not a candidate", model.AccessDecision{Decision: "allow"}, false},
		{"a step-up is not a candidate", model.AccessDecision{Decision: "require_reauthentication"}, false},
	}
	for _, tc := range cases {
		if got := decision.IsDefaultDeny(tc.dec); got != tc.want {
			t.Fatalf("%s: IsDefaultDeny = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// East-West flows are excluded on purpose: they already have their own observe → adopt inventory, and
// capturing them here too would queue one flow for adoption into two different planes.
func TestSteerMuxCandidateCaptureSkipsEastWest(t *testing.T) {
	for _, family := range []string{"ssh", "rdp", "smb"} {
		if !decision.IsEastWestProtocol(family) {
			t.Fatalf("%s is expected to be an east-west protocol; the capture exclusion depends on it", family)
		}
	}
	if decision.IsEastWestProtocol("https") {
		t.Fatalf("https must NOT be east-west — excluding it would drop ordinary egress candidates")
	}
}

// The store records what the capture hands it, keyed so the same destination does not pile up duplicates.
func TestObserveUnmatchedFlowRecordsAnAdoptableCandidate(t *testing.T) {
	store := policycandidate.NewStore()
	now := time.Date(2026, 8, 5, 10, 0, 0, 0, time.UTC)
	first, err := store.ObserveUnmatchedFlow(context.Background(), "tenant_lab_001", "203.0.113.10", "", 8088, "", now)
	if err != nil {
		t.Fatalf("ObserveUnmatchedFlow: %v", err)
	}
	if first.Source != policycandidate.SourceUnmatchedFlow {
		t.Fatalf("source = %q, want %q", first.Source, policycandidate.SourceUnmatchedFlow)
	}
	second, err := store.ObserveUnmatchedFlow(context.Background(), "tenant_lab_001", "203.0.113.10", "", 8088, "", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("second ObserveUnmatchedFlow: %v", err)
	}
	if second.CandidateID != first.CandidateID {
		t.Fatalf("a repeated flow made a NEW candidate (%q vs %q) — a denied destination retries constantly and would bury the queue",
			second.CandidateID, first.CandidateID)
	}
}
