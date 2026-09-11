package policycandidate

import (
	"context"
	"testing"
	"time"
)

// observe-mode learning: an unmatched destination is recorded as a pending allow-policy candidate the
// first time, and repeat observations increment the count on the same candidate (no duplicates).
func TestObserveUnmatchedFlowCreatesAndUpserts(t *testing.T) {
	store := NewStore()
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0).UTC()

	c, err := store.ObserveUnmatchedFlow(ctx, "acme", "api.example.com", "api.example.com", 443, "", now)
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if c.Status != "pending" {
		t.Fatalf("first observation must be pending, got %q", c.Status)
	}
	if c.CandidateType != "allow_policy" || c.ProposedAction != "allow" || c.Source != SourceUnmatchedFlow {
		t.Fatalf("expected an allow-policy policy-learning candidate, got type=%q action=%q source=%q", c.CandidateType, c.ProposedAction, c.Source)
	}
	if c.FailureCount != 1 {
		t.Fatalf("first observation count = %d, want 1", c.FailureCount)
	}

	c2, err := store.ObserveUnmatchedFlow(ctx, "acme", "api.example.com", "api.example.com", 443, "", now)
	if err != nil {
		t.Fatalf("observe again: %v", err)
	}
	if c2.CandidateID != c.CandidateID {
		t.Fatalf("repeat observation must upsert the same candidate, got %q vs %q", c2.CandidateID, c.CandidateID)
	}
	if c2.FailureCount != 2 {
		t.Fatalf("repeat observation count = %d, want 2", c2.FailureCount)
	}

	// It must show up in the allow_policy candidate listing (the admin's "observed traffic to adopt" view).
	resp, err := store.List(ctx, "acme", ListOptions{CandidateType: "allow_policy"})
	if err != nil || len(resp.Candidates) != 1 {
		t.Fatalf("list allow_policy: err=%v n=%d", err, len(resp.Candidates))
	}
}

// observe-mode proposing never enforces by itself: the admin must approve, then materialize, to adopt
// the destination into explicit policy (same governance as cert-pinning).
func TestObserveUnmatchedFlowAdoptLifecycle(t *testing.T) {
	store := NewStore()
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0).UTC()

	c, _ := store.ObserveUnmatchedFlow(ctx, "acme", "api.example.com", "", 443, "", now)

	// pending -> materialize must fail (unreviewed proposals are not adopted).
	if _, _, err := store.Materialize(ctx, "acme", c.CandidateID, false, now); err == nil {
		t.Fatal("materialize from pending must fail")
	}
	if _, ok, err := store.Review(ctx, "acme", c.CandidateID, ReviewRequest{Decision: "approved", ReviewReasonCode: "operator_adopted"}, now); err != nil || !ok {
		t.Fatalf("approve: %v ok=%v", err, ok)
	}
	m, ok, err := store.Materialize(ctx, "acme", c.CandidateID, false, now)
	if err != nil || !ok || m.Status != "materialized" {
		t.Fatalf("materialize after approve: %v ok=%v %+v", err, ok, m)
	}
}

func TestObserveUnmatchedFlowRequiresDestination(t *testing.T) {
	store := NewStore()
	if _, err := store.ObserveUnmatchedFlow(context.Background(), "acme", "", "", 443, "", time.Now()); err == nil {
		t.Fatal("an observation with neither host nor sni must be rejected")
	}
}
