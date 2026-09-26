package main

import (
	"context"
	"github.com/lantern-networks/dsse-core/policycandidate"
	"testing"
	"time"
)

func TestPostgresCandidatePeerKeepsReview(t *testing.T) {
	db := initialBlobDB(t)
	p := initialBlob(t, db, "candidate_peer")
	a, b := policycandidate.NewStore(), policycandidate.NewStore()
	for _, s := range []*policycandidate.Store{a, b} {
		if err := s.SetPersister(p); err != nil {
			t.Fatal(err)
		}
	}
	ctx, now := context.Background(), time.Now()
	c, err := a.ObserveCertPinFailure(ctx, "own", "named.example", "", 443, "pin", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Review(ctx, "own", c.CandidateID, policycandidate.ReviewRequest{Decision: "suppressed"}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := b.ObserveCertPinFailure(ctx, "own", "named.example", "", 443, "pin", now); err != nil {
		t.Fatal(err)
	}
	fresh := policycandidate.NewStore()
	if err := fresh.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	got, ok, err := fresh.Get(ctx, "own", c.CandidateID)
	if err != nil || !ok || got.Status != "suppressed" || got.FailureCount != 2 {
		t.Fatalf("peer overwrote review/count: status=%s count=%d found=%v err=%v", got.Status, got.FailureCount, ok, err)
	}
}
