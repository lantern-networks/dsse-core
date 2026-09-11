package policycandidate

import (
	"context"
	"testing"
	"time"
)

func TestNormalizeValidation(t *testing.T) {
	now := time.Now().UTC()
	if _, err := normalize(Candidate{}, "", now); err == nil {
		t.Fatal("expected error for missing tenant_id")
	}
	if _, err := normalize(Candidate{}, "t1", now); err == nil {
		t.Fatal("expected error for missing candidate_id")
	}
	if _, err := normalize(Candidate{CandidateID: "a/b"}, "t1", now); err == nil {
		t.Fatal("expected error for slash in candidate_id")
	}
	if _, err := normalize(Candidate{CandidateID: "c1", CandidateType: "bogus"}, "t1", now); err == nil {
		t.Fatal("expected error for invalid candidate_type")
	}
	if _, err := normalize(Candidate{CandidateID: "c1", TenantID: "other"}, "t1", now); err == nil {
		t.Fatal("expected error for tenant mismatch")
	}
	if _, err := normalize(Candidate{CandidateID: "c1"}, "t1", now); err == nil {
		t.Fatal("expected error for missing application_id")
	}
}

func TestUpsertAndListScopeTenant(t *testing.T) {
	store := NewStore()
	now := time.Now().UTC()
	ctx := context.Background()
	a := Candidate{CandidateID: "cand_a", ApplicationID: "app1", ServiceFamily: "web", Status: "pending"}
	if _, err := store.Upsert(ctx, a, "t1", now); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	b := Candidate{CandidateID: "cand_b", ApplicationID: "app2", ServiceFamily: "web", Status: "pending"}
	if _, err := store.Upsert(ctx, b, "t2", now); err != nil {
		t.Fatalf("upsert t2: %v", err)
	}
	resp, err := store.List(ctx, "t1", ListOptions{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if resp.Count != 1 || resp.Candidates[0].CandidateID != "cand_a" {
		t.Fatalf("tenant t1 list = %+v, want only cand_a", resp.Candidates)
	}
}
