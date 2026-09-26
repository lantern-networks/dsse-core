package policycandidate

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestLegacyCandidateEvidenceSurvivesLoadAndUnrelatedReview(t *testing.T) {
	original, raw := candidateSnapshotFixture(t)
	var rows map[string]map[string]Candidate
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	legacy := rows[original.TenantID][original.CandidateID]
	oldTime := "historical timestamp"
	legacy.ReviewReasonCode = "previous/review reason"
	legacy.LastObserved = &oldTime
	legacy.ReviewedAt = &oldTime
	legacy.UpdatedAt = &oldTime
	rows[legacy.TenantID][legacy.CandidateID] = legacy
	data, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	p := &candidateTestPersister{data: data}
	// Further observations must not fail merely because an old review was free-form.
	observationStore := NewStore()
	observationWriter := &candidateTestPersister{data: append([]byte(nil), data...)}
	if err := observationStore.SetPersister(observationWriter); err != nil {
		t.Fatal(err)
	}
	observed, err := observationStore.ObserveCertPinFailure(context.Background(), legacy.TenantID, "named.example", "named.example", 443, "rejected", time.Now())
	if err != nil || observed.ReviewReasonCode != legacy.ReviewReasonCode || *observed.ReviewedAt != oldTime || observed.FailureCount != legacy.FailureCount+1 {
		t.Fatalf("legacy review blocked observation: %v", err)
	}
	s := NewStore()
	if err := s.SetPersister(p); err != nil {
		t.Fatalf("legacy metadata blocked load: %v", err)
	}
	got, ok, err := s.Get(context.Background(), legacy.TenantID, legacy.CandidateID)
	if err != nil || !ok || !reflect.DeepEqual(got, legacy) {
		t.Fatal("load changed legacy evidence")
	}
	if _, err := s.Upsert(context.Background(), Candidate{CandidateID: "other", ApplicationID: "app", ServiceFamily: "web"}, legacy.TenantID, time.Now()); err != nil {
		t.Fatal(err)
	}
	fresh := NewStore()
	if err := fresh.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	got, ok, err = fresh.Get(context.Background(), legacy.TenantID, legacy.CandidateID)
	if err != nil || !ok || !reflect.DeepEqual(got, legacy) {
		t.Fatal("unrelated edit lost legacy evidence")
	}
	if _, err := fresh.Upsert(context.Background(), legacy, legacy.TenantID, time.Now()); err == nil {
		t.Fatal("invalid new evidence accepted")
	}
	// A normal review replaces the old review metadata but preserves observations.
	if _, _, err := fresh.Review(context.Background(), legacy.TenantID, legacy.CandidateID, ReviewRequest{Decision: "suppressed"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	reload := NewStore()
	if err := reload.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	got, ok, err = reload.Get(context.Background(), legacy.TenantID, legacy.CandidateID)
	if err != nil || !ok || got.Status != "suppressed" || *got.LastObserved != oldTime {
		t.Fatal("review/reload lost evidence")
	}
}
