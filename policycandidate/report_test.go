package policycandidate

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
)

func mustGet(t *testing.T, s *Store, tenant, id string) Candidate {
	t.Helper()
	c, ok, err := s.Get(context.Background(), tenant, id)
	if err != nil || !ok {
		t.Fatalf("candidate %s: ok=%v err=%v", id, ok, err)
	}
	return c
}

// A report of n sightings must produce the candidate n local observations would have produced.
func TestReportProducesTheCandidateLocalObservationWould(t *testing.T) {
	ctx := context.Background()
	at := time.Date(2026, 9, 23, 1, 2, 3, 0, time.UTC)
	stamp := at.Format(time.RFC3339)
	local, cp := NewStore(), NewStore()
	for i := 0; i < 3; i++ {
		local.ObserveUnmatchedFlow(ctx, "a", "API.example.com", "", 443, "", at)
		local.ObserveCertPinFailure(ctx, "a", "pinned.example", "pinned.example", 443, "interception_handshake_rejected", at)
		local.ObserveCertPinFailureDNSCorrelated(ctx, "a", "cdn.example", "203.0.113.9", 443, "interception_handshake_rejected", at)
	}
	report := []ReportedObservation{
		{Kind: ReportUnmatchedFlow, Host: "API.example.com", Port: 443, Count: 3, LastObserved: stamp},
		{Kind: ReportCertPinFailure, Host: "pinned.example", SNI: "pinned.example", Port: 443, Reason: "interception_handshake_rejected", Count: 3, LastObserved: stamp},
		{Kind: ReportCertPinFailureDNSMatch, Host: "cdn.example", ObservedIP: "203.0.113.9", Port: 443, Reason: "interception_handshake_rejected", Count: 3, LastObserved: stamp},
	}
	if ok, err := cp.ApplyReport(ctx, "a", "edge-1", 1, report, at); err != nil || !ok {
		t.Fatalf("apply: %v %v", ok, err)
	}
	want, _ := local.List(ctx, "a", ListOptions{})
	got, _ := cp.List(ctx, "a", ListOptions{})
	if len(want.Candidates) != 3 || len(got.Candidates) != 3 {
		t.Fatalf("candidates: local %d, reported %d", len(want.Candidates), len(got.Candidates))
	}
	for _, w := range want.Candidates {
		g := mustGet(t, cp, "a", w.CandidateID)
		wj, _ := json.Marshal(w)
		gj, _ := json.Marshal(g)
		if string(wj) != string(gj) {
			t.Fatalf("reported candidate differs from the observed one:\nobserved %s\nreported %s", wj, gj)
		}
	}
}

func TestCandidateReportIsAppliedOncePerReporterSequence(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	p := &candidateSharedFixture{}
	cp, peer := NewStore(), NewStore()
	cp.SetPersister(p)
	peer.SetPersister(p)
	obs := []ReportedObservation{{Kind: ReportUnmatchedFlow, Host: "db.example", Port: 5432, Count: 2, LastObserved: now.Format(time.RFC3339)}}
	if ok, err := cp.ApplyReport(ctx, "a", "edge-1", 1, obs, now); err != nil || !ok {
		t.Fatalf("first: %v %v", ok, err)
	}
	id := LearningCandidateID("db.example", "", 5432)
	// Another writer's ordinary edit rewrites the row; the receipt must survive it.
	if _, _, err := peer.Review(ctx, "a", id, ReviewRequest{Decision: "suppressed", ReviewReasonCode: "not_needed"}, now); err != nil {
		t.Fatal(err)
	}
	if ok, err := cp.ApplyReport(ctx, "a", "edge-1", 1, obs, now); err != nil || ok {
		t.Fatalf("replay after a peer edit was applied: %v %v", ok, err)
	}
	if ok, _ := cp.ApplyReport(ctx, "a", "edge-1", 2, obs, now); !ok {
		t.Fatal("next sequence refused")
	}
	fresh := NewStore()
	fresh.SetPersister(p)
	c := mustGet(t, fresh, "a", id)
	if c.FailureCount != 4 || c.Status != "suppressed" {
		t.Fatalf("count %d status %s, want 4 suppressed (an observation never re-opens a decision)", c.FailureCount, c.Status)
	}
}

// A report whose commit outcome is unknown is delivered again and recognised. It must not stop the store the way
// an unknown local increment does, because redelivery here is exactly-once.
func TestCandidateReportUnknownCommitIsRedeliverable(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	p := &candidateSharedFixture{unknown: true}
	cp := NewStore()
	cp.SetPersister(p)
	obs := []ReportedObservation{{Kind: ReportUnmatchedFlow, Host: "db.example", Port: 5432, Count: 5, LastObserved: now.Format(time.RFC3339)}}
	if ok, err := cp.ApplyReport(ctx, "a", "edge-1", 9, obs, now); err == nil || ok {
		t.Fatalf("unknown outcome reported as applied: %v %v", ok, err)
	}
	if cp.ReconciliationRequired() {
		t.Fatal("a redeliverable report stopped the store")
	}
	p.unknown = false
	if ok, err := cp.ApplyReport(ctx, "a", "edge-1", 9, obs, now); err != nil || ok {
		t.Fatalf("redelivery: %v %v", ok, err)
	}
	if c := mustGet(t, cp, "a", LearningCandidateID("db.example", "", 5432)); c.FailureCount != 5 {
		t.Fatalf("count %d, want 5", c.FailureCount)
	}
}

// Reports from several Edges arrive in any order. An older one adds its count but does not move last_observed back.
func TestOlderReportKeepsTheLatestSighting(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	cp := NewStore()
	newer := now.Format(time.RFC3339)
	older := now.Add(-time.Hour).Format(time.RFC3339)
	cp.ApplyReport(ctx, "a", "edge-1", 1, []ReportedObservation{{Kind: ReportUnmatchedFlow, Host: "h", Port: 443, Count: 1, LastObserved: newer}}, now)
	cp.ApplyReport(ctx, "a", "edge-2", 1, []ReportedObservation{{Kind: ReportUnmatchedFlow, Host: "h", Port: 443, Count: 1, LastObserved: older}}, now)
	c := mustGet(t, cp, "a", LearningCandidateID("h", "", 443))
	if c.FailureCount != 2 || c.LastObserved == nil || *c.LastObserved != newer {
		t.Fatalf("count %d last %v", c.FailureCount, c.LastObserved)
	}
}

// One invalid observation refuses the whole report, so a sender that corrects and resends does not double the rest.
func TestInvalidReportChangesNothing(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339)
	cp := NewStore()
	good := ReportedObservation{Kind: ReportUnmatchedFlow, Host: "h", Port: 443, Count: 1, LastObserved: now}
	for i, bad := range []ReportedObservation{
		{Kind: "guess", Host: "h", Count: 1, LastObserved: now},
		{Kind: ReportUnmatchedFlow, Count: 1, LastObserved: now},
		{Kind: ReportUnmatchedFlow, Host: "h", Count: 0, LastObserved: now},
		{Kind: ReportUnmatchedFlow, Host: "h", Count: 1, LastObserved: "soon"},
		{Kind: ReportCertPinFailureDNSMatch, Host: "h", Count: 1, LastObserved: now},
		{Kind: ReportCertPinFailure, Port: 443, Count: 1, LastObserved: now},
	} {
		if _, err := cp.ApplyReport(ctx, "a", "edge", uint64(i+1), []ReportedObservation{good, bad}, time.Now()); err == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
	if n := cp.CountForTenant("a"); n != 0 {
		t.Fatalf("a refused report left %d candidate(s)", n)
	}
	if _, err := cp.ApplyReport(ctx, "a", "edge", 1, nil, time.Now()); err == nil {
		t.Fatal("empty report accepted")
	}
}

func TestCandidateRowShapeWithAndWithoutReceipts(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	p := &candidateSharedFixture{}
	s := NewStore()
	s.SetPersister(p)
	if _, err := s.ObserveUnmatchedFlow(ctx, "a", "h", "", 443, "", now); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeCandidateSnapshot(p.data); err != nil {
		t.Fatalf("a row without receipts changed shape: %v", err)
	}
	s.ApplyReport(ctx, "a", "edge-1", 1, []ReportedObservation{{Kind: ReportUnmatchedFlow, Host: "h2", Port: 443, Count: 1, LastObserved: now.Format(time.RFC3339)}}, now)
	candidates, receipts, err := decodeCandidateRow(p.data)
	if err != nil || len(candidates["a"]) != 2 || receipts["edge-1"].Seq != 1 {
		t.Fatalf("row with receipts: %v %v %v", candidates, receipts, err)
	}
	for _, bad := range []string{`{"format":"policy_candidates.v9","candidates":{},"receipts":{}}`, `{"format":"policy_candidates.v2","candidates":{}}`,
		`{"format":"policy_candidates.v2","candidates":{},"receipts":{"":{"seq":1,"at":"2026-09-23T00:00:00Z"}}}`} {
		if _, _, err := decodeCandidateRow([]byte(bad)); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}

func TestFileCandidateStoreKeepsReceiptsAcrossRestart(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "candidates.json")
	obs := []ReportedObservation{{Kind: ReportUnmatchedFlow, Host: "h", Port: 443, Count: 2, LastObserved: now.Format(time.RFC3339)}}
	s := NewStore()
	if err := s.SetPersister(blobstore.FilePersister{Path: path}); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.ApplyReport(ctx, "a", "edge-1", 4, obs, now); err != nil || !ok {
		t.Fatalf("apply: %v %v", ok, err)
	}
	// An ordinary edit afterwards keeps the receipt in the file.
	if _, err := s.ObserveUnmatchedFlow(ctx, "a", "other", "", 443, "", now); err != nil {
		t.Fatal(err)
	}
	restarted := NewStore()
	if err := restarted.SetPersister(blobstore.FilePersister{Path: path}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := restarted.ApplyReport(ctx, "a", "edge-1", 4, obs, now); ok {
		t.Fatal("receipt lost across restart")
	}
	if c := mustGet(t, restarted, "a", LearningCandidateID("h", "", 443)); c.FailureCount != 2 {
		t.Fatalf("count %d", c.FailureCount)
	}
}

func TestCandidateReportReorderingAcrossTenantsAndRestart(t *testing.T) {
	p := &candidateSharedFixture{}
	s := NewStore()
	s.SetPersister(p)
	now := time.Now().UTC().Truncate(time.Second)
	obs := []ReportedObservation{{Kind: ReportUnmatchedFlow, Host: "db.example", Port: 443, Count: 1, LastObserved: now.Format(time.RFC3339)}}
	apply := func(store *Store, tenant string, seq uint64, want bool) {
		t.Helper()
		ok, err := store.ApplyReport(context.Background(), tenant, "edge", seq, obs, now)
		if err != nil || ok != want {
			t.Fatalf("%s/%d: %v %v", tenant, seq, ok, err)
		}
	}
	apply(s, "b", 3, true)
	peer := NewStore()
	if err := peer.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	apply(peer, "a", 1, true)
	id := LearningCandidateID("db.example", "", 443)
	if _, _, err := peer.Review(context.Background(), "a", id, ReviewRequest{Decision: "suppressed", ReviewReasonCode: "not_needed"}, now); err != nil {
		t.Fatal(err)
	}
	fresh := NewStore()
	if err := fresh.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	apply(fresh, "a", 2, true)
	apply(fresh, "a", 1, false)
	apply(fresh, "b", 3, false)
	a, b := mustGet(t, fresh, "a", id), mustGet(t, fresh, "b", id)
	if a.FailureCount != 2 || b.FailureCount != 1 || a.Status != "suppressed" {
		t.Fatalf("lost count or review: %+v %+v", a, b)
	}
}
