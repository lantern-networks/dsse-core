package policycandidate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/reportreceipt"
)

func TestReportWindowBoundsPersistentGrowth(t *testing.T) {
	p := &candidateSharedFixture{}
	s := NewStore()
	s.SetPersister(p)
	now := time.Now().UTC().Truncate(time.Second)
	obs := []ReportedObservation{{Kind: ReportUnmatchedFlow, Host: "db", Port: 22, Count: 1, LastObserved: now.Format(time.RFC3339)}}
	apply := func(seq uint64) (bool, error) { return s.ApplyReport(context.Background(), "a", "edge", seq, obs, now) }

	// Start with an oversized v3 row from before the fix. The sustained input
	// series is exercised separately in reportreceipt; keep JSON-store regression
	// bounded in runtime while checking migration and repeated window advances.
	obs[0].Count = 4500
	if ok, err := apply(9000); err != nil || !ok {
		t.Fatal(err)
	}
	obs[0].Count = 1
	var legacy map[string]json.RawMessage
	if err := json.Unmarshal(p.data, &legacy); err != nil {
		t.Fatal(err)
	}
	r := ReportReceipt{Seq: 9000, At: now.Format(time.RFC3339)}
	for seq := uint64(1); seq < 9000; seq += 2 {
		r.Gaps = append(r.Gaps, reportreceipt.Gap{First: seq, Last: seq})
	}
	legacy["receipts"], _ = json.Marshal(map[string]ReportReceipt{"edge": r})
	legacy["format"] = json.RawMessage(`"policy_candidates.v3"`)
	p.data, _ = json.Marshal(legacy)
	seqs := []uint64{}
	for seq := uint64(9002); seq <= 9256; seq += 2 {
		seqs = append(seqs, seq)
	}
	seqs = append(seqs, 18000)
	for _, seq := range seqs {
		if ok, err := apply(seq); err != nil || !ok {
			t.Fatalf("%d: %v %v", seq, ok, err)
		}
		if seq == 9256 || seq == 18000 {
			var row struct {
				Receipts map[string]ReportReceipt `json:"receipts"`
			}
			if err := json.Unmarshal(p.data, &row); err != nil {
				t.Fatal(err)
			}
			r := row.Receipts["edge"]
			t.Logf("high_seq=%d row_bytes=%d gaps=%d retired_through=%d", seq, len(p.data), len(r.Gaps), r.RetiredThrough)
			if len(r.Gaps) > int(reportreceipt.ReplayWindow/2) || len(p.data) > 200000 {
				t.Fatal("unbounded row")
			}
		}
	}
	s = NewStore()
	s.SetPersister(p)
	before := bytes.Clone(p.data)
	for _, seq := range []uint64{1, 2, 18000 - reportreceipt.ReplayWindow} {
		if ok, err := apply(seq); ok || !errors.Is(err, reportreceipt.ErrExpired) {
			t.Fatalf("expired %d: %v %v", seq, ok, err)
		}
		if !bytes.Equal(before, p.data) || mustGet(t, s, "a", LearningCandidateID("db", "", 22)).FailureCount != 4629 {
			t.Fatal("expired report changed state")
		}
	}
	if ok, err := apply(18000 - reportreceipt.ReplayWindow + 1); err != nil || !ok {
		t.Fatalf("retained hole: %v %v", ok, err)
	}
	if ok, err := apply(18000 - reportreceipt.ReplayWindow + 1); err != nil || ok {
		t.Fatalf("retained duplicate: %v %v", ok, err)
	}
	// A rejected transaction must not advance retirement in the live receipt.
	p.fail = true
	if ok, err := apply(24000); err == nil || ok {
		t.Fatal("failed commit accepted")
	}
	p.fail = false
	if ok, err := apply(17999); err != nil || !ok {
		t.Fatalf("failed commit retired a valid hole: %v %v", ok, err)
	}
	if mustGet(t, s, "a", LearningCandidateID("db", "", 22)).FailureCount != 4631 {
		t.Fatal("incorrect counts")
	}
}
func TestMemoryReportWindowRefusalPreservesCounts(t *testing.T) {
	s := NewStore()
	now := time.Now().UTC()
	obs := []ReportedObservation{{Kind: ReportUnmatchedFlow, Host: "db", Port: 22, Count: 1, LastObserved: now.Format(time.RFC3339)}}
	for _, seq := range []uint64{2, reportreceipt.ReplayWindow + 2} {
		if ok, err := s.ApplyReport(context.Background(), "a", "edge", seq, obs, now); err != nil || !ok {
			t.Fatal(err)
		}
	}
	if ok, err := s.ApplyReport(context.Background(), "a", "edge", 1, obs, now); ok || !errors.Is(err, reportreceipt.ErrExpired) {
		t.Fatal("expired report accepted")
	}
	if mustGet(t, s, "a", LearningCandidateID("db", "", 22)).FailureCount != 2 {
		t.Fatal("refusal changed counts")
	}
}
