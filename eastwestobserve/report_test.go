package eastwestobserve

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
)

func reportedFlow(dest string, count int, first, last time.Time) FlowObservation {
	return FlowObservation{Source: "dev-1", User: "alice", Destination: dest, ServiceFamily: "SSH", Port: 22, Count: count,
		FirstSeen: first.UTC().Format(time.RFC3339), LastSeen: last.UTC().Format(time.RFC3339)}
}

func countOf(t *testing.T, s *Store, tenant, dest string) int {
	t.Helper()
	for _, o := range s.List(tenant) {
		if o.Destination == dest {
			return o.Count
		}
	}
	return 0
}

// A report is delivered at least once. Applying it twice would count its flows twice.
func TestReportIsAppliedOncePerReporterSequence(t *testing.T) {
	p := &sharedFixture{}
	cp := NewStore()
	cp.SetPersister(p, 0)
	now := time.Now().UTC().Truncate(time.Second)
	ctx := context.Background()
	if ok, err := cp.ApplyReport(ctx, "a", "edge-1", 1, []FlowObservation{reportedFlow("db", 3, now, now)}, now); err != nil || !ok {
		t.Fatalf("first report: %v %v", ok, err)
	}
	if ok, err := cp.ApplyReport(ctx, "a", "edge-1", 1, []FlowObservation{reportedFlow("db", 3, now, now)}, now); err != nil || ok {
		t.Fatalf("replayed report was applied again: %v %v", ok, err)
	}
	if ok, _ := cp.ApplyReport(ctx, "a", "edge-1", 2, []FlowObservation{reportedFlow("db", 2, now, now.Add(time.Second))}, now); !ok {
		t.Fatal("next report from the same reporter was refused")
	}
	if ok, _ := cp.ApplyReport(ctx, "a", "edge-2", 1, []FlowObservation{reportedFlow("db", 1, now.Add(-time.Minute), now)}, now); !ok {
		t.Fatal("another reporter's first report was refused")
	}
	fresh := NewStore()
	fresh.SetPersister(p, 0)
	got := fresh.List("a")
	if len(got) != 1 || got[0].Count != 6 || got[0].ServiceFamily != "ssh" || got[0].FirstSeen != now.Add(-time.Minute).Format(time.RFC3339) || got[0].LastSeen != now.Add(time.Second).Format(time.RFC3339) {
		t.Fatalf("durable inventory: %+v", got)
	}
	if countOf(t, cp, "a", "db") != 6 {
		t.Fatalf("published view: %+v", cp.List("a"))
	}
}

// The counts and the receipt commit together, so a report whose commit outcome was not seen is delivered again
// and recognised, rather than stopping the store or counting twice.
func TestReportWithUnknownCommitOutcomeIsSafeToDeliverAgain(t *testing.T) {
	p := &sharedFixture{committedError: true}
	cp := NewStore()
	cp.SetPersister(p, 0)
	now := time.Now().UTC().Truncate(time.Second)
	if ok, err := cp.ApplyReport(context.Background(), "a", "edge-1", 7, []FlowObservation{reportedFlow("db", 4, now, now)}, now); err == nil || ok {
		t.Fatalf("lost acknowledgement reported as applied: %v %v", ok, err)
	}
	p.committedError = false
	if ok, err := cp.ApplyReport(context.Background(), "a", "edge-1", 7, []FlowObservation{reportedFlow("db", 4, now, now)}, now); err != nil || ok {
		t.Fatalf("redelivery: %v %v", ok, err)
	}
	fresh := NewStore()
	fresh.SetPersister(p, 0)
	if c := countOf(t, fresh, "a", "db"); c != 4 {
		t.Fatalf("count after redelivery = %d, want 4", c)
	}
	if cp.sharedUncertain {
		t.Fatal("a redeliverable report stopped the store")
	}
}

// The store's own periodic flush rewrites the row. It must keep the receipts other writers put there.
func TestFlushKeepsReportReceipts(t *testing.T) {
	p := &sharedFixture{}
	cp, peer := NewStore(), NewStore()
	cp.SetPersister(p, 0)
	peer.SetPersister(p, 0)
	now := time.Now().UTC().Truncate(time.Second)
	cp.ApplyReport(context.Background(), "a", "edge-1", 1, []FlowObservation{reportedFlow("db", 1, now, now)}, now)
	peer.Observe("a", "dev-2", "", "web", "http", 80, now)
	if err := peer.PersistIfDirty(); err != nil {
		t.Fatal(err)
	}
	if ok, _ := cp.ApplyReport(context.Background(), "a", "edge-1", 1, []FlowObservation{reportedFlow("db", 1, now, now)}, now); ok {
		t.Fatal("the peer's flush dropped the receipt, so the report was counted again")
	}
	fresh := NewStore()
	fresh.SetPersister(p, 0)
	if countOf(t, fresh, "a", "db") != 1 || countOf(t, fresh, "a", "web") != 1 {
		t.Fatalf("inventory: %+v", fresh.List("a"))
	}
}

// A row nobody has reported into keeps the original shape, which earlier builds read. A row in the original
// shape is read as it always was.
func TestRowShapeWithAndWithoutReceipts(t *testing.T) {
	p := &sharedFixture{}
	s := NewStore()
	s.SetPersister(p, 0)
	now := time.Now().UTC().Truncate(time.Second)
	s.Observe("a", "dev", "", "db", "ssh", 22, now)
	if err := s.PersistIfDirty(); err != nil {
		t.Fatal(err)
	}
	var legacy map[string]map[string]FlowObservation
	if err := json.Unmarshal(p.raw, &legacy); err != nil || len(legacy["a"]) != 1 {
		t.Fatalf("row without receipts changed shape: %s", p.raw)
	}
	s.ApplyReport(context.Background(), "a", "edge-1", 1, []FlowObservation{reportedFlow("db2", 1, now, now)}, now)
	var envelope struct {
		Format   string                                `json:"format"`
		Flows    map[string]map[string]FlowObservation `json:"flows"`
		Receipts map[string]ReportReceipt              `json:"receipts"`
	}
	if err := json.Unmarshal(p.raw, &envelope); err != nil || envelope.Format != rowFormat || len(envelope.Flows["a"]) != 2 || envelope.Receipts["edge-1"].Seq != 1 {
		t.Fatalf("row with receipts: %s", p.raw)
	}
	for _, bad := range []string{`{"format":"eastwest_observations.v9","flows":{},"receipts":{}}`, `{"format":"eastwest_observations.v2","flows":{}}`,
		`{"format":"eastwest_observations.v2","flows":{},"receipts":{"edge":{"seq":0,"at":"2026-09-23T00:00:00Z"}}}`} {
		if _, _, err := decodeShared([]byte(bad), true); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}

func TestReportRejectsMalformedObservations(t *testing.T) {
	s := NewStore()
	now := time.Now().UTC()
	ctx := context.Background()
	cases := [][]FlowObservation{
		nil,
		{reportedFlow("", 1, now, now)},
		{reportedFlow("db", 0, now, now)},
		{reportedFlow("db", 1, now, now.Add(-time.Second))},
		{{Destination: "db", Count: 1, FirstSeen: "yesterday", LastSeen: "today"}},
		{reportedFlow("db", 1, now, now), {Destination: "db", Port: 70000, Count: 1, FirstSeen: now.Format(time.RFC3339), LastSeen: now.Format(time.RFC3339)}},
	}
	for i, flows := range cases {
		if _, err := s.ApplyReport(ctx, "a", "edge", uint64(i+1), flows, now); err == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
	if _, err := s.ApplyReport(ctx, "a", "", 1, []FlowObservation{reportedFlow("db", 1, now, now)}, now); err == nil {
		t.Fatal("report without a reporter accepted")
	}
	if len(s.List("a")) != 0 {
		t.Fatal("a refused report changed the inventory")
	}
}

// Without a shared database (a single-process lab) the receipts are kept in the file beside the flows.
func TestFileStoreKeepsReceiptsAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ew.json")
	now := time.Now().UTC().Truncate(time.Second)
	s := NewStore()
	s.SetPersister(blobstore.FilePersister{Path: path}, 0)
	s.ApplyReport(context.Background(), "a", "edge-1", 3, []FlowObservation{reportedFlow("db", 2, now, now)}, now)
	if err := s.PersistIfDirty(); err != nil {
		t.Fatal(err)
	}
	restarted := NewStore()
	if err := restarted.SetPersister(blobstore.FilePersister{Path: path}, 0); err != nil {
		t.Fatal(err)
	}
	if ok, _ := restarted.ApplyReport(context.Background(), "a", "edge-1", 3, []FlowObservation{reportedFlow("db", 2, now, now)}, now); ok {
		t.Fatal("receipt lost across restart")
	}
	if countOf(t, restarted, "a", "db") != 2 {
		t.Fatalf("inventory: %+v", restarted.List("a"))
	}
}

// A different control plane may receive a lower sequence after another tenant's
// report advanced the watermark. Persisted holes survive both peer writes and restart.
func TestReportReorderingAcrossTenantsAndRestart(t *testing.T) {
	p := &sharedFixture{}
	s := NewStore()
	s.SetPersister(p, 0)
	now := time.Now().UTC().Truncate(time.Second)
	apply := func(store *Store, tenant string, seq uint64, want bool) {
		t.Helper()
		ok, err := store.ApplyReport(context.Background(), tenant, "edge", seq, []FlowObservation{reportedFlow("db", 1, now, now)}, now)
		if err != nil || ok != want {
			t.Fatalf("%s/%d: %v %v", tenant, seq, ok, err)
		}
	}
	apply(s, "b", 3, true)
	peer := NewStore()
	if err := peer.SetPersister(p, 0); err != nil {
		t.Fatal(err)
	}
	apply(peer, "a", 1, true)
	peer.Observe("b", "other", "", "web", "http", 80, now)
	if err := peer.PersistIfDirty(); err != nil {
		t.Fatal(err)
	}
	fresh := NewStore()
	if err := fresh.SetPersister(p, 0); err != nil {
		t.Fatal(err)
	}
	apply(fresh, "a", 2, true)
	apply(fresh, "a", 1, false)
	apply(fresh, "b", 3, false)
	if countOf(t, fresh, "a", "db") != 2 || countOf(t, fresh, "b", "db") != 1 {
		t.Fatal("reordering lost or doubled observations")
	}
}
