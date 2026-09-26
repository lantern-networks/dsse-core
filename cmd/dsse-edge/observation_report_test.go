package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/eastwestobserve"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/policycandidate"
)

func readReportRecords(t *testing.T, dir, stream string) []observationReportRecord {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, stream))
	if err != nil {
		t.Fatalf("read %s: %v", stream, err)
	}
	var out []observationReportRecord
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		var rec observationReportRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatalf("record %s: %v", line, err)
		}
		out = append(out, rec)
	}
	return out
}

func postIngest(t *testing.T, h http.Handler, stream string, body []byte) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/audit-ingest", bytes.NewReader(body))
	req.Header.Set("authorization", "Bearer ship-secret")
	req.Header.Set("x-audit-stream", stream)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

// Sightings between two reports become one record per organization and stream, with counts, the earliest and
// latest time, and a sequence that grows only when a record was written.
func TestObservationReporterAggregatesPerOrganization(t *testing.T) {
	dir := t.TempDir()
	writer, err := logs.NewWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := newObservationReporter(writer)
	t0 := time.Date(2026, 9, 23, 1, 0, 0, 0, time.UTC)
	r.eastWestFlow("a", "dev-1", "alice", "10.0.0.5", "SSH", 22, t0)
	r.eastWestFlow("a", "dev-1", "bob", "10.0.0.5", "ssh", 22, t0.Add(time.Minute))
	r.eastWestFlow("b", "", "", "10.1.0.9", "smb", 445, t0)
	r.candidate(policycandidate.ReportUnmatchedFlow, "a", "api.example", "", "", 443, "", t0)
	r.candidate(policycandidate.ReportUnmatchedFlow, "a", "api.example", "", "", 443, "", t0.Add(time.Second))
	r.eastWestFlow("", "dev", "", "x", "ssh", 22, t0) // no organization: nothing to file it under
	r.flush()
	r.flush() // nothing waiting: no empty record, no sequence consumed

	ew := readReportRecords(t, dir, eastWestObservationReportStream)
	if len(ew) != 2 || ew[0].TenantID != "a" || ew[1].TenantID != "b" || ew[0].Seq != 1 || ew[1].Seq != 2 || ew[0].Reporter != r.reporter {
		t.Fatalf("east-west records: %+v", ew)
	}
	f := ew[0].Flows[0]
	if len(ew[0].Flows) != 1 || f.Count != 2 || f.User != "bob" || f.ServiceFamily != "ssh" || f.FirstSeen != t0.Format(time.RFC3339) || f.LastSeen != t0.Add(time.Minute).Format(time.RFC3339) {
		t.Fatalf("aggregated flow: %+v", f)
	}
	if ew[1].Flows[0].Source != eastwestobserve.SourceAny {
		t.Fatalf("empty source: %+v", ew[1].Flows[0])
	}
	pc := readReportRecords(t, dir, candidateObservationReportStream)
	if len(pc) != 1 || pc[0].Seq != 1 || len(pc[0].Observations) != 1 || pc[0].Observations[0].Count != 2 || pc[0].Observations[0].LastObserved != t0.Add(time.Second).Format(time.RFC3339) {
		t.Fatalf("candidate records: %+v", pc)
	}
}

// A record the writer could not write was never handed to the shipper, so its observations wait for the next
// report under the same sequence, rather than being lost or skipping a number.
func TestObservationReporterKeepsWhatItCouldNotWrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs")
	writer, err := logs.NewWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := newObservationReporter(writer)
	now := time.Now().UTC().Truncate(time.Second)
	r.eastWestFlow("a", "dev", "", "db", "ssh", 22, now)
	os.RemoveAll(dir)
	if err := os.WriteFile(dir, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.flush()
	r.eastWestFlow("a", "dev", "", "db", "ssh", 22, now)
	os.Remove(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	r.flush()
	ew := readReportRecords(t, dir, eastWestObservationReportStream)
	if len(ew) != 1 || ew[0].Seq != 1 || ew[0].Flows[0].Count != 2 {
		t.Fatalf("records after a failed write: %+v", ew)
	}
}

// More distinct observations than one record carries go out as several records in sequence.
func TestObservationReporterSplitsLargeReports(t *testing.T) {
	dir := t.TempDir()
	writer, _ := logs.NewWriter(dir)
	r, _ := newObservationReporter(writer)
	now := time.Now().UTC()
	for i := 0; i < observationReportMaxPerRecord+3; i++ {
		r.candidate(policycandidate.ReportUnmatchedFlow, "a", "h"+strconv.Itoa(i)+".example", "", "", 443, "", now)
	}
	r.flush()
	pc := readReportRecords(t, dir, candidateObservationReportStream)
	total := 0
	for i, rec := range pc {
		if rec.Seq != uint64(i+1) {
			t.Fatalf("sequence %d at position %d", rec.Seq, i)
		}
		total += len(rec.Observations)
	}
	if len(pc) != 2 || total != observationReportMaxPerRecord+3 {
		t.Fatalf("%d records carrying %d observations", len(pc), total)
	}
}

// End to end without a database: the Edge's reporter, its own shipper and the control plane's receiver. What the
// Edge saw is in the control plane's stores, once, however many times a record arrives.
func TestObservationReportsReachTheControlPlaneOnce(t *testing.T) {
	cpWriter, _ := logs.NewWriter(t.TempDir())
	sink := observationReportSink{eastWest: eastwestobserve.NewStore(), candidates: policycandidate.NewStore()}
	mux := http.NewServeMux()
	registerAuditIngestReceiver(mux, cpWriter, "ship-secret", nil, nil, nil, true, sink)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	edgeDir := t.TempDir()
	edgeWriter, _ := logs.NewWriter(edgeDir)
	shipper, err := newRemoteAuditShipper(srv.URL+"/audit-ingest", "ship-secret", "", observationReportStreams, 64, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer shipper.stop()
	edgeWriter.AddAppendHook(shipper.hook())
	r, _ := newObservationReporter(edgeWriter)
	now := time.Now().UTC().Truncate(time.Second)
	for i := 0; i < 3; i++ {
		r.eastWestFlow("a", "dev-1", "alice", "10.0.0.5", "ssh", 22, now)
		r.candidate(policycandidate.ReportCertPinFailure, "a", "pinned.example", "pinned.example", "", 443, "egress_tls_unrecognized_name", now)
	}
	r.flush()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && (len(sink.eastWest.List("a")) == 0 || sink.candidates.CountForTenant("a") == 0) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := sink.eastWest.List("a"); len(got) != 1 || got[0].Count != 3 {
		t.Fatalf("control plane east-west inventory: %+v", got)
	}
	id := policycandidate.CertPinCandidateID("pinned.example", "pinned.example", 443, "egress_tls_unrecognized_name")
	c, ok, _ := sink.candidates.Get(context.Background(), "a", id)
	if !ok || c.FailureCount != 3 || c.Status != "pending" {
		t.Fatalf("control plane candidate: %+v ok=%v", c, ok)
	}

	// The same records again, as a restarted Edge replays its spool: acknowledged, not counted.
	for _, stream := range observationReportStreams {
		raw, _ := os.ReadFile(filepath.Join(edgeDir, stream))
		if code := postIngest(t, mux, stream, bytes.TrimSpace(raw)); code != http.StatusAccepted {
			t.Fatalf("replay of %s answered %d", stream, code)
		}
	}
	if got := sink.eastWest.List("a"); got[0].Count != 3 {
		t.Fatalf("replay counted again: %+v", got)
	}
	if c, _, _ := sink.candidates.Get(context.Background(), "a", id); c.FailureCount != 3 {
		t.Fatalf("replay counted again: %d", c.FailureCount)
	}
}

// What the shipper acts on: a record no retry can fix is refused with 400 (set aside), a control plane without
// the store answers 503 (kept and retried), and nothing reaches this node's logs either way.
func TestObservationReportRefusals(t *testing.T) {
	dir := t.TempDir()
	cpWriter, _ := logs.NewWriter(dir)
	full := http.NewServeMux()
	registerAuditIngestReceiver(full, cpWriter, "ship-secret", nil, nil, nil, true,
		observationReportSink{eastWest: eastwestobserve.NewStore(), candidates: policycandidate.NewStore()})
	empty := http.NewServeMux()
	registerAuditIngestReceiver(empty, cpWriter, "ship-secret", nil, nil, nil, true, observationReportSink{})
	now := time.Now().UTC().Format(time.RFC3339)
	good := `{"kind":"east_west_observation_report","event_id":"r:s:1","tenant_id":"a","reporter":"r","seq":1,"timestamp":"` + now +
		`","flows":[{"source":"d","destination":"db","service_family":"ssh","port":22,"count":1,"first_seen":"` + now + `","last_seen":"` + now + `"}]}`
	for name, tc := range map[string]struct {
		mux    http.Handler
		stream string
		body   string
		want   int
	}{
		"unknown field":       {full, eastWestObservationReportStream, strings.Replace(good, `"seq":1`, `"seq":1,"extra":true`, 1), http.StatusBadRequest},
		"wrong kind":          {full, candidateObservationReportStream, good, http.StatusBadRequest},
		"no reporter":         {full, eastWestObservationReportStream, strings.Replace(good, `"reporter":"r"`, `"reporter":""`, 1), http.StatusBadRequest},
		"invalid flow":        {full, eastWestObservationReportStream, strings.Replace(good, `"count":1`, `"count":0`, 1), http.StatusBadRequest},
		"store not held here": {empty, eastWestObservationReportStream, good, http.StatusServiceUnavailable},
		"applied":             {full, eastWestObservationReportStream, good, http.StatusAccepted},
	} {
		if code := postIngest(t, tc.mux, tc.stream, []byte(tc.body)); code != tc.want {
			t.Errorf("%s: %d, want %d", name, code, tc.want)
		}
	}
	for _, stream := range observationReportStreams {
		if _, err := os.Stat(filepath.Join(dir, stream)); !os.IsNotExist(err) {
			t.Fatalf("report stream %s was written to the control plane's logs", stream)
		}
	}
}

// With the shared database: a report is acknowledged only after it committed, a redelivery is recognised, and
// a standby control plane answers 503 so the shipper takes the report to the leader.
func TestPostgresObservationReportCommitsBeforeAcknowledging(t *testing.T) {
	db := initialBlobDB(t)
	ewP, pcP := initialBlob(t, db, "observations"), initialBlob(t, db, "candidates")
	peer := &cpLeaderElector{}
	sink := observationReportSink{eastWest: eastwestobserve.NewStore(), candidates: policycandidate.NewStore()}
	if err := sink.eastWest.SetPersister(ewP, 0); err != nil {
		t.Fatal(err)
	}
	if err := sink.candidates.SetPersister(pcP); err != nil {
		t.Fatal(err)
	}
	cpWriter, _ := logs.NewWriter(t.TempDir())
	mux := http.NewServeMux()
	registerAuditIngestReceiver(mux, cpWriter, "ship-secret", nil, nil, nil, true, sink)
	now := time.Now().UTC().Format(time.RFC3339)
	record := func(seq int) []byte {
		b, _ := json.Marshal(observationReportRecord{Kind: "policy_candidate_observation_report", TenantID: "a", Reporter: "edge-1", Seq: uint64(seq), Timestamp: now,
			Observations: []policycandidate.ReportedObservation{{Kind: policycandidate.ReportUnmatchedFlow, Host: "db.example", Port: 5432, Count: 2, LastObserved: now}}})
		return b
	}
	durableCount := func() int {
		fresh := policycandidate.NewStore()
		if err := fresh.SetPersister(pcP); err != nil {
			t.Fatal(err)
		}
		c, _, _ := fresh.Get(context.Background(), "a", policycandidate.LearningCandidateID("db.example", "", 5432))
		return c.FailureCount
	}
	if code := postIngest(t, mux, candidateObservationReportStream, record(1)); code != http.StatusAccepted || durableCount() != 2 {
		t.Fatalf("first report: %d, durable count %d", code, durableCount())
	}
	if code := postIngest(t, mux, candidateObservationReportStream, record(1)); code != http.StatusAccepted || durableCount() != 2 {
		t.Fatalf("redelivery: %d, durable count %d", code, durableCount())
	}

	saved := cpLeaderElectorInstance
	cpLeaderElectorInstance = peer
	code := postIngest(t, mux, candidateObservationReportStream, record(2))
	cpLeaderElectorInstance = saved
	if code != http.StatusServiceUnavailable || durableCount() != 2 {
		t.Fatalf("standby answered %d, durable count %d", code, durableCount())
	}
	if peer.IsLeader() {
		t.Fatal("a standby's refusal changed leadership")
	}
	if code := postIngest(t, mux, candidateObservationReportStream, record(2)); code != http.StatusAccepted || durableCount() != 4 {
		t.Fatalf("delivered to the leader: %d, durable count %d", code, durableCount())
	}
	if sink.candidates.ReconciliationRequired() {
		t.Fatal("a refused report stopped the store")
	}
}

// An Edge whose reports are not reaching the control plane goes on enforcing, so the only place that can say so
// is the node itself: /healthz carries the reports' shipper beside the audit shipper.
func TestHealthzSaysWhetherObservationReportsAreDelivered(t *testing.T) {
	writer, _ := logs.NewWriter(t.TempDir())
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, Registry: connector.NewRegistry(), AdminAuth: newAdminAuthStore()})
	body := func() map[string]any {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		return out
	}
	if _, ok := body()["observation_reporting"]; ok {
		t.Fatal("a node that does not report claims a reporting state")
	}
	shipper, err := newRemoteAuditShipper("", "", "", observationReportStreams, 8, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer shipper.stop()
	r, _ := newObservationReporter(writer)
	r.shipper = shipper
	observationReports.Store(r)
	defer observationReports.Store(nil)
	if _, ok := body()["observation_reporting"].(map[string]any); !ok {
		t.Fatalf("healthz does not say whether reports are delivered: %v", body())
	}
}

func TestObservationPendingLimitIsVisibleAndExistingCountsStillAccumulate(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	r, err := newObservationReporter(writer)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for i := 0; i < observationReportMaxPending+2; i++ {
		r.candidate(policycandidate.ReportUnmatchedFlow, "a", fmt.Sprintf("host-%d.example", i), "", "", 443, "", now)
	}
	if r.pending != observationReportMaxPending || r.dropped.Load() != 2 {
		t.Fatal("pending cap", r.pending, r.dropped.Load())
	}
	r.candidate(policycandidate.ReportUnmatchedFlow, "a", "host-0.example", "", "", 443, "", now)
	for _, item := range r.candidates["a"] {
		if item.Host == "host-0.example" && item.Count != 2 {
			t.Fatal("existing count stopped at capacity")
		}
	}
	r.flush()
	if r.pending != 0 {
		t.Fatal("flush did not release capacity")
	}
	r.candidate(policycandidate.ReportUnmatchedFlow, "a", "after.example", "", "", 443, "", now)
	if r.pending != 1 {
		t.Fatal("capacity did not recover")
	}
}
