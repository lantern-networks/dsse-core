package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/lantern-networks/dsse-core/eastwestobserve"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/policycandidate"
	"github.com/lantern-networks/dsse-core/reportreceipt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func windowReport(t *testing.T, stream string, seq uint64) []byte {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339)
	rec := observationReportRecord{TenantID: "a", Reporter: "window-edge", Seq: seq, Timestamp: now}
	if stream == eastWestObservationReportStream {
		rec.Kind = "east_west_observation_report"
		rec.Flows = []eastwestobserve.FlowObservation{{Source: "d", Destination: "db", Port: 22, ServiceFamily: "ssh", Count: 1, FirstSeen: now, LastSeen: now}}
	} else {
		rec.Kind = "policy_candidate_observation_report"
		rec.Observations = []policycandidate.ReportedObservation{{Kind: policycandidate.ReportUnmatchedFlow, Host: "db", Port: 22, Count: 1, LastObserved: now}}
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func assertWindowCounts(t *testing.T, sink observationReportSink, want int) {
	t.Helper()
	flows := sink.eastWest.List("a")
	cand, ok, err := sink.candidates.Get(context.Background(), "a", policycandidate.LearningCandidateID("db", "", 22))
	if len(flows) != 1 || flows[0].Count != want || err != nil || !ok || cand.FailureCount != want {
		t.Fatalf("flows=%+v candidate=%+v err=%v", flows, cand, err)
	}
}

func TestObservationExpiredReportSetAsideWithoutFalseAcknowledgement(t *testing.T) {
	for _, stream := range observationReportStreams {
		t.Run(stream, func(t *testing.T) {
			sink := observationReportSink{eastWest: eastwestobserve.NewStore(), candidates: policycandidate.NewStore()}
			writer, err := logs.NewWriter(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Close()
			mux := http.NewServeMux()
			registerAuditIngestReceiver(mux, writer, "ship-secret", nil, nil, nil, true, sink)
			high := reportreceipt.ReplayWindow + 2
			if code := postIngest(t, mux, stream, windowReport(t, stream, high)); code != 202 {
				t.Fatal(code)
			}
			old := windowReport(t, stream, 1)
			if code := postIngest(t, mux, stream, old); code != 422 {
				t.Fatalf("old gap was acknowledged: %d", code)
			}
			srv := httptest.NewServer(mux)
			defer srv.Close()
			path := filepath.Join(t.TempDir(), "spool.ndjson")
			spool, _, err := newShipSpool(path, 64)
			if err != nil {
				t.Fatal(err)
			}
			for _, raw := range [][]byte{old, windowReport(t, stream, high+1)} {
				spool.append(auditShipItem{stream: stream, record: raw})
			}
			spool.close()
			shipper, err := newRemoteAuditShipper(srv.URL+"/audit-ingest", "ship-secret", "", observationReportStreams, 64, path, "", "")
			if err != nil {
				t.Fatal(err)
			}
			defer shipper.stop()
			for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline) && (shipper.shipped.Load() != 1 || shipper.refused.Load() != 1); {
				time.Sleep(10 * time.Millisecond)
			}
			if shipper.shipped.Load() != 1 || shipper.refused.Load() != 1 {
				t.Fatalf("shipped=%d refused=%d", shipper.shipped.Load(), shipper.refused.Load())
			}
			raw, err := os.ReadFile(path + ".refused")
			if err != nil {
				t.Fatal(err)
			}
			var refused struct {
				Stream string `json:"s"`
				Record []byte `json:"r"`
			}
			if err := json.Unmarshal(bytes.TrimSpace(raw), &refused); err != nil || refused.Stream != stream || !bytes.Equal(refused.Record, old) {
				t.Fatalf("refused spool did not retain exact original record: %v", err)
			}
			if stream == eastWestObservationReportStream {
				if sink.eastWest.List("a")[0].Count != 2 {
					t.Fatal("refusal changed flow count")
				}
			} else {
				c, ok, err := sink.candidates.Get(context.Background(), "a", policycandidate.LearningCandidateID("db", "", 22))
				if err != nil || !ok || c.FailureCount != 2 {
					t.Fatalf("refusal changed candidate count: %+v %v", c, err)
				}
			}
			t.Logf("retired=422 shipped=%d refused=%d local_refused_record_retained=true", shipper.shipped.Load(), shipper.refused.Load())
		})
	}
}

func TestPostgresObservationReplayWindow(t *testing.T) {
	db := initialBlobDB(t)
	ewP, pcP := initialBlob(t, db, "observations"), initialBlob(t, db, "candidates")
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	fresh := func() observationReportSink {
		sink := observationReportSink{eastWest: eastwestobserve.NewStore(), candidates: policycandidate.NewStore()}
		if err := sink.eastWest.SetPersister(ewP, 0); err != nil {
			t.Fatal(err)
		}
		if err := sink.candidates.SetPersister(pcP); err != nil {
			t.Fatal(err)
		}
		return sink
	}
	for _, tc := range []struct {
		seq    uint64
		status int
	}{{2, 202}, {reportreceipt.ReplayWindow + 2, 202}, {1, 422}, {2, 422}, {3, 202}, {3, 202}} {
		sink := fresh()
		mux := http.NewServeMux()
		registerAuditIngestReceiver(mux, writer, "ship-secret", nil, nil, nil, true, sink)
		for _, stream := range observationReportStreams {
			p := ewP
			if stream == candidateObservationReportStream {
				p = pcP
			}
			before, err := p.Load()
			if err != nil {
				t.Fatal(err)
			}
			if code := postIngest(t, mux, stream, windowReport(t, stream, tc.seq)); code != tc.status {
				t.Fatalf("%s seq=%d status=%d want=%d", stream, tc.seq, code, tc.status)
			}
			after, err := p.Load()
			if err != nil {
				t.Fatal(err)
			}
			if tc.status == 422 && !bytes.Equal(before, after) {
				t.Fatal("refusal modified committed row")
			}
		}
	}
	assertWindowCounts(t, fresh(), 3)
	t.Log("both streams: 2/high/old-gap/old-applied/first-retained/retry=202/202/422/422/202/202; fresh counts=3; refused SQL payloads unchanged")
}
