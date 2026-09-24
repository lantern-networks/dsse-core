package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/eastwestobserve"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/policycandidate"
)

func TestObservationSequenceSurvivesShipperRotation(t *testing.T) {
	cpWriter, _ := logs.NewWriter(t.TempDir())
	sink := observationReportSink{eastWest: eastwestobserve.NewStore()}
	mux := http.NewServeMux()
	registerAuditIngestReceiver(mux, cpWriter, "ship-secret", nil, nil, nil, true, sink)
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	defer srv.Close()
	spoolPath := filepath.Join(t.TempDir(), "spool.ndjson")
	spool, _, err := newShipSpool(spoolPath, 64)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for i, tenant := range []string{"a", "b"} {
		rec := observationReportRecord{Kind: "east_west_observation_report", TenantID: tenant, Reporter: "same-edge-process", Seq: uint64(i + 1), Timestamp: now, Flows: []eastwestobserve.FlowObservation{{Source: "d", Destination: "db", Port: 22, ServiceFamily: "ssh", Count: 1, FirstSeen: now, LastSeen: now}}}
		raw, _ := json.Marshal(rec)
		spool.append(auditShipItem{stream: eastWestObservationReportStream, record: raw})
	}
	spool.close()
	shipper, err := newRemoteAuditShipper(srv.URL+"/audit-ingest", "ship-secret", "", observationReportStreams, 64, spoolPath, "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer shipper.stop()
	deadline := time.Now().Add(5 * time.Second)
	for shipper.shipped.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	t.Logf("attempts=%d shipped=%d refused=%d a=%v b=%v", attempts.Load(), shipper.shipped.Load(), shipper.refused.Load(), sink.eastWest.List("a"), sink.eastWest.List("b"))
	if shipper.shipped.Load() != 2 {
		t.Fatal("did not complete both HTTP deliveries")
	}
	if got := sink.eastWest.List("a"); len(got) != 1 || got[0].Count != 1 {
		t.Fatalf("ACKNOWLEDGED BUT LOST: tenant a must retain its earlier report, got %v", got)
	}
}

// Both report streams share the transactional row with receipts; gaps must also
// survive another reader and the next commit, not just an in-memory cache.
func TestPostgresObservationReportReordering(t *testing.T) {
	d, _, _, _ := trustDistributionPostgresFixture(t)
	base := d.store.(postgresBlobPersister)
	ewP, pcP := base, base
	ewP.key, pcP.key = "east_west_observations", "policy_candidates"
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	now := time.Now().UTC().Format(time.RFC3339)
	for _, seq := range []uint64{3, 1, 2, 3, 1} {
		ew, pc := eastwestobserve.NewStore(), policycandidate.NewStore()
		if err := ew.SetPersister(ewP, 0); err != nil {
			t.Fatal(err)
		}
		if err := pc.SetPersister(pcP); err != nil {
			t.Fatal(err)
		}
		mux := http.NewServeMux()
		registerAuditIngestReceiver(mux, writer, "ship-secret", nil, nil, nil, true, observationReportSink{eastWest: ew, candidates: pc})
		tenant := "a"
		if seq == 3 {
			tenant = "b"
		}
		for _, stream := range observationReportStreams {
			rec := observationReportRecord{TenantID: tenant, Reporter: "reordered-edge", Seq: seq, Timestamp: now}
			if stream == eastWestObservationReportStream {
				rec.Kind = "east_west_observation_report"
				rec.Flows = []eastwestobserve.FlowObservation{{Source: "d", Destination: "db", Port: 22, ServiceFamily: "ssh", Count: 1, FirstSeen: now, LastSeen: now}}
			} else {
				rec.Kind = "policy_candidate_observation_report"
				rec.Observations = []policycandidate.ReportedObservation{{Kind: policycandidate.ReportUnmatchedFlow, Host: "db.example", Port: 5432, Count: 1, LastObserved: now}}
			}
			body, err := json.Marshal(rec)
			if err != nil {
				t.Fatal(err)
			}
			if code := postIngest(t, mux, stream, body); code != http.StatusAccepted {
				t.Fatalf("seq %d stream %s: %d", seq, stream, code)
			}
		}
	}
	ew, pc := eastwestobserve.NewStore(), policycandidate.NewStore()
	if err := ew.SetPersister(ewP, 0); err != nil {
		t.Fatal(err)
	}
	if err := pc.SetPersister(pcP); err != nil {
		t.Fatal(err)
	}
	for tenant, want := range map[string]int{"a": 2, "b": 1} {
		rows := ew.List(tenant)
		if len(rows) != 1 || rows[0].Count != want {
			t.Fatalf("%s flows: %+v", tenant, rows)
		}
		c, ok, err := pc.Get(context.Background(), tenant, policycandidate.LearningCandidateID("db.example", "", 5432))
		if err != nil || !ok || c.FailureCount != want {
			t.Fatalf("%s candidate: %+v %v", tenant, c, err)
		}
	}
}
