package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
)

// An Edge used to carry its records to the control plane one request per record. Under a load that produced
// them faster than that, its spool filled for as long as the load lasted (measured with 10,006 devices,
// 2026-11-11). These exercise the many-records route against the real receiver.

// realAuditReceiver is the control plane's own receiver behind a counting front, held closed until release.
func realAuditReceiver(t *testing.T, withBatchRoute bool) (srv *httptest.Server, writer *logs.Writer, requests, batches *int64, release func()) {
	t.Helper()
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { writer.Close() })
	mux := http.NewServeMux()
	registerAuditIngestReceiver(mux, writer, "ship-secret", nil, nil, nil, true, observationReportSink{})
	managementListener := adminSurfaceOnlyMiddleware(mux)
	requests, batches = new(int64), new(int64)
	gate := make(chan struct{})
	var once sync.Once
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-gate
		atomic.AddInt64(requests, 1)
		if r.URL.Path == auditIngestBatchPath {
			if !withBatchRoute {
				http.NotFound(w, r) // what a control plane of an earlier release answers
				return
			}
			atomic.AddInt64(batches, 1)
		}
		// Through the middleware of the listener an Edge actually ships to. Registering the route was not
		// enough: this listener serves a named list of paths and answered the new one with 404, which the
		// shipper reads as "a control plane of an earlier release" — so batching never took effect on a
		// real deployment while every test of the receiver alone passed (review, 2026-11-14).
		managementListener.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, writer, requests, batches, func() { once.Do(func() { close(gate) }) }
}

func waitForShipping(t *testing.T, what string, done func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if done() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func persisted(t *testing.T, writer *logs.Writer) int {
	t.Helper()
	rows, err := writer.ReadJSONL("audit.log.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

func TestRecordsThatQueuedUpTravelTogether(t *testing.T) {
	srv, writer, requests, batches, release := realAuditReceiver(t, true)
	s, err := newRemoteAuditShipper(srv.URL+"/audit-ingest", "ship-secret", "", []string{"audit.log.jsonl"}, 4096, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.stop()
	const n = 500
	hook := s.hook()
	for i := 0; i < n; i++ {
		if err := hook("audit.log.jsonl", []byte(fmt.Sprintf(`{"event":"e%d","tenant_id":"t1"}`, i))); err != nil {
			t.Fatal(err)
		}
	}
	release()
	waitForShipping(t, "every record to be shipped", func() bool { return s.shipped.Load() == n })
	if got := persisted(t, writer); got != n {
		t.Fatalf("the control plane holds %d record(s), want %d", got, n)
	}
	if atomic.LoadInt64(batches) == 0 {
		t.Fatal("no batch was sent")
	}
	if got, _ := s.health(time.Now())["batches"].(int64); got == 0 {
		t.Fatal("the shipper's health does not say that batches were answered")
	}
	if got := atomic.LoadInt64(requests); got > n/10 {
		t.Fatalf("%d records took %d requests — they are still travelling one at a time", n, got)
	}
	if s.pending.Load() != 0 || s.failed.Load() != 0 {
		t.Fatalf("pending=%d failed=%d after everything shipped", s.pending.Load(), s.failed.Load())
	}
}

func TestAControlPlaneWithoutTheBatchRouteStillReceivesEveryRecord(t *testing.T) {
	srv, writer, _, batches, release := realAuditReceiver(t, false)
	s, err := newRemoteAuditShipper(srv.URL+"/audit-ingest", "ship-secret", "", []string{"audit.log.jsonl"}, 4096, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.stop()
	const n = 40
	hook := s.hook()
	for i := 0; i < n; i++ {
		_ = hook("audit.log.jsonl", []byte(fmt.Sprintf(`{"event":"e%d","tenant_id":"t1"}`, i)))
	}
	release()
	waitForShipping(t, "every record to be shipped one at a time", func() bool { return s.shipped.Load() == n })
	if got := persisted(t, writer); got != n {
		t.Fatalf("the control plane holds %d record(s), want %d", got, n)
	}
	if atomic.LoadInt64(batches) != 0 {
		t.Fatal("this receiver has no batch route; the test is not testing the fallback")
	}
	if s.failed.Load() != 0 {
		t.Fatalf("falling back was counted as %d failure(s); an earlier release's control plane is not an outage", s.failed.Load())
	}
	if got, _ := s.health(time.Now())["batches"].(int64); got != 0 {
		t.Fatalf("health reports %d answered batch(es) against a control plane with no batch route", got)
	}
}

func TestARecordTheControlPlaneRefusesInABatchIsSetAsideAndTheRestArrive(t *testing.T) {
	srv, writer, _, batches, release := realAuditReceiver(t, true)
	dir := t.TempDir()
	s, err := newRemoteAuditShipper(srv.URL+"/audit-ingest", "ship-secret", "", []string{"audit.log.jsonl", "secrets.jsonl"}, 4096, dir+"/spool.jsonl", "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.stop()
	hook := s.hook()
	const good = 30
	for i := 0; i < good; i++ {
		if i == 10 {
			// A stream the receiver does not accept: refused with 400, for this record and no other.
			_ = hook("secrets.jsonl", []byte(`{"event":"never-accepted","tenant_id":"t1"}`))
		}
		_ = hook("audit.log.jsonl", []byte(fmt.Sprintf(`{"event":"e%d","tenant_id":"t1"}`, i)))
	}
	release()
	waitForShipping(t, "the accepted records to arrive and the refused one to be set aside", func() bool {
		return s.shipped.Load() == good && s.refused.Load() == 1 && s.pending.Load() == 0
	})
	if got := persisted(t, writer); got != good {
		t.Fatalf("the control plane holds %d record(s), want %d", got, good)
	}
	if atomic.LoadInt64(batches) == 0 {
		t.Fatal("no batch was sent; the refusal was not met inside one")
	}
	if s.dropped.Load() != 0 {
		t.Fatalf("%d record(s) dropped", s.dropped.Load())
	}
}

// The batch route answers each record exactly as the single-record route would.
func TestTheBatchRouteAnswersEachRecordAsTheSingleRouteDoes(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	mux := http.NewServeMux()
	registerAuditIngestReceiver(mux, writer, "ship-secret", nil, nil, nil, true, observationReportSink{})
	records := []auditIngestBatchRecord{
		{Stream: "audit.log.jsonl", Record: json.RawMessage(`{"event":"ok","tenant_id":"t1"}`)},
		{Stream: "secrets.jsonl", Record: json.RawMessage(`{"event":"unknown stream","tenant_id":"t1"}`)},
		{Stream: "audit.log.jsonl", Record: json.RawMessage(`{"event":"ok too","tenant_id":"t1"}`)},
	}
	single := make([]int, len(records))
	for i, rec := range records {
		req := httptest.NewRequest(http.MethodPost, "/audit-ingest", strings.NewReader(string(rec.Record)))
		req.Header.Set("authorization", "Bearer ship-secret")
		req.Header.Set("x-audit-stream", rec.Stream)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		single[i] = w.Code
	}
	body, _ := json.Marshal(auditIngestBatch{Records: records})
	post := func(bearer string, body io.Reader) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, auditIngestBatchPath, body)
		req.Header.Set("authorization", "Bearer "+bearer)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w
	}
	w := post("ship-secret", strings.NewReader(string(body)))
	if w.Code != http.StatusOK {
		t.Fatalf("batch status %d: %s", w.Code, w.Body.String())
	}
	var answer auditIngestBatchAnswer
	if err := json.Unmarshal(w.Body.Bytes(), &answer); err != nil || len(answer.Results) != len(records) {
		t.Fatalf("batch answer %s (%v)", w.Body.String(), err)
	}
	for i := range records {
		if answer.Results[i].Status != single[i] {
			t.Errorf("record %d: the batch route says %d, the single route said %d", i, answer.Results[i].Status, single[i])
		}
	}
	if single[0] != http.StatusAccepted || single[1] != http.StatusBadRequest {
		t.Fatalf("the single route answered %v; the comparison above compared nothing useful", single)
	}
	if got := post("wrong", strings.NewReader(string(body))).Code; got != http.StatusUnauthorized {
		t.Fatalf("a batch with the wrong bearer was answered %d, want 401", got)
	}
	if got := post("ship-secret", strings.NewReader(strings.Repeat("x", maxAuditIngestBatchBytes+10))).Code; got != http.StatusRequestEntityTooLarge {
		t.Fatalf("an oversized batch was answered %d, want 413", got)
	}
}

func TestTheManagementListenerServesTheBatchRoute(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	mux := http.NewServeMux()
	registerAuditIngestReceiver(mux, writer, "ship-secret", nil, nil, nil, true, observationReportSink{})
	listener := adminSurfaceOnlyMiddleware(mux)
	post := func(path, body string, stream string) int {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("authorization", "Bearer ship-secret")
		if stream != "" {
			req.Header.Set("x-audit-stream", stream)
		}
		w := httptest.NewRecorder()
		listener.ServeHTTP(w, req)
		return w.Code
	}
	if got := post("/audit-ingest", `{"event":"x","tenant_id":"t1"}`, "audit.log.jsonl"); got != http.StatusAccepted {
		t.Fatalf("one record: %d", got)
	}
	if got := post(auditIngestBatchPath, `{"records":[{"stream":"audit.log.jsonl","record":{"event":"y","tenant_id":"t1"}}]}`, ""); got != http.StatusOK {
		t.Fatalf("the batch route on the management listener answered %d", got)
	}
	// Still authenticated there.
	req := httptest.NewRequest(http.MethodPost, auditIngestBatchPath, strings.NewReader(`{"records":[]}`))
	w := httptest.NewRecorder()
	listener.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("a batch with no bearer was answered %d", w.Code)
	}
}
