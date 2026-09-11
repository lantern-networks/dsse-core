package main

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
)

// Audit decoupling: the shipper forwards only the configured streams to the control-plane ingest endpoint,
// best-effort, without blocking the caller; the local jsonl stays the canonical record.
func TestRemoteAuditShipper(t *testing.T) {
	var got int64
	var mu sync.Mutex
	var streams []string
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		streams = append(streams, r.Header.Get("x-audit-stream"))
		bodies = append(bodies, string(b))
		mu.Unlock()
		atomic.AddInt64(&got, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s, err := newRemoteAuditShipper(srv.URL, "tok", "", []string{"audit.log.jsonl"}, 64, "", "", "")
	if err != nil {
		t.Fatalf("new shipper: %v", err)
	}
	hook := s.hook()
	// audit stream -> shipped; access stream (not configured) -> ignored.
	if err := hook("audit.log.jsonl", []byte(`{"event":"x"}`)); err != nil {
		t.Fatalf("hook returned error (must never block/fail): %v", err)
	}
	if err := hook("access.log.jsonl", []byte(`{"event":"a"}`)); err != nil {
		t.Fatalf("hook error: %v", err)
	}
	// wait for the async ship.
	deadline := time.Now().Add(3 * time.Second)
	for atomic.LoadInt64(&got) < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if atomic.LoadInt64(&got) != 1 {
		t.Fatalf("expected exactly 1 shipped record (audit only), got %d", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(streams) != 1 || streams[0] != "audit.log.jsonl" {
		t.Fatalf("wrong stream header: %v", streams)
	}
	if bodies[0] != `{"event":"x"}` {
		t.Fatalf("wrong body: %q", bodies[0])
	}
}

// Best-effort: a full buffer drops the shipment (counted) without blocking; never errors.
func TestRemoteAuditShipperDropsWhenFull(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-block; w.WriteHeader(200) }))
	defer srv.Close()
	defer close(block)
	s, err := newRemoteAuditShipper(srv.URL, "", "", []string{"audit.log.jsonl"}, 1, "", "", "")
	if err != nil {
		t.Fatalf("new shipper: %v", err)
	}
	hook := s.hook()
	// Flood far past the buffer; the worker is blocked on the server, so the channel fills and excess drops.
	for i := 0; i < 200; i++ {
		if err := hook("audit.log.jsonl", []byte(`{"i":1}`)); err != nil {
			t.Fatalf("hook must never error: %v", err)
		}
	}
	if s.dropped.Load() == 0 {
		t.Fatal("expected some dropped shipments when the buffer is saturated (best-effort, non-blocking)")
	}
}

// Cross-region durability (Phase 2): when the CP is unreachable the shipper RETAINS the record and REPLAYS it
// once a CP is reachable again — no loss within the spool window, and no drop.
func TestRemoteAuditShipperRetainsAndReplays(t *testing.T) {
	var calls, delivered int64
	var mu sync.Mutex
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Fail the first attempt (simulating a CP outage), then accept — the retained record must replay.
		if atomic.AddInt64(&calls, 1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		body = string(b)
		mu.Unlock()
		atomic.AddInt64(&delivered, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s, err := newRemoteAuditShipper(srv.URL, "", "", []string{"audit.log.jsonl"}, 64, "", "", "")
	if err != nil {
		t.Fatalf("new shipper: %v", err)
	}
	if err := s.hook()("audit.log.jsonl", []byte(`{"event":"keep"}`)); err != nil {
		t.Fatalf("hook error: %v", err)
	}
	// The first ship fails; the record is retained and replayed after the (1s) backoff. Wait for the SHIPPER's
	// own settled state (pending drained to 0), not just the server-side `delivered` counter — the historical
	// flake was a check-too-early race: the httptest handler bumps `delivered` and returns BEFORE run executes
	// its post-ship bookkeeping (q=q[1:]; pending.Store(0)), so a test that exits on delivered==1 could then read
	// pending==1. Gating on delivered==1 AND s.pending==0 closes that window. The deadline is a generous UPPER
	// BOUND (the loop exits the instant both hold, so a large value never slows the passing case) that must clear
	// the production retry schedule — backoff doubles 1s→2s→4s→… and each ship has a 10s timeout — so a starved
	// ship under full-suite contention cannot blow it. Correctness is asserted below (exactly-once, no-drop).
	deadline := time.Now().Add(30 * time.Second)
	for (atomic.LoadInt64(&delivered) < 1 || s.pending.Load() != 0) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if atomic.LoadInt64(&delivered) != 1 {
		t.Fatalf("expected the retained record to replay exactly once, delivered=%d calls=%d", delivered, calls)
	}
	if s.failed.Load() == 0 {
		t.Fatal("expected at least one recorded failure (the outage attempt)")
	}
	if s.dropped.Load() != 0 {
		t.Fatalf("a retained-and-replayed record must not be dropped, dropped=%d", s.dropped.Load())
	}
	if s.pending.Load() != 0 {
		t.Fatalf("pending spool should drain to 0 after replay, pending=%d", s.pending.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	if body != `{"event":"keep"}` {
		t.Fatalf("replayed body mismatch: %q", body)
	}
}

// Multi-region: setEndpoints makes baseURL follow the CP selector's current leader; with no CP reachable the
// ship target is "" so the record is retained (not lost) rather than sent to a stale URL.
func TestRemoteAuditShipperBaseURLFollowsEndpoints(t *testing.T) {
	s, err := newRemoteAuditShipper("https://seed:9443/audit-ingest", "", "", []string{"audit.log.jsonl"}, 8, "", "", "")
	if err != nil {
		t.Fatalf("new shipper: %v", err)
	}
	// No endpoints wired -> the fixed seed URL.
	if got := s.baseURL(); got != "https://seed:9443/audit-ingest" {
		t.Fatalf("single-CP baseURL mismatch: %q", got)
	}
	// Wire a selector with a reachable-but-unprobed endpoint list; before any successful probe CurrentBaseURL is
	// the home/first endpoint, so baseURL is that CP's admin base + /audit-ingest.
	sel := newCPEndpointSelector(parseCPEndpoints("region-a=https://cpa:9443;region-b=https://cpb:9443"), "region-a", &http.Client{}, time.Second, 3)
	if sel == nil {
		t.Fatal("selector should build from a valid endpoint list")
	}
	s.setEndpoints(sel)
	got := s.baseURL()
	if got != "https://cpa:9443/audit-ingest" && got != "https://cpb:9443/audit-ingest" && got != "" {
		t.Fatalf("multi-region baseURL should be a CP admin base + /audit-ingest (or \"\" when none healthy), got %q", got)
	}
}

// Audit/persistence decoupling: by default the embedded outbox admin endpoints are registered (so existing
// callers/tests are unchanged), but DisableEmbeddedOutboxAdmin removes them from the Edge surface (404) —
// durable outbox is the control plane's responsibility.
func TestEmbeddedOutboxAdminGating(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	get := func(disable bool) int {
		h := newServerWithConfig(serverConfig{
			Evaluator:                  testEvaluator(),
			Writer:                     writer,
			Registry:                   connector.NewRegistry(),
			AdminAuth:                  newAdminAuthStore(),
			LabMode:                    boolPtr(true),
			DisableEmbeddedOutboxAdmin: disable,
		})
		req := httptest.NewRequest(http.MethodGet, "/admin/audit-outbox/health", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	// Registered (default): reaches the handler -> 501 (no postgres outbox in this config), not 404.
	if code := get(false); code == http.StatusNotFound {
		t.Fatalf("default config should register the outbox endpoint (got 404)")
	}
	// Disabled: removed from the surface -> 404.
	if code := get(true); code != http.StatusNotFound {
		t.Fatalf("DisableEmbeddedOutboxAdmin should remove the endpoint (want 404, got %d)", code)
	}
}

// AddAppendHook composes: both the prior and the added hook run, in order.
func TestWriterAddAppendHookComposes(t *testing.T) {
	w, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	var order []string
	var mu sync.Mutex
	w.SetAppendHook(func(fn string, enc []byte) error { mu.Lock(); order = append(order, "first"); mu.Unlock(); return nil })
	w.AddAppendHook(func(fn string, enc []byte) error { mu.Lock(); order = append(order, "second"); mu.Unlock(); return nil })
	if err := w.Append("audit.log.jsonl", map[string]string{"a": "b"}); err != nil {
		t.Fatalf("append: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(order) != 2 || order[0] != "first" || order[1] != "second" {
		t.Fatalf("hooks must run in order [first second], got %v", order)
	}
}

// ★★ A SHIPPER THAT CANNOT SHIP MUST SAY SO (2026-08-14). On failure this incremented a counter and went back
// to sleep, so an Edge could retain every record it produced without writing one line about it — which is what
// region-b did: 176 records held for an afternoon, the Mac's steering among them, because it had the ingest URL
// and token but not the client certificate the receiver requires. Retain-and-replay is what made that silence
// survivable enough to last: nothing was lost, so nothing complained, and no history reached the control plane.
//
// The log is the only surface that distinguishes "retaining safely through a blip" from "cannot ship at all",
// so this test holds the shipper to saying both edges of the condition.
func TestRemoteAuditShipperSaysWhenItCannotShip(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusUnauthorized) // exactly what region-b was answered
			return
		}
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var logbuf bytes.Buffer
	var logmu sync.Mutex
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&syncWriter{mu: &logmu, w: &logbuf})
	log.SetFlags(0)
	defer func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) }()
	readLog := func() string {
		logmu.Lock()
		defer logmu.Unlock()
		return logbuf.String()
	}

	s, err := newRemoteAuditShipper(srv.URL, "", "", []string{"audit.log.jsonl"}, 64, "", "", "")
	if err != nil {
		t.Fatalf("new shipper: %v", err)
	}
	defer s.stop()
	if err := s.hook()("audit.log.jsonl", []byte(`{"event":"held"}`)); err != nil {
		t.Fatalf("hook error: %v", err)
	}

	deadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(readLog(), "audit ship: FAILING") && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := readLog(); !strings.Contains(got, "audit ship: FAILING") {
		t.Fatalf("the shipper retained a record it could not ship and said nothing. Log was:\n%s", got)
	}
	if got := readLog(); !strings.Contains(got, "401") {
		t.Fatalf("the failure line does not carry WHY, so an operator cannot act on it:\n%s", got)
	}

	// And recovery is an event too: an operator who saw the failure needs to see it end without inferring it
	// from the absence of further complaints.
	fail.Store(false)
	deadline = time.Now().Add(30 * time.Second)
	for !strings.Contains(readLog(), "audit ship: recovered") && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := readLog(); !strings.Contains(got, "audit ship: recovered") {
		t.Fatalf("shipping recovered and the log never said so:\n%s", got)
	}
}

// syncWriter serialises writes from the shipper goroutine with the test's reads.
type syncWriter struct {
	mu *sync.Mutex
	w  *bytes.Buffer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// ★ ONE PERMANENTLY-REFUSED RECORD STOPPED EVERY TENANT'S HISTORY (2026-08-16, found on the reference lab).
// The shipper ships q[0] and retries it on failure, so a record the control plane will never accept blocks
// everything behind it — forever. The lab held 3,390 records and shipped nothing for two days because ONE
// organization was missing from the control plane's authority map and its records came back 403.
//
// A 403 is not a transient condition. Retrying it is not resilience; it is a guarantee that the spool never
// drains. The refused record is set aside — durably, never dropped — and the queue carries on.
func TestOneRefusedRecordDoesNotStopEverythingBehindIt(t *testing.T) {
	var delivered int64
	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		// The control plane refuses records belonging to one organization, exactly as the lab's did.
		if strings.Contains(string(b), "tenant_unauthorised") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		atomic.AddInt64(&delivered, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	spool := t.TempDir() + "/ship_spool.jsonl"
	s, err := newRemoteAuditShipper(srv.URL, "tok", "", []string{"audit.log.jsonl"}, 64, spool, "", "")
	if err != nil {
		t.Fatalf("new shipper: %v", err)
	}
	defer s.stop()
	hook := s.hook()

	// The refused one FIRST, so it is the head of the queue — the position that used to block the rest.
	_ = hook("audit.log.jsonl", []byte(`{"tenant_id":"tenant_unauthorised","event":"blocked"}`))
	for i := 0; i < 3; i++ {
		_ = hook("audit.log.jsonl", []byte(`{"tenant_id":"tenant_ok","event":"behind-it"}`))
	}

	// ★★★ WAIT FOR WHAT IS ABOUT TO BE ASSERTED, NOT FOR ITS PRECONDITION (2026-08-31, reported as an
	// intermittent "refused counter = 0, want 1" under a loaded full-suite run and never reproducible alone).
	//
	// delivered is incremented by the receiver's HTTP handler; the refusal is set aside by the shipper on a
	// LATER pass of its own loop, once it has observed that other records got through. So the third delivery
	// arriving says nothing about whether the refusal has been counted yet, and the gap between them is
	// exactly the scheduling delay that a busy machine widens. Gating on the counter closes it — and because
	// the dead-spool append happens BEFORE refused.Add(1) (audit_ship.go), waiting for the counter also
	// guarantees the spool assertion below.
	//
	// The same fix is already in this file at the retained-record test, on the same reasoning; it was made
	// once and not carried to its neighbours.
	deadline := time.Now().Add(5 * time.Second)
	for (atomic.LoadInt64(&delivered) < 3 || s.refused.Load() < 1) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := atomic.LoadInt64(&delivered); got != 3 {
		t.Fatalf("%d of 3 deliverable records arrived — a refusal at the head still blocks the queue", got)
	}
	if s.refused.Load() != 1 {
		t.Fatalf("refused counter = %d, want 1", s.refused.Load())
	}

	// Set aside, not discarded: "the receiver refuses this" and "this never happened" are different facts.
	dead, err := readShipSpool(spool + ".refused")
	if err != nil {
		t.Fatalf("read the refused spool: %v", err)
	}
	if len(dead) != 1 || !strings.Contains(string(dead[0].record), "tenant_unauthorised") {
		t.Fatalf("the refused record is not in the dead spool: %+v", dead)
	}
}

// And a TRANSIENT failure must still hold the queue, or the fix would turn a control-plane restart into
// silent loss — the opposite mistake, and the one the retain-and-retry design exists to prevent.
func TestATransientFailureStillHoldsTheRecord(t *testing.T) {
	var refuse atomic.Bool
	refuse.Store(true)
	var delivered int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if refuse.Load() {
			w.WriteHeader(http.StatusServiceUnavailable) // the receiver is unwell, not the record
			return
		}
		atomic.AddInt64(&delivered, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	spool := t.TempDir() + "/ship_spool.jsonl"
	s, err := newRemoteAuditShipper(srv.URL, "tok", "", []string{"audit.log.jsonl"}, 64, spool, "", "")
	if err != nil {
		t.Fatalf("new shipper: %v", err)
	}
	defer s.stop()
	_ = s.hook()("audit.log.jsonl", []byte(`{"tenant_id":"tenant_ok","event":"held"}`))

	time.Sleep(400 * time.Millisecond)
	if s.refused.Load() != 0 {
		t.Fatal("a 503 was treated as permanent — a control-plane restart would set records aside instead of retrying")
	}
	if atomic.LoadInt64(&delivered) != 0 {
		t.Fatal("the harness delivered while refusing")
	}

	// The control: once the receiver recovers, the held record arrives. Without it, "nothing was set aside"
	// is also what a shipper that lost the record looks like.
	refuse.Store(false)
	deadline := time.Now().Add(5 * time.Second)
	for atomic.LoadInt64(&delivered) < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if atomic.LoadInt64(&delivered) != 1 {
		t.Fatal("the retained record never arrived after the receiver recovered")
	}
}

// ★ AND A CHANNEL THAT REFUSES EVERYTHING MUST NOT BE READ AS A PILE OF BAD RECORDS (2026-08-16). The first
// version of the fix read "4xx = permanent", and an existing test refuted it within the minute: region-b was
// answered 401 for two days because it had the ingest URL and token but not the client certificate. Nothing
// at all was deliverable there, and retaining every record was exactly right — setting them aside would have
// turned a fixable misconfiguration into a pile nobody would ever replay.
//
// So the shipper runs the experiment instead of trusting the code: rotate the head, try the next, and only
// set a record aside once something ELSE has gone through.
func TestAChannelThatRefusesEverythingSetsNothingAside(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized) // exactly what region-b was answered, for every record
	}))
	defer srv.Close()

	spool := t.TempDir() + "/ship_spool.jsonl"
	s, err := newRemoteAuditShipper(srv.URL, "tok", "", []string{"audit.log.jsonl"}, 64, spool, "", "")
	if err != nil {
		t.Fatalf("new shipper: %v", err)
	}
	defer s.stop()
	hook := s.hook()
	for i := 0; i < 4; i++ {
		_ = hook("audit.log.jsonl", []byte(`{"tenant_id":"tenant_ok","event":"held"}`))
	}
	time.Sleep(700 * time.Millisecond)

	if s.refused.Load() != 0 {
		t.Fatalf("%d record(s) were set aside while NOTHING could be delivered — a misconfiguration was read "+
			"as bad records, and the operator would have had to replay them by hand after fixing it", s.refused.Load())
	}
	if s.pending.Load() != 4 {
		t.Fatalf("pending = %d, want all 4 retained", s.pending.Load())
	}
	dead, _ := readShipSpool(spool + ".refused")
	if len(dead) != 0 {
		t.Fatalf("the refused spool holds %d record(s) that were only ever refused by a broken channel", len(dead))
	}
}
