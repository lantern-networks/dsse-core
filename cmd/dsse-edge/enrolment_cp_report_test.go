package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The report reaches the control plane, carrying the tenant the device enrolled into — not whatever tenant
// the CP would otherwise infer. Filing it unassigned is a different and wrong claim.
func TestEnrolmentReportNamesTheTenantToTheControlPlane(t *testing.T) {
	var gotPath, gotTenant, gotAuth string
	var gotBody map[string]any
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotTenant, gotAuth = r.URL.Path, r.Header.Get("X-Operate-Tenant"), r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer cp.Close()

	rep := &enrolmentCPReporter{url: cp.URL, token: "cptok", client: cp.Client(),
		outboxPath: filepath.Join(t.TempDir(), "outbox.jsonl")}
	rep.Report(enrolmentReport{Identity: "conn-lab-1", TenantID: "tenant_a", Group: "default", Note: "via POST /enroll"})

	if gotPath != "/admin/enrolled-devices" {
		t.Fatalf("path = %q, want /admin/enrolled-devices", gotPath)
	}
	if gotTenant != "tenant_a" {
		t.Fatalf("X-Operate-Tenant = %q, want tenant_a — without it the CP files the device as unassigned", gotTenant)
	}
	if gotAuth != "Bearer cptok" {
		t.Fatalf("Authorization = %q", gotAuth)
	}
	if gotBody["identity"] != "conn-lab-1" || gotBody["group"] != "default" {
		t.Fatalf("body = %#v", gotBody)
	}
	if _, err := os.Stat(rep.outboxPath); !os.IsNotExist(err) {
		t.Fatalf("a delivered report must not be queued; outbox exists")
	}
}

// THE POINT OF THE WHOLE FILE: a control plane that is away costs a retry, not a device. The report is
// queued durably and delivered when the CP comes back.
func TestEnrolmentReportSurvivesAnUnreachableControlPlane(t *testing.T) {
	var mu sync.Mutex
	up := false
	var delivered []string
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if !up {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		delivered = append(delivered, body["identity"].(string))
		w.WriteHeader(http.StatusOK)
	}))
	defer cp.Close()

	outbox := filepath.Join(t.TempDir(), "outbox.jsonl")
	rep := &enrolmentCPReporter{url: cp.URL, token: "t", client: cp.Client(), outboxPath: outbox}

	rep.Report(enrolmentReport{Identity: "mac-dev-1", TenantID: "tenant_a"})
	raw, err := os.ReadFile(outbox)
	if err != nil {
		t.Fatalf("the report must be QUEUED when the CP refuses: %v", err)
	}
	if !strings.Contains(string(raw), "mac-dev-1") {
		t.Fatalf("outbox = %q, want the queued identity", raw)
	}

	mu.Lock()
	up = true
	mu.Unlock()
	rep.drainOnce(context.Background())

	mu.Lock()
	got := append([]string(nil), delivered...)
	mu.Unlock()
	if len(got) != 1 || got[0] != "mac-dev-1" {
		t.Fatalf("delivered = %v, want [mac-dev-1] once the CP is back", got)
	}
	if _, err := os.Stat(outbox); !os.IsNotExist(err) {
		t.Fatalf("a delivered report must be removed from the outbox")
	}
}

// The queue survives a restart: it is a file, and a new reporter over the same path delivers what the old
// one could not. This is the case the outbox exists for — the Edge restarting while the CP is down.
func TestEnrolmentOutboxSurvivesAProcessRestart(t *testing.T) {
	dir := t.TempDir()
	outbox := filepath.Join(dir, "outbox.jsonl")

	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	first := &enrolmentCPReporter{url: down.URL, token: "t", client: down.Client(), outboxPath: outbox}
	first.Report(enrolmentReport{Identity: "win-dev-1", TenantID: "tenant_a"})
	down.Close()

	var delivered []string
	upSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		delivered = append(delivered, body["identity"].(string))
		w.WriteHeader(http.StatusOK)
	}))
	defer upSrv.Close()

	// A different reporter instance — as after a restart — over the same durable path.
	second := &enrolmentCPReporter{url: upSrv.URL, token: "t", client: upSrv.Client(), outboxPath: outbox}
	second.drainOnce(context.Background())

	if len(delivered) != 1 || delivered[0] != "win-dev-1" {
		t.Fatalf("delivered = %v, want the report queued before the restart", delivered)
	}
}

// A settled refusal is not retried for ever. 409/404 mean the identity is unassigned or owned elsewhere —
// an operator decision this Edge cannot resolve by asking again.
func TestEnrolmentReportDoesNotRetryASettledRefusal(t *testing.T) {
	calls := 0
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusConflict)
	}))
	defer cp.Close()

	outbox := filepath.Join(t.TempDir(), "outbox.jsonl")
	rep := &enrolmentCPReporter{url: cp.URL, token: "t", client: cp.Client(), outboxPath: outbox}
	rep.Report(enrolmentReport{Identity: "someone-elses-device", TenantID: "tenant_a"})

	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}
	if _, err := os.Stat(outbox); !os.IsNotExist(err) {
		t.Fatalf("a 409 must NOT be queued: retrying cannot change an ownership decision")
	}
}

// A reporter with no control plane does nothing at all, so an Edge that is its own authority is unchanged.
func TestEnrolmentReportIsInertWithoutAControlPlane(t *testing.T) {
	var nilReporter *enrolmentCPReporter
	nilReporter.Report(enrolmentReport{Identity: "x", TenantID: "t"}) // must not panic

	outbox := filepath.Join(t.TempDir(), "outbox.jsonl")
	empty := &enrolmentCPReporter{outboxPath: outbox}
	empty.Report(enrolmentReport{Identity: "x", TenantID: "t"})
	if _, err := os.Stat(outbox); !os.IsNotExist(err) {
		t.Fatalf("no control plane means nothing to report and nothing to queue")
	}
}

// The drain loop stops with its context, so it does not outlive the process it belongs to.
func TestEnrolmentDrainStopsWithItsContext(t *testing.T) {
	rep := &enrolmentCPReporter{outboxPath: filepath.Join(t.TempDir(), "o.jsonl"), url: "https://cp.invalid"}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { rep.drain(ctx, 10*time.Millisecond); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("drain did not stop when its context was cancelled")
	}
}
