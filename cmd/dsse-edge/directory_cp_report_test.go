package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	humanidentity "github.com/lantern-networks/dsse-core/humanidentity"
	"github.com/lantern-networks/dsse-core/model"
)

func directoryReportFixture() directoryImportReport {
	return directoryImportReport{
		TenantID: "tenant_northwind", ConnectorID: "conn-northwind",
		Request: humanidentity.HumanIdentityDirectoryImportRequest{
			Source: "scim",
			Identities: []model.HumanIdentity{
				{TenantID: "tenant_northwind", ID: "hi_relay", Subject: "relay@northwind.example", Status: "active", Source: "scim"},
			},
		},
	}
}

// A connector's import reaches the CP machine door with the tenant, connector
// and source claims it must independently check against its own authorities.
func TestAConnectorImportIsCarriedToTheControlPlane(t *testing.T) {
	var gotPath string
	var gotReport directoryImportReport
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotReport)
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-Operate-Tenant") != "" {
			t.Errorf("machine report used operator credentials or tenant header")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	outbox := filepath.Join(t.TempDir(), "outbox.jsonl")
	reporter := &directoryCPReporter{url: server.URL, client: server.Client(), outboxPath: outbox}
	if err := reporter.Report(directoryReportFixture()); err != nil {
		t.Fatal(err)
	}

	if gotPath != "/directory-import-report" {
		t.Fatalf("the import was carried to %q, want the CP machine route", gotPath)
	}
	if gotReport.TenantID != "tenant_northwind" || gotReport.ConnectorID != "conn-northwind" {
		t.Fatalf("the machine report lost its tenant or connector claim")
	}
	if gotReport.Request.Source != "scim" {
		t.Fatalf("the carried request lost its source: %q", gotReport.Request.Source)
	}
	if _, err := os.Stat(outbox); !os.IsNotExist(err) {
		t.Fatalf("a delivered report was queued anyway")
	}
}

// ★ The half that matters when it is 3am: a control plane that is away must not lose the people. The
// connector has already been told the import succeeded and has moved its checkpoint on, so it will not send
// these records again — the retry can only come from here.
func TestAnUnreachableControlPlaneDoesNotLoseThePeople(t *testing.T) {
	var accepting atomic.Bool
	var delivered atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !accepting.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		delivered.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	outbox := filepath.Join(t.TempDir(), "outbox.jsonl")
	reporter := &directoryCPReporter{url: server.URL, client: server.Client(), outboxPath: outbox}
	if err := reporter.Report(directoryReportFixture()); err != nil {
		t.Fatal(err)
	}

	queued, err := os.ReadFile(outbox)
	if err != nil || len(queued) == 0 {
		t.Fatalf("the control plane refused and the import was not queued (err=%v) — those people are lost, and "+
			"the connector will not send them again", err)
	}

	accepting.Store(true)
	reporter.drainOnce(context.Background())
	if delivered.Load() != 1 {
		t.Fatalf("the control plane came back and the queued import was delivered %d time(s), want 1", delivered.Load())
	}
	if _, err := os.Stat(outbox); !os.IsNotExist(err) {
		t.Fatalf("a delivered report stayed in the outbox and will be replayed forever")
	}
}

// A content or route refusal must not be acknowledged as a successful
// checkpoint, and the original report remains available for correction.
func TestADirectoryReportRefusalKeepsTheObligation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	outbox := filepath.Join(t.TempDir(), "outbox.jsonl")
	var said string
	reporter := &directoryCPReporter{url: server.URL, client: server.Client(), outboxPath: outbox,
		logf: func(format string, args ...interface{}) { said = format }}
	if err := reporter.Report(directoryReportFixture()); err == nil {
		t.Fatal("control-plane refusal was acknowledged as a successful connector checkpoint")
	}

	if _, err := os.Stat(outbox); err != nil {
		t.Fatalf("control-plane refusal lost the source report: %v", err)
	}
	if said == "" {
		t.Fatalf("a refused report was saved without an operator-visible warning")
	}
	reporter.drainOnce(context.Background())
	if _, err := os.Stat(outbox); err != nil {
		t.Fatalf("replay discarded a refused report: %v", err)
	}
}

// An Edge with no control plane has nothing to carry to, and must not spend a request or an outbox line
// finding that out on every import.
func TestAnEdgeWithNoControlPlaneCarriesNothing(t *testing.T) {
	outbox := filepath.Join(t.TempDir(), "outbox.jsonl")
	reporter := &directoryCPReporter{outboxPath: outbox}
	if err := reporter.Report(directoryReportFixture()); err == nil {
		t.Fatal("unconfigured reporter was acknowledged")
	}
	if _, err := os.Stat(outbox); !os.IsNotExist(err) {
		t.Fatalf("an Edge with no control plane queued a report for nobody")
	}
	var nilReporter *directoryCPReporter
	if err := nilReporter.Report(directoryReportFixture()); err == nil {
		t.Fatal("nil reporter was acknowledged")
	}
	_ = time.Now
}

func TestDirectoryImportOutboxFollowsPromotedControlPlane(t *testing.T) {
	previous := controlChannelSelector.Load()
	previousData := cpDataEndpoints.Load()
	t.Cleanup(func() { controlChannelSelector.Store(previous); cpDataEndpoints.Store(previousData) })
	var oldCalls, promotedCalls atomic.Int32
	oldCP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		oldCalls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer oldCP.Close()
	promotedCP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var report directoryImportReport
		if r.URL.Path != "/directory-import-report" || json.NewDecoder(r.Body).Decode(&report) != nil || report.TenantID != "tenant_northwind" {
			t.Errorf("directory report lost the route or tenant on failover")
		}
		promotedCalls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer promotedCP.Close()
	sel := &cpEndpointSelector{regions: []string{"region-a", "region-b"}, current: oldCP.URL, currentRegion: "region-a"}
	controlChannelSelector.Store(sel)
	data := map[string]string{"region-a": oldCP.URL, "region-b": promotedCP.URL}
	cpDataEndpoints.Store(&data)
	outbox := filepath.Join(t.TempDir(), "outbox.jsonl")
	reporter := &directoryCPReporter{url: oldCP.URL, client: oldCP.Client(), outboxPath: outbox}
	reporter.Report(directoryReportFixture())
	if oldCalls.Load() != 1 {
		t.Fatalf("initial report did not try the original control plane: calls=%d", oldCalls.Load())
	}
	if _, err := os.Stat(outbox); err != nil {
		t.Fatalf("offline import was not queued: %v", err)
	}
	sel.mu.Lock()
	sel.current = promotedCP.URL
	sel.currentRegion = "region-b"
	sel.mu.Unlock()
	reporter.drainOnce(context.Background())
	if promotedCalls.Load() != 1 || oldCalls.Load() != 1 {
		t.Fatalf("queued import did not follow the promoted CP: old=%d promoted=%d", oldCalls.Load(), promotedCalls.Load())
	}
	if _, err := os.Stat(outbox); !os.IsNotExist(err) {
		t.Fatalf("promoted CP accepted report, but it remains queued: %v", err)
	}
}
