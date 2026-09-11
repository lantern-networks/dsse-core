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
		TenantID: "tenant_northwind",
		Request: humanidentity.HumanIdentityDirectoryImportRequest{
			Source: "scim",
			Identities: []model.HumanIdentity{
				{TenantID: "tenant_northwind", ID: "hi_relay", Subject: "relay@northwind.example", Status: "active", Source: "scim"},
			},
		},
	}
}

// A connector's import reaches the control plane, addressed to the organization it came from. Without the
// tenant header the control plane would file the people under whatever tenant the Edge's own credential
// belongs to, which is a different and wrong claim.
func TestAConnectorImportIsCarriedToTheControlPlane(t *testing.T) {
	var gotTenant, gotPath string
	var gotSource string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotTenant = r.Header.Get("X-Operate-Tenant")
		raw, _ := io.ReadAll(r.Body)
		var request humanidentity.HumanIdentityDirectoryImportRequest
		_ = json.Unmarshal(raw, &request)
		gotSource = request.Source
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	outbox := filepath.Join(t.TempDir(), "outbox.jsonl")
	reporter := &directoryCPReporter{url: server.URL, token: "t", client: server.Client(), outboxPath: outbox}
	reporter.Report(directoryReportFixture())

	if gotPath != "/admin/human-identities/import" {
		t.Fatalf("the import was carried to %q, want the control plane's own import route", gotPath)
	}
	if gotTenant != "tenant_northwind" {
		t.Fatalf("the import was carried without naming the organization (X-Operate-Tenant=%q), so the control "+
			"plane would file these people under the Edge's own tenant", gotTenant)
	}
	if gotSource != "scim" {
		t.Fatalf("the carried request lost its source: %q", gotSource)
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
	reporter := &directoryCPReporter{url: server.URL, token: "t", client: server.Client(), outboxPath: outbox}
	reporter.Report(directoryReportFixture())

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

// The other direction: a refusal that retrying cannot fix must NOT sit in the outbox replaying itself. It is
// dropped, and the log says the control plane does not hold those people — an honest gap beats a queue that
// never empties.
func TestARefusalThatCannotBeFixedIsNotQueued(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	outbox := filepath.Join(t.TempDir(), "outbox.jsonl")
	var said string
	reporter := &directoryCPReporter{url: server.URL, token: "t", client: server.Client(), outboxPath: outbox,
		logf: func(format string, args ...interface{}) { said = format }}
	reporter.Report(directoryReportFixture())

	if _, err := os.Stat(outbox); !os.IsNotExist(err) {
		t.Fatalf("a permanently-refused report was queued and will replay for as long as the outbox lives")
	}
	if said == "" {
		t.Fatalf("a permanently-refused report was dropped in silence")
	}
}

// An Edge with no control plane has nothing to carry to, and must not spend a request or an outbox line
// finding that out on every import.
func TestAnEdgeWithNoControlPlaneCarriesNothing(t *testing.T) {
	outbox := filepath.Join(t.TempDir(), "outbox.jsonl")
	reporter := &directoryCPReporter{outboxPath: outbox}
	reporter.Report(directoryReportFixture())
	if _, err := os.Stat(outbox); !os.IsNotExist(err) {
		t.Fatalf("an Edge with no control plane queued a report for nobody")
	}
	var nilReporter *directoryCPReporter
	nilReporter.Report(directoryReportFixture()) // must not panic
	_ = time.Now
}
