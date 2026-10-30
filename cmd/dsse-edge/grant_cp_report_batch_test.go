package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/grantstore"
)

func TestGrantReportReconcilesBeyondOneReceiverBody(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	rows := make([]grantstore.Grant, 1800)
	for i := range rows {
		rows[i] = accessIngestGrant(fmt.Sprintf("grant-%04d-%s", i, strings.Repeat("x", 128)), now)
	}
	rows[len(rows)-1].Scope = "app:22"
	rows[len(rows)-1].RequiredFeatures = []string{grantstore.FeatureScopedAuthorization}
	source, authority := grantstore.NewStore(), grantstore.NewStore()
	if _, _, err := source.MergeAuthorityEvidence(rows, now); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerGrantReportRoute(mux, authority, nil, "", true)
	var requests atomic.Int32
	var modernRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request := requests.Add(1)
		if r.ContentLength > maxGrantReportBodyBytes {
			t.Errorf("report exceeded receiver body limit: %d", r.ContentLength)
		}
		if r.URL.Path == "/grant-report-v2" {
			modernRequests.Add(1)
		}
		if request == 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	defer server.Close()
	reporter := &grantCPReporter{url: server.URL + "/grant-report", client: server.Client(), grants: func() *grantstore.Store { return source }}
	reporter.report(context.Background())
	if requests.Load() != 2 {
		t.Fatal("large reconciliation was not divided into requests")
	}
	partial, err := authority.ListAllChecked()
	if err != nil || len(partial) == len(rows) {
		t.Fatalf("failed batch should remain retryable: accepted=%d err=%v", len(partial), err)
	}
	reporter.report(context.Background())
	got, err := authority.ListAllChecked()
	if err != nil || len(got) != len(rows) {
		t.Fatalf("authority accepted %d/%d grants after batched report: %v", len(got), len(rows), err)
	}
	if modern, ok := authority.Get(rows[len(rows)-1].GrantID); !ok || len(modern.RequiredFeatures) != 1 {
		t.Fatal("modern-only grant was not preserved across batched reporting")
	}
	if modernRequests.Load() == 0 {
		t.Fatal("modern-only grant was not sent to the v2 receiver")
	}
}

func TestGrantReportBatchKeepsModernEvidenceOnV2Route(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ordinary := accessIngestGrant("ordinary", now)
	protected := accessIngestGrant("protected", now)
	protected.Scope = "app:22"
	protected.RequiredFeatures = []string{grantstore.FeatureScopedAuthorization}
	batches, err := grantReportBatches([]grantstore.Grant{ordinary, protected})
	if err != nil || len(batches) != 1 || !batches[0].protected || !strings.Contains(string(batches[0].body), `"protected_grants"`) {
		t.Fatalf("modern grant was not isolated for v2 reporting: batches=%d err=%v", len(batches), err)
	}
}
