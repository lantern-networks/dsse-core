package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/logs"
)

func TestAuditIngestRejectsTenantAliasThatChangesPersistedPartition(t *testing.T) {
	previous := auditIngestAuthorityMap
	auditIngestAuthorityMap = &auditIngestAuthority{byEdge: map[string][]string{"edge-a": {"Acme"}}}
	t.Cleanup(func() { auditIngestAuthorityMap = previous })
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	writer.SetTenantPartitionedFiles("audit.log.jsonl")
	mux := http.NewServeMux()
	registerAuditIngestReceiver(mux, writer, "ship-secret", nil, nil, nil, false, observationReportSink{})
	post := func(body string) int {
		req := reqWithClientCertCN("edge-a")
		req.URL.Path = "/audit-ingest"
		req.Body = io.NopCloser(strings.NewReader(body))
		req.Header.Set("authorization", "Bearer ship-secret")
		req.Header.Set("x-audit-stream", "audit.log.jsonl")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w.Code
	}
	if got := post(`{"tenant_id":"Acme","event":"normal"}`); got != http.StatusAccepted {
		t.Fatalf("canonical tenant record status = %d, want 202", got)
	}
	for _, body := range []string{
		`{"tenant_id":"Acme","TENANT_ID":"other","event":"alias-after"}`,
		`{"TENANT_ID":"other","tenant_id":"Acme","event":"alias-before"}`,
		`{"tenant_id":"Acme","tenant_id":"Acme","event":"duplicate"}`,
	} {
		if got := post(body); got == http.StatusAccepted {
			t.Fatalf("ambiguous tenant record was accepted: %s", body)
		}
	}
}

func TestAuditIngestAuthorityKeepsTenantIDCaseDistinct(t *testing.T) {
	previous := auditIngestAuthorityMap
	auditIngestAuthorityMap = &auditIngestAuthority{byEdge: map[string][]string{"edge-a": {"Acme"}}}
	t.Cleanup(func() { auditIngestAuthorityMap = previous })
	shipper := auditIngestShipper{Identity: "edge-a", CertTenant: "Acme"}
	if !edgeMayShipForTenant(shipper, "Acme") {
		t.Fatal("the exact authorized tenant was rejected")
	}
	if edgeMayShipForTenant(shipper, "acme") {
		t.Fatal("the differently cased tenant inherited another tenant's authority")
	}
	auditIngestAuthorityMap = nil
	if !edgeMayShipForTenant(shipper, "Acme") || edgeMayShipForTenant(shipper, "acme") {
		t.Fatal("single-tenant certificate fallback did not preserve exact tenant identity")
	}
}
