package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	tenantca "github.com/lantern-networks/dsse-core/tenantca"

	"github.com/lantern-networks/dsse-core/logs"
)

// logReqWithChains builds a POST /logs/access-style request carrying the given JSON body and, when chains
// are supplied, a verified mTLS state (as if it arrived over the (T) transport).
func logReqWithChains(body map[string]any, chains [][]*x509.Certificate) *http.Request {
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "https://edge/logs/access", bytes.NewReader(raw))
	if chains != nil {
		r.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{chains[0][0]},
			VerifiedChains:   chains,
		}
	}
	return r
}

// tenant isolation: access/audit logs are physically partitioned by the row's tenant_id. A
// client posting over the (T) mTLS transport must NOT be able to inject a row into another tenant's
// partition by claiming a foreign tenant_id — appendRawJSONL stamps the cert-proven tenant and denies a
// disagreeing claim.
func TestAppendRawJSONLTenantBinding(t *testing.T) {
	dir := t.TempDir()
	caA := makeTestCA(t, dir, "tenant-A-CA", 31)
	caB := makeTestCA(t, dir, "tenant-B-CA", 32)
	regPath := writeRegistry(t, dir, map[string]string{"tenant_a": caA.pemPath, "tenant_b": caB.pemPath})
	reg, err := tenantca.LoadTenantCARegistry(regPath)
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}
	chainsA := leafSignedBy(t, caA, "dev-a", reg.Pool)
	if chainsA == nil {
		t.Fatal("tenant_a leaf should verify")
	}

	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}
	writer.SetTenantPartitionedFiles("access.log.jsonl")

	t.Run("foreign tenant_id claim denied (no cross-tenant injection)", func(t *testing.T) {
		// tenant_a certificate but the row claims tenant_b — must be rejected, nothing written to tenant_b.
		rec := httptest.NewRecorder()
		appendRawJSONL(rec, logReqWithChains(map[string]any{"tenant_id": "tenant_b", "event": "x"}, chainsA), writer, "access.log.jsonl", reg)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for cross-tenant log injection, got %d", rec.Code)
		}
		rows, _ := writer.ReadJSONLTenant("tenant_b", "access.log.jsonl")
		if len(rows) != 0 {
			t.Fatalf("ISOLATION VIOLATION: %d row(s) leaked into tenant_b partition", len(rows))
		}
	})

	t.Run("own/empty tenant stamped to certificate tenant", func(t *testing.T) {
		rec := httptest.NewRecorder()
		appendRawJSONL(rec, logReqWithChains(map[string]any{"event": "y"}, chainsA), writer, "access.log.jsonl", reg)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("expected 202, got %d", rec.Code)
		}
		a, _ := writer.ReadJSONLTenant("tenant_a", "access.log.jsonl")
		if len(a) != 1 {
			t.Fatalf("expected the row in tenant_a partition, got %d", len(a))
		}
		if a[0]["tenant_id"] != "tenant_a" {
			t.Fatalf("row should be stamped with the cert tenant, got %v", a[0]["tenant_id"])
		}
		// And it must NOT have landed in _system or tenant_b.
		if sys, _ := writer.ReadJSONLTenant("", "access.log.jsonl"); len(sys) != 0 {
			t.Fatalf("row leaked into _system partition (%d)", len(sys))
		}
	})
}
