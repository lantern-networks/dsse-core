package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tenantca"
)

func TestConnectorReportsEnforceShipperAndExistingOwner(t *testing.T) {
	dir := t.TempDir()
	ca := makeTestCA(t, dir, "connector-report-ca", 78)
	certs, err := tenantca.LoadTenantCARegistry(writeRegistry(t, dir, map[string]string{"tenant_a": ca.pemPath}))
	if err != nil {
		t.Fatal(err)
	}
	chains := leafSignedBy(t, ca, "edge-a", certs.Pool)
	old := auditIngestAuthorityMap
	t.Cleanup(func() { auditIngestAuthorityMap = old })
	for _, tc := range []struct {
		name, tenant, existing string
		authority              *auditIngestAuthority
		status                 int
	}{
		{"own", "tenant_a", "", nil, 204},
		{"foreign", "tenant_b", "", nil, 403},
		{"delegated", "tenant_b", "", &auditIngestAuthority{byEdge: map[string][]string{"edge-a": {"tenant_b"}}}, 204},
		{"wildcard", "tenant_b", "", &auditIngestAuthority{byEdge: map[string][]string{"edge-a": {"*"}}}, 204},
		{"unmapped", "tenant_a", "", &auditIngestAuthority{byEdge: map[string][]string{}}, 403},
		{"foreign attachment with own body", "tenant_a", "tenant_b", nil, 403},
		{"own attachment", "tenant_a", "tenant_a", nil, 204},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auditIngestAuthorityMap = tc.authority
			registry := connector.NewRegistry()
			var original model.ConnectorRegistration
			if tc.existing != "" {
				if _, err := registry.Register(model.ConnectorRegistration{ID: "conn-report", TenantID: tc.existing,
					PrivateBaseURL: "https://internal.invalid", AttachedRegionID: "region-original", Status: "registered"}, time.Now()); err != nil {
					t.Fatal(err)
				}
				original, _ = registry.Get("conn-report")
			}
			body, err := json.Marshal(map[string]any{"tenant_id": tc.tenant, "attached_region_id": "region-new",
				"registration": model.ConnectorRegistration{ID: "conn-report", PrivateBaseURL: "https://internal.invalid",
					Status: "online", LastHeartbeatAt: "2026-10-23T00:00:00Z"}})
			if err != nil {
				t.Fatal(err)
			}
			mux := http.NewServeMux()
			registerConnectorReportRoute(mux, registry, certs, "", false)
			req := httptest.NewRequest("POST", "/connector-report", bytes.NewReader(body))
			req.TLS = &tls.ConnectionState{PeerCertificates: chains[0][:1], VerifiedChains: chains}
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)
			if w.Code != tc.status {
				t.Errorf("status=%d want=%d: %s", w.Code, tc.status, w.Body.String())
			}
			got, exists := registry.Get("conn-report")
			if tc.status == 204 {
				if !exists || got.TenantID != tc.tenant || got.AttachedRegionID != "region-new" {
					t.Fatalf("accepted report not recorded: %+v", got)
				}
			} else if tc.existing == "" && exists {
				t.Fatal("refused report created a connector")
			} else if tc.existing != "" && (got.AttachedRegionID != original.AttachedRegionID || got.Status != original.Status || got.LastHeartbeatAt != original.LastHeartbeatAt) {
				t.Fatalf("refused report changed the foreign connector: %+v", got)
			}
		})
	}
}
