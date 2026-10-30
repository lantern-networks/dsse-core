package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/inspection"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tenantca"
)

func TestInspectionRuntimeRoutesBindToConnectorCertificateTenant(t *testing.T) {
	dir := t.TempDir()
	caA := makeTestCA(t, dir, "inspection-tenant-a", 71)
	caB := makeTestCA(t, dir, "inspection-tenant-b", 72)
	reg, err := tenantca.LoadTenantCARegistry(writeRegistry(t, dir, map[string]string{
		"tenant-a": caA.pemPath,
		"tenant-b": caB.pemPath,
	}))
	if err != nil {
		t.Fatal(err)
	}
	chains := map[string][][]*x509.Certificate{
		"tenant-a": leafSignedBy(t, caA, "conn-a", reg.Pool),
		"tenant-b": leafSignedBy(t, caB, "conn-b", reg.Pool),
	}
	for tenant, chain := range chains {
		if len(chain) == 0 {
			t.Fatalf("%s client certificate not verified", tenant)
		}
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store := inspection.NewStore(0)
	store.Upsert(model.InspectionEvent{ID: "shared", TenantID: "tenant-a"})
	store.Upsert(model.InspectionEvent{ID: "shared", TenantID: "tenant-b"})
	store.Upsert(model.InspectionEvent{ID: "only-a", TenantID: "tenant-a"})
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		Registry:         connector.NewRegistry(),
		InspectionEvents: store,
		TenantCARegistry: reg,
		LabMode:          boolPtr(false),
	})
	request := func(tenant, method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set(connectorIDHeader, map[string]string{"tenant-a": "conn-a", "tenant-b": "conn-b"}[tenant])
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{chains[tenant][0][0]}, VerifiedChains: chains[tenant]}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		w := request(tenant, http.MethodGet, "/inspection/events/shared", "")
		if w.Code != http.StatusOK {
			t.Fatalf("%s own same-ID read: %d %s", tenant, w.Code, w.Body.String())
		}
		var got model.InspectionEvent
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || got.TenantID != tenant {
			t.Fatalf("%s received another tenant's event: %+v, %v", tenant, got, err)
		}
	}
	if w := request("tenant-b", http.MethodGet, "/inspection/events/only-a", ""); w.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant inspection read status=%d, want 404", w.Code)
	}
	if w := request("tenant-b", http.MethodPost, "/inspection/events", `{"id":"claimed-a","tenant_id":"tenant-a"}`); w.Code < 400 {
		t.Fatalf("cross-tenant inspection write status=%d, want refusal", w.Code)
	}
	if _, ok := store.GetForTenant("tenant-a", "claimed-a"); ok {
		t.Fatal("cross-tenant inspection claim was stored")
	}
	if w := request("tenant-b", http.MethodPost, "/inspection/events", `{"id":"own-b","tenant_id":"tenant-b"}`); w.Code != http.StatusAccepted {
		t.Fatalf("tenant-b inspection write status=%d: %s", w.Code, w.Body.String())
	}
}
