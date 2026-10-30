package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tenantca"
)

type startupAdoptionProbe struct {
	observedExclusionStoreAPI
	devices map[string][]string
}

func (s *startupAdoptionProbe) TransportCAReadiness(tenant, fingerprint string, devices []string) transportCAReadiness {
	s.devices[tenant] = append([]string(nil), devices...)
	return s.observedExclusionStoreAPI.TransportCAReadiness(tenant, fingerprint, devices)
}

func TestPKIInventoryMeasuresOnlyExactTenantDevices(t *testing.T) {
	old := transportTenantCertificates
	t.Cleanup(func() { transportTenantCertificates = old })
	transportTenantCertificates = newTransportTenantCerts()
	ca := makeTestCA(t, t.TempDir(), "tenant anchor", 92)
	anchor, err := os.ReadFile(ca.pemPath)
	if err != nil {
		t.Fatal(err)
	}
	transportTenantCertificates.anchorOf["Acme"] = string(anchor)
	ledger := enrolledinventory.NewLedger()
	for id, tenant := range map[string]string{"own": "Acme", "foreign": "acme"} {
		if _, err := ledger.Enroll(id, tenant, "", time.Now().UTC().Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}
	probe := &startupAdoptionProbe{observedExclusionStoreAPI: newObservedExclusionStore(10), devices: map[string][]string{}}
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(), EnrolledLedger: ledger, ObservedExclusions: probe, LabMode: boolPtr(true)})
	w := doAdmin(t, h, http.MethodGet, "/admin/pki/certificates", "")
	if w.Code != 200 {
		t.Fatalf("inventory: %d %s", w.Code, w.Body.String())
	}
	if got := probe.devices["Acme"]; len(got) != 1 || got[0] != "own" {
		t.Fatalf("adoption measured foreign devices: %v", got)
	}
}

func TestRecentLogSummaryKeepsCaseDistinctTenantsSeparate(t *testing.T) {
	w, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"Acme", "acme"} {
		if err := w.Append("audit.log.jsonl", map[string]any{"tenant_id": tenant, "id": tenant}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := adminRecentLogs(w, "Acme")
	if err != nil {
		t.Fatal(err)
	}
	summary := got["audit.log.jsonl"].(map[string]any)
	if summary["count"] != 1 || summary["latest"].(map[string]any)["tenant_id"] != "Acme" {
		t.Fatalf("tenant summary exposed another tenant: %#v", summary)
	}
}

func TestEnrolledAssetSyncDoesNotRelabelAnotherTenant(t *testing.T) {
	ledger := enrolledinventory.NewLedger()
	for id, tenant := range map[string]string{"own-device": "tenant_lab_001", "foreign-device": "TENANT_LAB_001"} {
		if _, err := ledger.Enroll(id, tenant, "", time.Now().UTC().Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}
	assets := assetcatalog.NewStore()
	newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(), EnrolledLedger: ledger, AssetStore: assets, LabMode: boolPtr(true)})
	got := assets.ListEndpoints("tenant_lab_001")
	if len(got) != 1 || got[0].Identity != "own-device" {
		t.Fatalf("tenant assets contain foreign enrollment: %+v", got)
	}
}

func TestConnectorHeartbeatCannotChangeAuthenticatedTarget(t *testing.T) {
	dir := t.TempDir()
	ca := makeTestCA(t, dir, "connector boundary", 91)
	cas, err := tenantca.LoadTenantCARegistry(writeRegistry(t, dir, map[string]string{"tenant_lab_001": ca.pemPath}))
	if err != nil {
		t.Fatal(err)
	}
	chains := leafSignedBy(t, ca, "conn_lab_001", cas.Pool)
	registry := connector.NewRegistry()
	for _, id := range []string{"conn_lab_001", "victim"} {
		if _, err := registry.Register(model.ConnectorRegistration{ID: id, TenantID: "tenant_lab_001", PrivateBaseURL: "https://private.example", Status: "healthy"}, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, Registry: registry, TenantCARegistry: cas, LabMode: boolPtr(true)})
	r := httptest.NewRequest(http.MethodPost, "/connectors/conn_lab_001/heartbeat", strings.NewReader(`{"id":"victim","tenant_id":"tenant_lab_001","status":"offline"}`))
	r.TLS = &tls.ConnectionState{PeerCertificates: chains[0], VerifiedChains: chains}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("authenticated connector changed body target: status=%d body=%s", w.Code, w.Body.String())
	}
	got, _ := registry.Get("victim")
	if got.Status != "healthy" {
		t.Fatalf("victim changed: %+v", got)
	}
}
