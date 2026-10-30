package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
)

func TestPublishedAgentTrustUsesExactTenantIssuer(t *testing.T) {
	now := time.Now()
	interception, err := edgeplane.NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	roots := map[string]string{}
	for _, tenant := range []string{"Acme", "acme"} {
		root, issuer, key := offlineTenantBundleForTest(t, tenant, now)
		if _, err := interception.LoadOfflineTenantIntermediate(tenant, root, issuer, key); err != nil {
			t.Fatal(err)
		}
		roots[tenant] = string(root)
	}
	publisher := &localNetworkExtensionSnapshotPublisher{}
	publisher.SetTrustedCABundleSource(func(tenant string) map[string]any {
		return agentTrustedCABundle(interception, tenant, "")
	})
	for _, tenant := range []string{"Acme", "acme"} {
		bundle, ok := publisher.agentConfig(tenant)["trusted_ca_bundle"].(map[string]any)
		if !ok || bundle["interception_root_pem"] != roots[tenant] {
			t.Fatalf("published trust for %q must contain only its exact tenant root", tenant)
		}
	}
}

func TestMeasuredZeroAdoptionRefusesTransportReplacement(t *testing.T) {
	ca, key, caPEM := testAdmissionCA(t)
	leaf := issueLeaf(t, ca, key, &x509.Certificate{
		DNSNames: []string{"edge.example.invalid"}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true,
	})
	leafPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))
	ledger := enrolledinventory.NewLedger()
	if _, err := ledger.Enroll("endpoint-1", "tenant_a", "", time.Now().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	config := serverConfig{
		TransportCertFile: "/tmp/transport.pem", TransportTLSURL: "https://edge.example.invalid:18543",
		TrustBundleCAPEM: caPEM, EnrolledLedger: ledger, TenantIDForTrust: "tenant_a",
		ObservedExclusions: fakeObserved{ready: map[string][]string{}},
	}
	if err := guardServedCertificateChange(config, "transport", leafPEM); err == nil || !strings.Contains(err.Error(), "adopt") {
		t.Fatalf("known endpoint with no adopted root must block replacement, got %v", err)
	}
	config.ObservedExclusions = fakeObserved{ready: map[string][]string{certFingerprint(ca): {"endpoint-1"}}}
	if err := guardServedCertificateChange(config, "transport", leafPEM); err != nil {
		t.Fatalf("replacement under a root adopted by every known endpoint must pass: %v", err)
	}
	config.ObservedExclusions = nil
	if err := guardServedCertificateChange(config, "transport", leafPEM); err != nil {
		t.Fatalf("absence of adoption measurement keeps the distribution-only contract: %v", err)
	}
}

func TestPKICertificateRouteScopesCaseDistinctTenantAndNotHolding(t *testing.T) {
	ledger := enrolledinventory.NewLedger()
	for _, row := range []struct{ id, tenant string }{{"own-device", "acme"}, {"foreign-device", "Acme"}} {
		if _, err := ledger.Enroll(row.id, row.tenant, "", time.Now().Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}
	mux := http.NewServeMux()
	registerAdminPKICertificates(mux, func() pkiCertificateInventory {
		return pkiCertificateInventory{Items: []pkiCertificateItem{
			{ID: "foreign-ca", Role: "device_issuing_ca", TenantID: "Acme"},
			{ID: "own-ca", Role: "device_issuing_ca", TenantID: "acme"},
			{ID: "shared-ca", Role: "transport_anchor", NotHolding: []string{"own-device", "foreign-device"}},
		}}
	}, ledger, func(_ string, handler http.HandlerFunc) http.HandlerFunc { return handler })
	req := httptest.NewRequest(http.MethodGet, "/admin/pki/certificates", nil)
	req = req.WithContext(context.WithValue(req.Context(), adminIdentityContextKey{}, adminIdentity{
		PrincipalID: "tenant-admin", TenantID: "acme", Roles: []string{"admin"}, AuthMethod: "admin_session",
	}))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("inventory HTTP %d", rec.Code)
	}
	var inv pkiCertificateInventory
	if err := json.Unmarshal(rec.Body.Bytes(), &inv); err != nil {
		t.Fatal(err)
	}
	got := map[string]pkiCertificateItem{}
	for _, item := range inv.Items {
		got[item.ID] = item
	}
	if _, leaked := got["foreign-ca"]; leaked {
		t.Fatal("case-distinct foreign tenant CA appeared in tenant inventory")
	}
	if _, own := got["own-ca"]; !own {
		t.Fatal("tenant's own CA was omitted")
	}
	shared, ok := got["shared-ca"]
	if !ok || len(shared.NotHolding) != 1 || shared.NotHolding[0] != "own-device" {
		t.Fatalf("shared CA must list only this tenant's devices as not holding it: %+v", shared.NotHolding)
	}
}
