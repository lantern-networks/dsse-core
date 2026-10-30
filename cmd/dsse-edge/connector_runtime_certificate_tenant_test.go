package main

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tenantca"
)

func TestConnectorRuntimeSecretLookupUsesCertificateTenant(t *testing.T) {
	dir := t.TempDir()
	ca := makeTestCA(t, dir, "Connector tenant CA", 77)
	reg, err := tenantca.LoadTenantCARegistry(writeRegistry(t, dir, map[string]string{"tenant_customer": ca.pemPath}))
	if err != nil {
		t.Fatal(err)
	}
	chains := leafSignedBy(t, ca, "conn_lab_001", reg.Pool)
	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{ID: "conn_lab_001", TenantID: "tenant_customer", PrivateBaseURL: "https://private.example", Metadata: map[string]any{"runtime_secret_hash": connectorRuntimeSecretHash("current-secret")}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"old-secret", "current-secret"} {
		r := connectorRequestPresenting(chains)
		r.Header.Set(connectorSecretHeader, secret)
		w := httptest.NewRecorder()
		allowed := authorizeConnectorRuntimeRequest(w, r, "", registry, "conn_lab_001", "tenant_node", true, reg)
		if allowed != (secret == "current-secret") {
			t.Fatalf("secret %q accepted=%v status=%d", secret, allowed, w.Code)
		}
	}
}
