package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// managedApplicationTestTLS gives an application request the same two proofs
// supplied by a connected endpoint: a verified client certificate and an
// enrolled device record. A certificate alone must not assert managed status.
func managedApplicationTestTLS(t *testing.T, handler http.Handler, tenantID, deviceID string) *tls.ConnectionState {
	t.Helper()
	registration, err := json.Marshal(struct {
		ID       string `json:"id"`
		TenantID string `json:"tenant_id"`
	}{ID: deviceID, TenantID: tenantID})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/devices/register", strings.NewReader(string(registration)))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register managed application device status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	ca := makeTestCA(t, t.TempDir(), "managed-application-device", 199)
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	chains := leafSignedBy(t, ca, deviceID, pool)
	if len(chains) == 0 {
		t.Fatal("managed application device certificate did not verify")
	}
	return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{chains[0][0]}, VerifiedChains: chains}
}
