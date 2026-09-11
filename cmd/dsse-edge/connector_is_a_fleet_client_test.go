package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"testing"
)

// requestFromConnector builds a request carrying a VERIFIED client certificate naming a connector, the way
// the transport hands one to these handlers.
func requestFromConnector(t *testing.T, certCN string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/connectors/x/heartbeat", nil)
	leaf := &x509.Certificate{Subject: pkix.Name{CommonName: certCN}}
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains:   [][]*x509.Certificate{{leaf}},
	}
	return r
}

// ★★★ A CONNECTOR CONNECTS TO THE FLEET, NOT TO ONE EDGE (the operator's decision, 2026-08-26). A region has
// more than one Edge by default and the front door alternates between them, so half of a connector's requests
// landed on an Edge it had never registered with — and were refused for ever.
func TestACertificateAuthenticatesAConnectorOnAnyEdge(t *testing.T) {
	// This Edge has never heard of the connector: no registry entry, no runtime secret.
	w := httptest.NewRecorder()
	r := requestFromConnector(t, "conn-abc")
	if !authorizeConnectorRuntimeRequest(w, r, "fleet-shared-secret", nil, "conn-abc", "tenant_a", true, nil) {
		t.Fatalf("an Edge that has never met this connector refused its certificate: %d %s", w.Code, w.Body.String())
	}

	// The guard: a certificate naming a DIFFERENT connector must not pass, or the check above says nothing.
	w2 := httptest.NewRecorder()
	r2 := requestFromConnector(t, "conn-somebody-else")
	if authorizeConnectorRuntimeRequest(w2, r2, "fleet-shared-secret", nil, "conn-abc", "tenant_a", true, nil) {
		t.Fatalf("a certificate naming another connector was accepted for conn-abc")
	}

	// And presenting nothing is still refused — the fleet identity widens nothing.
	w3 := httptest.NewRecorder()
	r3 := httptest.NewRequest(http.MethodPost, "/connectors/x/heartbeat", nil)
	if authorizeConnectorRuntimeRequest(w3, r3, "fleet-shared-secret", nil, "conn-abc", "tenant_a", true, nil) {
		t.Fatalf("a caller presenting no certificate was accepted")
	}
}

// Registering is part of connecting to the fleet: a connector that has just failed over to another Edge is
// unknown there, and that is the ordinary state, not a refusal.
func TestAConnectorMayRegisterWithAnEdgeThatHasNeverMetIt(t *testing.T) {
	w := httptest.NewRecorder()
	r := requestFromConnector(t, "conn-abc")
	if !authorizeConnectorRegistrationRequest(w, r, "fleet-shared-secret", nil, "conn-abc", "tenant_a", nil) {
		t.Fatalf("registration was refused on an Edge that has never met the connector: %d %s", w.Code, w.Body.String())
	}
	w2 := httptest.NewRecorder()
	r2 := requestFromConnector(t, "conn-somebody-else")
	if authorizeConnectorRegistrationRequest(w2, r2, "fleet-shared-secret", nil, "conn-abc", "tenant_a", nil) {
		t.Fatalf("a certificate naming another connector was allowed to register as conn-abc")
	}
}
