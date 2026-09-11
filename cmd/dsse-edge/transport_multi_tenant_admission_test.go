package main

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lantern-networks/dsse-core/tenantca"
)

// ★ ONE EDGE COULD ONLY EVER SERVE ONE TENANT (2026-08-15). Configuring a Tenant CA registry pinned the (T)
// listener to the node's own bundle tenant, so a second organization's device was refused at the handshake as
// cross-tenant — on the very Edge an MSSP would use to serve several customers. The mode that admits every
// registered tenant existed in the transport and was unreachable from configuration.
//
// These tests are about the DOWNSTREAM half, which is what makes multi-tenant admission safe: a decision must
// be keyed to the tenant the certificate proves, never to the node's own and never to what the body claims.
func TestTheAuthoritativeTenantComesFromTheCertificateNotTheBody(t *testing.T) {
	registry := &tenantca.TenantCARegistry{Pool: x509.NewCertPool()}
	caCert, caPEM := tenantCATestCA(t, "Northwind Device CA")
	if _, err := registry.Register("tenant_northwind", caPEM); err != nil {
		t.Fatalf("register: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/decide", nil)
	req.TLS = tlsStateChainingTo(caCert)

	// No claim: the certificate decides.
	got, err := authoritativeTenantForRequest(req, "", registry)
	if err != nil || got != "tenant_northwind" {
		t.Fatalf("resolved %q (err %v) — a device is keyed to the tenant whose CA signed it", got, err)
	}
	// A matching claim is fine.
	if got, err := authoritativeTenantForRequest(req, "tenant_northwind", registry); err != nil || got != "tenant_northwind" {
		t.Fatalf("matching claim: %q %v", got, err)
	}
	// A DIFFERENT claim is refused — this is the whole point of multi-tenant admission being safe.
	if _, err := authoritativeTenantForRequest(req, "tenant_reference_lab", registry); err == nil {
		t.Fatal("a body claiming another tenant than its certificate was accepted")
	}
}

// A certificate that chains to no registered Tenant CA resolves to no tenant, and the caller's existing value
// stands. That is the back-compatible path (plaintext listener, lab), and it must not silently become "the
// node's own tenant" — inventing an answer is how a device ends up enforced against the wrong customer.
func TestAnUnregisteredChainResolvesToNoTenantRatherThanTheNodesOwn(t *testing.T) {
	registry := &tenantca.TenantCARegistry{Pool: x509.NewCertPool()}
	if _, err := registry.Register("tenant_northwind", mustCAPEM(t, "Northwind Device CA")); err != nil {
		t.Fatalf("register: %v", err)
	}
	strangerCert, _ := tenantCATestCA(t, "Some Other CA")

	req := httptest.NewRequest(http.MethodPost, "/decide", nil)
	req.TLS = tlsStateChainingTo(strangerCert)

	got, err := authoritativeTenantForRequest(req, "", registry)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Fatalf("an unregistered chain resolved to %q — it must resolve to nothing", got)
	}
}

func mustCAPEM(t *testing.T, cn string) []byte {
	t.Helper()
	_, pemBytes := tenantCATestCA(t, cn)
	return pemBytes
}

// tlsStateChainingTo builds the verified-chain state a client presenting a certificate under this CA would
// produce at the (T) handshake.
func tlsStateChainingTo(ca *x509.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{
		HandshakeComplete: true,
		VerifiedChains:    [][]*x509.Certificate{{ca}},
	}
}
