package main

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ★★★ A STEERED FLOW BELONGS TO THE ORGANIZATION ITS DEVICE'S CERTIFICATE PROVES (2026-08-28, measured by
// putting a second organization on the lab and running one flow as one of its devices).
//
// The mux handler bound the device's IDENTITY from the moment it was written and never its ORGANIZATION: the
// decision request was seeded with this node's own tenant and nothing replaced it. Three things read that
// field — which authority signs the leaf the browser is shown, whose policy is applied, and whose flow the
// record says it was — so for every organization but the operator's, all three were wrong.
//
// Measured on the wire: a device of "Suzuran Foods", holding a certificate from Suzuran's own device CA and
// dialling Suzuran's own transport name, was served a leaf for example.com signed by the DEPLOYMENT's
// interception root while Suzuran's own issuing CA sat loaded on that same Edge.
func TestASteeredFlowIsKeyedToTheOrganizationTheCertificateProves(t *testing.T) {
	_, registry, _, _ := tenantCARoutesForTest(t)
	caCert, caPEM := tenantCATestCA(t, "Suzuran Device CA")
	if _, err := registry.Register("tenant_suzuran", caPEM); err != nil {
		t.Fatalf("register: %v", err)
	}

	withChain := httptest.NewRequest(http.MethodGet, "/", nil)
	withChain.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{caCert}}}

	if got := steerMuxFlowTenant(withChain, registry, "tenant_operator", "suzuran-walk-1"); got != "tenant_suzuran" {
		t.Fatalf("the flow was keyed to %q — the leaf its browser is shown would be signed by the wrong "+
			"authority, its own organization's policy would not apply, and the record would name somebody "+
			"else", got)
	}

	// ★ AN UNRESOLVED CHAIN KEEPS TODAY'S ANSWER. The /steer path denies this on a multi-tenant production
	// Edge; turning that on here in the same change would convert an attribution defect into an outage for
	// every device whose CA is not registered. It is the remaining half, and it is no longer silent.
	stranger, _ := tenantCATestCA(t, "Unregistered CA")
	unknown := httptest.NewRequest(http.MethodGet, "/", nil)
	unknown.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{stranger}}}
	if got := steerMuxFlowTenant(unknown, registry, "tenant_operator", "stranger-1"); got != "tenant_operator" {
		t.Fatalf("an unresolved chain changed behaviour: %q", got)
	}

	// No registry at all is a single-tenant Edge, and it is left exactly as it was.
	plain := httptest.NewRequest(http.MethodGet, "/", nil)
	if got := steerMuxFlowTenant(plain, nil, "tenant_operator", "no-tls"); got != "tenant_operator" {
		t.Fatalf("a single-tenant Edge changed behaviour: %q", got)
	}
}
