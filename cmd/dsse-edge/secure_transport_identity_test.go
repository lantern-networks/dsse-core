package main

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

func labLeafCert(t *testing.T) *x509.Certificate {
	t.Helper()
	cert, _, err := generateSelfSignedTransportCert([]string{"localhost"})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return leaf
}

func TestEnrichDecisionRequestWithTransportIdentity(t *testing.T) {
	leaf := labLeafCert(t)

	// Plaintext request (no TLS) -> no-op, not verified.
	if got := enrichDecisionRequestWithTransportIdentity(&http.Request{}, model.DecisionRequest{}); got.TransportClientCertVerified {
		t.Fatalf("plaintext request must not be marked verified")
	}

	// Verified client cert chain -> verified + identity bound from CN.
	verified := &http.Request{TLS: &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains:   [][]*x509.Certificate{{leaf}},
	}}
	got := enrichDecisionRequestWithTransportIdentity(verified, model.DecisionRequest{})
	if !got.TransportClientCertVerified {
		t.Fatalf("verified mTLS chain should mark the request verified")
	}
	if got.TransportDeviceIdentity != leaf.Subject.CommonName || got.TransportDeviceIdentity == "" {
		t.Fatalf("device identity should be the cert CN, got %q (cn=%q)", got.TransportDeviceIdentity, leaf.Subject.CommonName)
	}

	// Presented but UNVERIFIED chain -> must NOT be trusted (zero-trust: only verified chains count).
	presentedOnly := &http.Request{TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}}
	if enrichDecisionRequestWithTransportIdentity(presentedOnly, model.DecisionRequest{}).TransportClientCertVerified {
		t.Fatalf("an unverified client cert chain must not be trusted")
	}

	// Already-set field is not overwritten.
	pre := model.DecisionRequest{TransportClientCertVerified: true, TransportDeviceIdentity: "preset"}
	if got := enrichDecisionRequestWithTransportIdentity(verified, pre); got.TransportDeviceIdentity != "preset" {
		t.Fatalf("must not overwrite an already-bound transport identity, got %q", got.TransportDeviceIdentity)
	}
}
