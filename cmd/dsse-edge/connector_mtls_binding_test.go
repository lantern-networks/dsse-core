package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"testing"
)

// reqWithClientCertCN builds an *http.Request as if it arrived over verified mTLS with the given leaf
// CommonName. An empty cn simulates a plaintext (no mTLS) request.
func reqWithClientCertCN(cn string) *http.Request {
	r, _ := http.NewRequest(http.MethodPost, "https://edge/connectors/c/heartbeat", nil)
	if cn == "" {
		return r
	}
	leaf := &x509.Certificate{Subject: pkix.Name{CommonName: cn}}
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains:   [][]*x509.Certificate{{leaf}},
	}
	return r
}

func TestConnectorMTLSIdentityBound(t *testing.T) {
	t.Run("matching cert CN is bound", func(t *testing.T) {
		bound, id, present := connectorMTLSIdentityBound(reqWithClientCertCN("conn_lab_001"), "conn_lab_001")
		if !present || !bound || id != "conn_lab_001" {
			t.Fatalf("expected bound match, got bound=%v id=%q present=%v", bound, id, present)
		}
	})

	t.Run("different connector cert is present but NOT bound (must reject)", func(t *testing.T) {
		bound, id, present := connectorMTLSIdentityBound(reqWithClientCertCN("conn_other_999"), "conn_lab_001")
		if !present {
			t.Fatal("expected present (mTLS cert was provided)")
		}
		if bound {
			t.Fatalf("expected NOT bound: cert %q must not authenticate as conn_lab_001", id)
		}
	})

	t.Run("device cert (wrong identity) present but not bound", func(t *testing.T) {
		bound, _, present := connectorMTLSIdentityBound(reqWithClientCertCN("Dsse Device Identity"), "conn_lab_001")
		if !present || bound {
			t.Fatalf("device cert must be present-but-unbound, got bound=%v present=%v", bound, present)
		}
	})

	t.Run("plaintext (no mTLS) is not present (caller keeps existing auth)", func(t *testing.T) {
		bound, _, present := connectorMTLSIdentityBound(reqWithClientCertCN(""), "conn_lab_001")
		if present || bound {
			t.Fatalf("plaintext request must be present=false, got bound=%v present=%v", bound, present)
		}
	})
}
