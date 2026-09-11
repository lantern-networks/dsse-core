package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/tenantca"
)

// ★★ "VERIFIED" IS NOT "AN EDGE" (2026-08-22).
//
// POST /tenant-edge-material hands out an organization's transport, interception and device-identity PRIVATE
// KEYS. Its guard read: a shared bearer, plus any client certificate the listener accepted — and its refusal
// message said "this request presents no Edge certificate", a promise wider than what was enforced. The tenant
// the certificate resolves to was already computed and thrown away.
//
// In the reference deployment the listener's client CA pool holds only operator anchors, so a device could not
// reach it. That is the DEPLOYMENT closing it, not the code: point -audit-ingest-client-ca at a pool that
// includes tenant CAs — which is what a deployment terminating device mTLS on the same listener would do — and
// one enrolled laptop becomes every organization's issuing key.
func TestTenantEdgeMaterialRefusesACertificateIssuedByAnOrganization(t *testing.T) {
	const bearer = "material-route-probe-bearer"

	caCert, caPEM := materialRouteTestCA(t, "Northwind Device Issuing CA")
	registry := tenantca.NewTenantCARegistry()
	if _, err := registry.Register("tenant_northwind", caPEM); err != nil {
		t.Fatalf("register the organization's CA: %v", err)
	}

	authority := newTenantTransportAuthority(nil, nil, time.Now)
	mux := http.NewServeMux()
	registerTenantTransportMaterialRoute(mux, authority, nil, nil, bearer, time.Hour, registry, false)

	ask := func(chain []*x509.Certificate, cn string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/tenant-edge-material",
			strings.NewReader(`{"tenants":["tenant_northwind"]}`))
		req.Header.Set("authorization", "Bearer "+bearer)
		req.Header.Set("content-type", "application/json")
		leaf := &x509.Certificate{Subject: pkix.Name{CommonName: cn}}
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{leaf},
			VerifiedChains:   [][]*x509.Certificate{append([]*x509.Certificate{leaf}, chain...)},
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	// A device or connector of tenant_northwind, holding the bearer.
	rec := ask([]*x509.Certificate{caCert}, "laptop-of-northwind")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a certificate issued by an organization's own authority was handed signing material: "+
			"HTTP %d %s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "tenant_northwind") {
		t.Fatalf("the refusal does not name the organization whose certificate this is: %s", body)
	}

	// ★ THE CONTROL, AND IT IS THE WHOLE TEST. Without it this passes for a build that refuses every caller —
	// which would stop every Edge in the fleet from fetching material and look, from here, exactly like a
	// working gate. An Edge's certificate is operator-issued and resolves to NO organization.
	rec = ask(nil, "dsse-edge")
	if rec.Code == http.StatusForbidden {
		t.Fatalf("an Edge certificate was refused, so this gate stops the fleet: %s", rec.Body.String())
	}

	// ★ AND THE OTHER HALF STILL HOLDS: no certificate at all is still refused, outside lab mode.
	req := httptest.NewRequest(http.MethodPost, "/tenant-edge-material", strings.NewReader(`{}`))
	req.Header.Set("authorization", "Bearer "+bearer)
	bare := httptest.NewRecorder()
	mux.ServeHTTP(bare, req)
	if bare.Code != http.StatusForbidden {
		t.Fatalf("an unidentified caller was answered: HTTP %d %s", bare.Code, bare.Body.String())
	}
}

func materialRouteTestCA(t *testing.T, cn string) (*x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
