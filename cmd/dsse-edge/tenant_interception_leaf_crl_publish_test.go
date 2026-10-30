package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/inspectioncrl"
)

func TestEdgePublishesSignedLeafCRLBeforeAcknowledgingReadiness(t *testing.T) {
	a, root, _, issuing, _, _, fail := crlRouteFixture(t)
	mat, err := a.IssueFor("tenant_customer", "edge-a", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	issuer := parseAllCerts([]byte(mat.ChainPEM))[0]
	engine, err := edgeplane.NewNetworkExtensionLabTLSInterception([]string{"*"}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = engine.LoadOfflineTenantIntermediate(mat.TenantID, []byte(mat.RootPEM), []byte(mat.ChainPEM), []byte(mat.KeyPEM)); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerTenantInspectionCRLRoute(mux, a, "bearer", nil)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity := &x509.Certificate{Subject: pkix.Name{CommonName: "edge-a"}}
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{identity}, VerifiedChains: [][]*x509.Certificate{{identity}}}
		mux.ServeHTTP(w, r)
	}))
	defer server.Close()
	f := newTenantTransportMaterialFetcher(server.URL, "bearer", nil, nil)
	f.dataURL = nil
	f.client = server.Client()
	if err = f.publishTenantLeafCRL(engine, "tenant_customer"); err != nil {
		t.Fatal(err)
	}
	status, err := a.crlStatus(context.Background(), "tenant_customer", inspectioncrl.Fingerprint(issuer))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = inspectioncrl.ParseAndValidate(status.DER, issuer, time.Now()); err != nil {
		t.Fatal(err)
	}
	rootStatus, err := a.crlStatus(context.Background(), "tenant_customer", inspectioncrl.Fingerprint(root))
	if err != nil {
		t.Fatal(err)
	}
	issuingStatus, err := a.crlStatus(context.Background(), "tenant_customer", inspectioncrl.Fingerprint(issuing))
	if err != nil {
		t.Fatal(err)
	}
	key, err := parseECKeyPEM([]byte(mat.KeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(91), Subject: pkix.Name{CommonName: "example.com"},
		DNSNames: []string{"example.com"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(10 * time.Minute),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, issuer, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	chain := []*x509.Certificate{leaf, issuer, issuing, root}
	lists := map[string][]byte{inspectioncrl.Fingerprint(issuer): status.DER,
		inspectioncrl.Fingerprint(issuing): issuingStatus.DER, inspectioncrl.Fingerprint(root): rootStatus.DER}
	if err := inspectioncrl.CheckChain(chain, lists, now); err != nil {
		t.Fatalf("complete signed status did not validate: %v", err)
	}
	delete(lists, inspectioncrl.Fingerprint(issuing))
	if err := inspectioncrl.CheckChain(chain, lists, now); err == nil {
		t.Fatal("missing issuing status was accepted")
	}
	*fail = true
	if err = f.publishTenantLeafCRL(engine, "tenant_customer"); err == nil {
		t.Fatal("failed durable publication was acknowledged")
	}
}
