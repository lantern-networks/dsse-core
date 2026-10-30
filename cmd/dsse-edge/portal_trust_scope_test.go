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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/idpregistry"
	"github.com/lantern-networks/dsse-core/internalca"
)

func TestPortalPrivateCAIsNotUpstreamOrIdentityProviderTrust(t *testing.T) {
	dir := t.TempDir()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Portal only disposable CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	root := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"portal-a.example.test", "portal-b.example.test", "portal-c.example.test", "accounts.google.com", "login.microsoftonline.com"}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	for name, data := range map[string][]byte{"ca.pem": root, "leaf.pem": certPEM, "key.pem": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	origins := []string{"https://portal-a.example.test", "https://portal-b.example.test", "https://portal-c.example.test"}
	t.Cleanup(func() { stepUpPortalCert.Store(nil) })
	configureStepUpPortalCertificatesWithTrust(origins, filepath.Join(dir, "leaf.pem"), filepath.Join(dir, "key.pem"), filepath.Join(dir, "ca.pem"), true)
	for _, host := range leaf.DNSNames[:3] {
		if stepUpPortalCertificateFor(host) == nil || stepUpPortalCertificateRefusal(host) != nil {
			t.Fatalf("approved Portal not served: %s", host)
		}
	}
	if stepUpPortalCertificateFor("accounts.google.com") != nil {
		t.Fatal("Portal pair served at undeclared SNI")
	}
	parsed, _ := x509.ParseCertificate(der)
	system, err := x509.SystemCertPool()
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range leaf.DNSNames[3:] {
		if _, err := parsed.Verify(x509.VerifyOptions{DNSName: host, Roots: system}); err == nil {
			t.Fatal("Portal CA leaked into process-wide trust")
		}
	}
	// Exercise real local TLS using a public IdP name forged by the Portal CA.
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	defer server.Close()
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "accounts.google.com"}
	defer base.CloseIdleConnections()
	shared := &http.Client{Transport: base, Timeout: time.Second}
	idp, err := idpHTTPClient(shared, idpregistry.Connection{})
	if err != nil {
		t.Fatal(err)
	}
	if response, err := idp.Get(server.URL); err == nil {
		response.Body.Close()
		t.Fatal("public IdP trusted Portal CA")
	}
	// A tenant with unrelated internal anchors must not inherit Portal trust.
	_, otherCA := privateAsset(t)
	store, _ := internalca.NewStore(nil)
	if _, err := store.Upsert(internalca.Authority{ID: "other", TenantID: "tenant-a", CertificatePEM: otherCA}, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		transport := upstreamTransportTrustingTheOrganizationsPrivateAssets(base, store, tenant, time.Now())
		if response, err := (&http.Client{Transport: transport, Timeout: time.Second}).Get(server.URL); err == nil {
			response.Body.Close()
			t.Fatalf("tenant %s inherited Portal CA", tenant)
		}
	}
	for name, data := range map[string][]byte{"empty": nil, "junk": []byte("not PEM"), "leaf-as-ca": certPEM, "mixed": append(root, []byte("junk")...)} {
		path := filepath.Join(dir, name)
		os.WriteFile(path, data, 0600)
		configureStepUpPortalCertificatesWithTrust(origins, filepath.Join(dir, "leaf.pem"), filepath.Join(dir, "key.pem"), path, true)
		for _, host := range leaf.DNSNames[:3] {
			if stepUpPortalCertificateRefusal(host) == nil || stepUpPortalCertificateFor(host) != nil {
				t.Fatalf("bad CA %s fell back or served Portal", name)
			}
		}
	}
}
