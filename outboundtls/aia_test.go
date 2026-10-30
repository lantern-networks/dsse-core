package outboundtls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func testCertificate(t *testing.T, template, parent *x509.Certificate, signer *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if parent == nil {
		parent = template
		signer = key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func TestMissingIssuerCompletesOnlyToExistingRoot(t *testing.T) {
	now := time.Now()
	serial := int64(0)
	base := func(name string, ca bool) *x509.Certificate {
		serial++
		return &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true,
			IsCA: ca, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	}
	rootTemplate := base("trusted root", true)
	root, rootKey := testCertificate(t, rootTemplate, nil, nil)
	missingTemplate := base("missing intermediate", true)
	missing, missingKey := testCertificate(t, missingTemplate, root, rootKey)
	servedTemplate := base("served intermediate", true)
	servedTemplate.IssuingCertificateURL = []string{"http://ca.example.test/issuer.crt"}
	served, servedKey := testCertificate(t, servedTemplate, missing, missingKey)
	leafTemplate := base("partner.example.test", false)
	leafTemplate.DNSNames = []string{"partner.example.test"}
	leaf, _ := testCertificate(t, leafTemplate, served, servedKey)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	v := &verifier{roots: roots, cache: map[string]issuerEntry{}, fetch: func(context.Context, string) (*x509.Certificate, error) { return missing, nil }}
	state := tls.ConnectionState{ServerName: "partner.example.test", PeerCertificates: []*x509.Certificate{leaf, served}}
	if err := v.verifyConnection(state); err != nil {
		t.Fatalf("complete trusted chain: %v", err)
	}
	if got := v.cached(served.IssuingCertificateURL[0]); got == nil {
		t.Fatal("verified intermediate was not cached")
	}
	state.ServerName = "other.example.test"
	if err := v.verifyConnection(state); err == nil {
		t.Fatal("wrong hostname accepted")
	}
	v.roots = x509.NewCertPool()
	state.ServerName = "partner.example.test"
	if err := v.verifyConnection(state); err == nil {
		t.Fatal("fetched issuer became a root")
	}
	v.roots = roots
	expiredTemplate := base("expired.example.test", false)
	expiredTemplate.DNSNames = []string{"expired.example.test"}
	expiredTemplate.NotAfter = now.Add(-time.Minute)
	expired, _ := testCertificate(t, expiredTemplate, served, servedKey)
	state.ServerName = "expired.example.test"
	state.PeerCertificates[0] = expired
	if err := v.verifyConnection(state); err == nil {
		t.Fatal("expired leaf accepted")
	}
}

func TestNumericIPUsesOriginalStrictTransport(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer server.Close()
	base := http.DefaultTransport.(*http.Transport).Clone()
	wrapper := WrapRoundTripper(base)
	if wrapper == base {
		t.Fatal("DNS AIA wrapper was not installed")
	}
	if _, err := (&http.Client{Transport: wrapper}).Get(server.URL); err == nil {
		t.Fatal("untrusted numeric-IP certificate was accepted")
	}
}

func TestWrapperPreservesConnectorDialerAndStrictHostname(t *testing.T) {
	now := time.Now()
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(90), Subject: pkix.Name{CommonName: "test root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	root, rootKey := testCertificate(t, rootTemplate, nil, nil)
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(91), Subject: pkix.Name{CommonName: "route.example.test"},
		DNSNames: []string{"route.example.test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leaf, leafKey := testCertificate(t, leafTemplate, root, rootKey)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.Raw, root.Raw}, PrivateKey: leafKey}}}
	server.StartTLS()
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(root)
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.TLSClientConfig = &tls.Config{RootCAs: pool}
	base.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}
	response, err := (&http.Client{Transport: WrapRoundTripper(base)}).Get("https://route.example.test/")
	if err != nil {
		t.Fatalf("routed, verified request: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("status %d", response.StatusCode)
	}
	if _, err := (&http.Client{Transport: WrapRoundTripper(base)}).Get("https://wrong.example.test/"); err == nil {
		t.Fatal("wrong hostname accepted through connector dialer")
	}
}

func TestAIARejectsPrivateAndReservedAddresses(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "10.0.0.1", "169.254.1.1", "100.64.0.1", "198.18.0.1", "192.0.2.1", "203.0.113.1", "::1", "fc00::1", "2001:db8::1", "64:ff9b::a00:1"} {
		if publicIP(net.ParseIP(raw)) {
			t.Errorf("accepted %s", raw)
		}
	}
	for _, raw := range []string{"1.1.1.1", "2606:4700:4700::1111"} {
		if !publicIP(net.ParseIP(raw)) {
			t.Errorf("rejected %s", raw)
		}
	}
}

func TestAIARejectsUnsafeIssuerURLs(t *testing.T) {
	for _, raw := range []string{
		"http://127.0.0.1/issuer.crt", "http://169.254.169.254/latest/meta-data/",
		"http://192.0.2.1/issuer.crt", "http://1.1.1.1:8080/issuer.crt",
		"file:///etc/passwd", "http://user@1.1.1.1/issuer.crt",
		"http://1.1.1.1/issuer.crt#fragment",
	} {
		if _, err := fetchPublicIssuer(context.Background(), raw); err == nil {
			t.Errorf("accepted unsafe CA Issuers URL %s", raw)
		}
	}
}
