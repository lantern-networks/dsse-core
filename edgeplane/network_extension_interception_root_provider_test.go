package edgeplane

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// testECDSARootProvider is a non-file interception root provider whose signing key is ECDSA (NOT the file
// provider's RSA). It stands in for an HSM / sealed-key provider to prove the seam: the engine mints leaves
// through whatever crypto.Signer the provider supplies, making no assumption about the key TYPE or WHERE it
// lives. If this passes with an ECDSA root, a PKCS#11/HSM signer (key never leaves hardware) drops in the same way.
type testECDSARootProvider struct {
	cert    *x509.Certificate
	certPEM []byte
	key     *ecdsa.PrivateKey
}

func (p *testECDSARootProvider) Certificate() *x509.Certificate { return p.cert }
func (p *testECDSARootProvider) CertPEM() []byte                { return p.certPEM }
func (p *testECDSARootProvider) Signer() crypto.Signer          { return p.key }

func newTestECDSARootProvider(t *testing.T, now time.Time) *testECDSARootProvider {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa root key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test HSM-style Interception Root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create ecdsa root cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ecdsa root cert: %v", err)
	}
	return &testECDSARootProvider{
		cert:    cert,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		key:     key,
	}
}

// TestInterceptionRootProviderSeamMintsLeafFromInjectedSigner proves the HSM/sealed-key seam: an interception
// engine built with an INJECTED provider (here ECDSA-rooted, standing in for an HSM) mints a per-SNI leaf signed
// by that provider's signer, and the leaf chains to the injected root — with NO change to the minting/serving path.
func TestInterceptionRootProviderSeamMintsLeafFromInjectedSigner(t *testing.T) {
	now := time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC)
	provider := newTestECDSARootProvider(t, now)

	interception, err := NewNetworkExtensionLabTLSInterceptionWithProvider([]string{"example.com"}, func() time.Time { return now }, provider)
	if err != nil {
		t.Fatalf("WithProvider: %v", err)
	}
	if interception == nil {
		t.Fatal("interception is nil")
	}

	// The engine surfaces the INJECTED provider's root, not a self-generated one.
	if string(interception.RootCertificatePEM()) != string(provider.CertPEM()) {
		t.Fatal("engine did not adopt the injected provider's root certificate")
	}

	leaf, err := interception.leafCertificate("", "example.com")
	if err != nil {
		t.Fatalf("leafCertificate: %v", err)
	}
	leafX509, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	// The leaf must verify against the INJECTED (ECDSA) root — i.e. the provider's signer actually signed it.
	roots := x509.NewCertPool()
	roots.AddCert(provider.Certificate())
	if _, err := leafX509.Verify(x509.VerifyOptions{
		Roots:       roots,
		DNSName:     "example.com",
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("leaf does not chain to the injected root (seam broken): %v", err)
	}
	// And specifically signed BY the ECDSA root (the signer is abstract, not RSA-bound).
	if err := leafX509.CheckSignatureFrom(provider.Certificate()); err != nil {
		t.Fatalf("leaf signature is not from the injected ECDSA root: %v", err)
	}
}

// TestInterceptionRootProviderRejectsIncompleteProvider guards the injection point against a half-built provider
// (nil cert/signer) rather than panicking later at leaf-minting time.
func TestInterceptionRootProviderRejectsIncompleteProvider(t *testing.T) {
	if _, err := NewNetworkExtensionLabTLSInterceptionWithProvider([]string{"example.com"}, time.Now, &testECDSARootProvider{}); err == nil {
		t.Fatal("expected an error for a provider with a nil certificate, got nil")
	}
}
