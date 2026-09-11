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
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ★★★ THE BROWSER GETS THE OPERATOR'S CERTIFICATE, AND ONLY AT THE PORTAL'S NAME (2026-09-02).
//
// The portal was served on the agent plane with the deployment's transport certificate, which a browser has
// no reason to trust — the only deployment root a steered device carries is its organization's interception
// root. The identity provider is not part of this product (it is the customer's Okta or Entra ID, publicly
// trusted), so the hop in between is a browser-facing page whose certificate is provided for it.
//
// The second half of this test is the one that matters: presenting the operator's certificate for ANY OTHER
// name would answer a device's tunnel handshake with a certificate its organization never anchored.
func TestTheStepUpPortalPresentsTheOperatorsCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "portal.crt"), filepath.Join(dir, "portal.key")
	writeSelfSignedFor(t, "stepup.example.test", certPath, keyPath)

	stepUpPortalCert.Store(nil)
	configureStepUpPortalCertificate("https://stepup.example.test/", certPath, keyPath)

	if got := stepUpPortalCertificateFor("stepup.example.test"); got == nil {
		t.Fatal("a browser asking for the portal's name was not given the operator's certificate")
	}
	// Case-insensitive, the way a client may send SNI.
	if got := stepUpPortalCertificateFor("StepUp.Example.Test"); got == nil {
		t.Error("the portal's name was not matched case-insensitively")
	}
	for _, other := range []string{"agents.example.test", "", "example.test", "stepup.example.test.evil"} {
		if got := stepUpPortalCertificateFor(other); got != nil {
			t.Errorf("%q was answered with the portal's certificate — a device's tunnel handshake would be "+
				"answered with a certificate its organization never anchored", other)
		}
	}

	// ★ AND A BAD PAIR DOES NOT TAKE THE NODE DOWN. A portal on the wrong certificate is a browser warning;
	// a node that refuses to start takes a region's enforcement with it.
	stepUpPortalCert.Store(nil)
	configureStepUpPortalCertificate("https://stepup.example.test/", filepath.Join(dir, "absent.crt"), keyPath)
	if got := stepUpPortalCertificateFor("stepup.example.test"); got != nil {
		t.Error("a certificate that could not be loaded was served anyway")
	}

	// No base URL means no name to present it for.
	stepUpPortalCert.Store(nil)
	configureStepUpPortalCertificate("", certPath, keyPath)
	if stepUpPortalCert.Load() != nil {
		t.Error("a certificate was bound with no portal name to bind it to")
	}
	stepUpPortalCert.Store(nil)
}

func writeSelfSignedFor(t *testing.T, host, certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatal(err)
	}
	var _ tls.Certificate
}
