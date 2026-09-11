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

// ★★★ THE IDENTITY THIS NODE PRESENTS TO THE CONTROL PLANE IS READ AT HANDSHAKE TIME (2026-08-20).
//
// Found by running on this side the sweep the Windows side ran on their own TLS configs: they had a health
// probe judging whether a region was reachable using the anchors the process started with and the certificate
// it was provisioned with, while every real dial used the adopted ones. Their failure mode was not "the probe
// fails" but "the probe is confidently wrong about a region", and failover decides on that.
//
// The same shape here is the certificate this node presents to the control plane. It is what every audit record
// is bound to, and it is what fetches per-organization material — so a rotation rides on it. Loaded once,
// replacing the file needs a restart and its expiry is a scheduled outage of the whole channel.
func TestTheControlPlaneIdentityIsRereadRatherThanCaptured(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "edge.crt"), filepath.Join(dir, "edge.key")
	caPath := filepath.Join(dir, "ca.pem")
	writeIdentity(t, certPath, keyPath, "edge-before")
	writeIdentity(t, caPath, filepath.Join(dir, "ca.key"), "anchor")

	cfg, err := auditShipTLSConfig(caPath, certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GetClientCertificate == nil {
		t.Fatal("the identity is captured in Certificates rather than read per handshake — replacing the file " +
			"then needs a restart, and its expiry takes the whole control-plane channel with it")
	}

	// Replace the file, as an operator rotating this node's identity would.
	writeIdentity(t, certPath, keyPath, "edge-after")
	got, err := cfg.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(got.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "edge-after" {
		t.Fatalf("the handshake still presents %q — the replacement on disk was not picked up",
			leaf.Subject.CommonName)
	}

	// A half-written file during a replacement must not take the channel down: the last good one is presented.
	if err := os.WriteFile(certPath, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.GetClientCertificate(&tls.CertificateRequestInfo{}); err != nil {
		t.Fatalf("an unreadable file took the channel down instead of keeping the working identity: %v", err)
	}
}

func writeIdentity(t *testing.T, certPath, keyPath, cn string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(240 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}
