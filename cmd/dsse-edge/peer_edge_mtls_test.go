package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeTestCertPair emits a self-signed cert+key to temp files and returns (certPath, keyPath).
func writeTestCertPair(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: "edge-peer"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "edge.crt")
	keyPath := filepath.Join(dir, "edge.key")
	keyDER, _ := x509.MarshalECPrivateKey(key)
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// TestMeshPeerTLSConfigPinnedCAOverridesSkipVerify proves a pinned peer CA forces verification even when
// skip-verify was requested — the hardened path can't be accidentally left insecure.
func TestMeshPeerTLSConfigPinnedCAOverridesSkipVerify(t *testing.T) {
	certPath, keyPath := writeTestCertPair(t)
	cfg, err := buildMeshPeerTLSConfig(certPath, keyPath, certPath /*the self-signed cert is its own CA*/, true /*skip-verify requested*/)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if cfg.InsecureSkipVerify {
		t.Fatal("a pinned peer CA must force verification (InsecureSkipVerify=false), even when skip-verify was requested")
	}
	if cfg.RootCAs == nil {
		t.Fatal("pinned CA must populate RootCAs")
	}
	if len(cfg.Certificates) != 1 {
		t.Fatal("client cert must be presented for mTLS")
	}
}

// TestMeshPeerTLSConfigClientCertRequiresBoth guards the client-identity contract.
func TestMeshPeerTLSConfigClientCertRequiresBoth(t *testing.T) {
	certPath, _ := writeTestCertPair(t)
	if _, err := buildMeshPeerTLSConfig(certPath, "", "", false); err == nil {
		t.Fatal("client cert without key must error")
	}
}

// TestMeshPeerTLSConfigLabSkipVerify confirms the lab fallback: no cert, no CA, skip-verify honored.
func TestMeshPeerTLSConfigLabSkipVerify(t *testing.T) {
	cfg, err := buildMeshPeerTLSConfig("", "", "", true)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !cfg.InsecureSkipVerify {
		t.Fatal("lab fallback (no CA) should honor skip-verify")
	}
	if cfg.RootCAs != nil || len(cfg.Certificates) != 0 {
		t.Fatal("lab fallback should set neither RootCAs nor client certs")
	}
}
