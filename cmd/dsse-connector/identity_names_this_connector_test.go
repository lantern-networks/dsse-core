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

func writeCertNamed(t *testing.T, dir, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "connector.crt")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// ★★★ A CERTIFICATE FOR A NAME THIS CONNECTOR NO LONGER USES IS REFUSED BY EVERY EDGE, SILENTLY (2026-08-26,
// measured on the lab: the connector was conn-80f88e327f37 and its certificate said conn-c5e3b2026b47, so the
// whole fleet turned it away for hours with a message about the certificate not being bound to the connector
// id — which reads as an Edge-side problem and is not).
func TestTheIdentityCertificateHasToNameThisConnector(t *testing.T) {
	dir := t.TempDir()
	path := writeCertNamed(t, dir, "conn-abc")

	if named, err := connectorIdentityCertNames(path, "conn-abc"); err != nil || !named {
		t.Fatalf("a certificate for this connector was not recognised: named=%v err=%v", named, err)
	}
	if named, err := connectorIdentityCertNames(path, "conn-xyz"); err != nil || named {
		t.Fatalf("a certificate for ANOTHER name was accepted: named=%v err=%v", named, err)
	}
}

// ★ AND STARTING WITH THE WRONG ONE AND NO WAY TO REPLACE IT IS A REFUSAL, NOT A DEGRADED MODE. The
// certificate is the whole of a connector's authentication to the fleet.
func TestAConnectorWithSomebodyElsesCertificateRefusesToStart(t *testing.T) {
	dir := t.TempDir()
	writeCertNamed(t, dir, "conn-old")
	if err := os.WriteFile(filepath.Join(dir, "connector.key"), []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	var certPath, keyPath string
	_, err := ensureConnectorIdentity(t.Context(), dir,
		connectorState{ConnectorID: "conn-new", TenantID: "tenant_a"}, "", &certPath, &keyPath)
	if err == nil {
		t.Fatalf("a connector started with a certificate issued for another name")
	}
	if got := err.Error(); got == "" {
		t.Fatalf("the refusal says nothing")
	}
}
