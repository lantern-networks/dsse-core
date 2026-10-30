package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestKeylessPublisherDoesNotInspectOptionalAuthorityKey(t *testing.T) {
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range issuerFiles {
		if err := os.WriteFile(filepath.Join(dir, file.cert), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	certs, files, err := loadIssuerCertificates(dir, filepath.Join(dir, "authority"), false)
	if err != nil || len(certs) != len(issuerFiles) || len(files) != len(issuerFiles) {
		t.Fatalf("keyless publication must load public certificates without authority access: %v", err)
	}
	if _, _, err := loadIssuerCertificates(dir, filepath.Join(dir, "authority"), true); err == nil {
		t.Fatal("signing mode accepted a missing optional Console authority key")
	}
}
