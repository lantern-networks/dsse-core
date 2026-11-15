package inspectioncrl

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func sealedTestRoot(t *testing.T, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "sealed test root"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(5 * 365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func TestASealedListMayOutlastTheOrdinaryBoundAndMayRevokeNothing(t *testing.T) {
	now := time.Now()
	root, key := sealedTestRoot(t, now)
	until := now.Add(2 * 365 * 24 * time.Hour)
	sealed, err := SignSealed(root, key, now, until)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseAndValidateSealed(sealed, root, now.Add(400*24*time.Hour)); err != nil {
		t.Fatalf("a sealed list is refused a year into its life: %v", err)
	}
	if _, err := ParseAndValidate(sealed, root, now); err == nil {
		t.Fatal("the ordinary rule accepted a two-year list")
	}
	if _, err := ParseAndValidateSealed(sealed, root, until.Add(time.Minute)); err == nil {
		t.Fatal("a sealed list was accepted after its end")
	}
	// A list of the same length that revokes something is not a sealed list.
	revoking, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now, NextUpdate: until,
		RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: big.NewInt(99), RevocationTime: now}}}, root, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseAndValidateSealed(revoking, root, now); err == nil {
		t.Fatal("a long-lived list that revokes a certificate was accepted as sealed")
	}
	if _, err := SignSealed(root, key, now, root.NotAfter.Add(time.Hour)); err == nil {
		t.Fatal("a sealed list was signed past its issuer's own end")
	}
}
