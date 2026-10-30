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
	"testing"
	"time"
)

func testIdentityForOrganization(t *testing.T, tenant string) ([]byte, *tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "same-device", Organization: []string{tenant}},
		NotBefore:    time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestRenewedIdentityOrganizationIsTenantExact(t *testing.T) {
	enrolledPEM, owner := testIdentityForOrganization(t, "Tenant_A")
	_, other := testIdentityForOrganization(t, "tenant_a")
	if !renewedIdentityBelongsToEnrollment(owner, enrolledPEM) {
		t.Fatal("same tenant's renewed identity rejected")
	}
	if renewedIdentityBelongsToEnrollment(other, enrolledPEM) {
		t.Fatal("case-distinct tenant's identity adopted")
	}
	if renewedIdentityBelongsToEnrollment(nil, enrolledPEM) {
		t.Fatal("missing renewed identity adopted")
	}
	if renewedIdentityBelongsToEnrollment(owner, []byte("not a certificate")) {
		t.Fatal("malformed enrollment identity accepted")
	}
	if !renewedIdentityBelongsToEnrollment(owner, nil) {
		t.Fatal("legacy file-based identity contract changed")
	}
}
