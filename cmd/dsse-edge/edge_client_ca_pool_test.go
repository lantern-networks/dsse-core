package main

import (
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

// ★ A CONTROL PLANE TRUSTS TWO DIFFERENT SETS OF CLIENT CERTIFICATES (2026-08-12, thirteenth review): tenant
// devices, and the operator-issued identity an Edge ships audit records with. The second registration used to
// REPLACE the first, so a deployment configured with both rejected one of them at the TLS handshake — which
// reads as a TLS misconfiguration rather than the policy decision it is not.
func TestBothClientCASourcesSurvive(t *testing.T) {
	edgeClientCAsMu.Lock()
	edgeClientAnchors = nil
	edgeClientBaseAnchors = nil
	edgeClientRegistryAnchors = nil
	edgeClientCAs.Store(nil)
	edgeClientCAsMu.Unlock()

	operator := clientCAForTest(t, "operator")
	tenant := clientCAForTest(t, "tenant")

	if !addEdgeClientCAPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: operator.Raw})) {
		t.Fatalf("the operator anchors were rejected")
	}
	addEdgeClientCAs([]*x509.Certificate{tenant})

	pool := edgeClientCAPool()
	if pool == nil {
		t.Fatalf("no client CA pool after registering two sources")
	}
	subjects := 0
	for _, c := range []*x509.Certificate{operator, tenant} {
		if _, err := c.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			t.Fatalf("%s is not trusted after the second registration: %v — half this deployment's clients "+
				"cannot connect", c.Subject.CommonName, err)
		}
		subjects++
	}
	if subjects != 2 {
		t.Fatalf("checked %d anchors", subjects)
	}
}

func clientCAForTest(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
