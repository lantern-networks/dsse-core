package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// ★★★ AN ISSUING AUTHORITY THAT CANNOT HAVE A CA BENEATH IT WAS ACCEPTED, AND THE CHAIN IT PRODUCED WAS
// INVALID (2026-08-21, measured on the reference deployment).
//
// The control plane does not hand an Edge the authority a customer gave it. It mints a SHORT-LIVED, PER-NODE
// certificate authority underneath and hands THAT out — which is the whole reason the long-lived key can stay
// in one place instead of living on every node that comes and goes. That per-node tier is a CA, so the
// authority above it needs room for one.
//
// A carefully issued issuing CA carries pathLenConstraint:0 — "nothing below me may be a CA" — and the
// reference deployment's did. The import was accepted, the tier was minted, and the result was a chain openssl
// rejects with "path length constraint exceeded": git stopped being able to reach github from an intercepted
// machine. Chrome accepted the same chain, which is precisely why this must be caught at the door.
func TestAnIssuingAuthorityWithNoRoomForATierIsRefused(t *testing.T) {
	now := time.Now().UTC()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("root key: %v", err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Customer Interception Root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(10, 0, 0),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, IsCA: true, BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	root, _ := x509.ParseCertificate(rootDER)

	issue := func(maxPathLen int, zero bool) (string, string) {
		key, kerr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if kerr != nil {
			t.Fatalf("issuing key: %v", kerr)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Customer Issuing CA"},
			NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(2, 0, 0),
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, IsCA: true, BasicConstraintsValid: true,
			MaxPathLen: maxPathLen, MaxPathLenZero: zero,
		}
		der, cerr := x509.CreateCertificate(rand.Reader, tmpl, root, &key.PublicKey, rootKey)
		if cerr != nil {
			t.Fatalf("issuing: %v", cerr)
		}
		keyDER, _ := x509.MarshalECPrivateKey(key)
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
			string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	}
	rootPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}))

	authority := newTenantInterceptionAuthority(nil, func([]byte) error { return nil }, func() time.Time { return now })

	// pathLenConstraint:0 — the careful way to issue one, and the one that produces an invalid chain here.
	certPEM, keyPEM := issue(0, true)
	_, err = authority.Import("tenant_probe", rootPEM, certPEM, keyPEM)
	if err == nil {
		t.Fatal("★ an issuing authority marked pathLenConstraint:0 was accepted. The per-node tier minted " +
			"beneath it makes a chain that openssl rejects with \"path length constraint exceeded\" — and a " +
			"browser accepts, so the first report comes from somebody's command line, not from here.")
	}
	if !strings.Contains(err.Error(), "pathLenConstraint") || !strings.Contains(err.Error(), "same root") {
		t.Fatalf("the refusal does not tell the customer what to send instead: %v", err)
	}

	// ★ THE CONTROL: one with room IS accepted, or this gate is just refusing everything.
	certPEM, keyPEM = issue(1, false)
	if _, err := authority.Import("tenant_probe", rootPEM, certPEM, keyPEM); err != nil {
		t.Fatalf("an issuing authority that permits a tier beneath it was refused: %v", err)
	}
}
