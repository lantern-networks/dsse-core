package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

// ★★ THE CUSTOMER-FACING DOOR REJECTED THE DEFAULT OUTPUT OF THE TOOL A CUSTOMER USES (2026-08-21, hit while
// moving an organization's interception authority onto the control plane).
//
// POST /admin/tenant-interception-authority exists so an organization can hand over an issuing CA it signed
// under its OWN root — the whole customer-holds-the-root design goes through it. It read the key with
// x509.ParseECPrivateKey alone, which understands SEC1 only, and a key from any current OpenSSL is PKCS#8.
// The refusal quoted a Go function name at the customer.
func TestAnIssuingKeyIsAcceptedInEitherEncoding(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	sec1, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("sec1: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("pkcs8: %v", err)
	}

	for _, tc := range []struct {
		name  string
		block *pem.Block
	}{
		{"SEC1 (BEGIN EC PRIVATE KEY)", &pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}},
		{"PKCS#8 (BEGIN PRIVATE KEY)", &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}},
	} {
		got, err := parseECKeyPEM(pem.EncodeToMemory(tc.block))
		if err != nil {
			t.Fatalf("%s was refused: %v — this is the encoding a customer's own openssl produces", tc.name, err)
		}
		if !got.PublicKey.Equal(&key.PublicKey) {
			t.Fatalf("%s parsed to a different key", tc.name)
		}
	}

	// ★ AND A FILE THAT LEADS WITH EC PARAMETERS (2026-08-21, hit while running the migration this route
	// exists for). `openssl ecparam -genkey` writes two blocks, parameters first — one of the most common ways
	// a customer makes an EC key, and reading only the first block reported their perfectly good key as
	// malformed ASN.1.
	params := pem.EncodeToMemory(&pem.Block{Type: "EC PARAMETERS", Bytes: []byte{0x06, 0x08, 0x2a, 0x86, 0x48,
		0xce, 0x3d, 0x03, 0x01, 0x07}})
	twoBlocks := append(params, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1})...)
	got, err := parseECKeyPEM(twoBlocks)
	if err != nil {
		t.Fatalf("a key file that leads with EC PARAMETERS was refused: %v — that is what openssl ecparam "+
			"-genkey writes", err)
	}
	if !got.PublicKey.Equal(&key.PublicKey) {
		t.Fatal("the two-block file parsed to a different key")
	}
	if _, err := parseECKeyPEM(params); err == nil {
		t.Fatal("a PEM containing ONLY EC PARAMETERS was accepted as a key")
	} else if !strings.Contains(err.Error(), "EC PARAMETERS") {
		t.Fatalf("the refusal does not tell the reader what they actually sent: %v", err)
	}

	// ★ AND THE REFUSALS STAY REFUSALS, in the reader's terms rather than Go's.
	if _, err := parseECKeyPEM([]byte("not a pem")); err == nil {
		t.Fatal("a body that is not PEM was accepted as a key")
	}
	rsaLike, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := parseECKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaLike[:len(rsaLike)/2]})); err == nil {
		t.Fatal("a truncated key was accepted")
	} else if strings.Contains(err.Error(), "ParsePKCS8PrivateKey instead") {
		t.Fatalf("the refusal still quotes a Go function at the reader: %v", err)
	}
}
