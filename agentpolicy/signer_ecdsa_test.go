package agentpolicy

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"
)

// The sign side, paired with the ECDSA verify already landed: an ECDSA-P256 signer (the shape an HSM token
// holds) must produce an envelope this package verifies, and the Ed25519 path must be unchanged. Wrapping a
// crypto.Signer is what lets the HSM key drop in later with nothing else in the signing path changing.
func TestSignerRoundTripsBothAlgorithms(t *testing.T) {
	payload := map[string]any{"schema_version": "x", "n": 1}

	// Ed25519 (the provisioned default), through the generalized signer.
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	edSigner, err := NewSignerFromCrypto(edPriv)
	if err != nil {
		t.Fatal(err)
	}
	edEnv, err := edSigner.Sign(payload, time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(edEnv, edSigner.PublicKeyHex()); err != nil {
		t.Fatalf("Ed25519 sign→verify must round-trip: %v", err)
	}

	// ECDSA-P256 (the token shape).
	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecSigner, err := NewSignerFromCrypto(ecPriv)
	if err != nil {
		t.Fatal(err)
	}
	if !ecSigner.isECDSA {
		t.Fatal("an ECDSA key must select the ECDSA path")
	}
	ecEnv, err := ecSigner.Sign(payload, time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if ecEnv.Signature[:len(ECDSAP256SignaturePrefix)] != ECDSAP256SignaturePrefix {
		t.Fatalf("ECDSA envelope must carry the ecdsa prefix, got %q", ecEnv.Signature)
	}
	if _, err := Verify(ecEnv, ecSigner.PublicKeyHex()); err != nil {
		t.Fatalf("ECDSA sign→verify must round-trip: %v", err)
	}
	// Cross-key must fail: the ed key must not verify the ecdsa envelope.
	if _, err := Verify(ecEnv, edSigner.PublicKeyHex()); err == nil {
		t.Fatal("the Ed25519 key must not verify an ECDSA envelope")
	}

	// The published key id and pubkey are stable and distinct per algorithm.
	if ecSigner.KeyID() == edSigner.KeyID() {
		t.Fatal("distinct keys must have distinct key ids")
	}
	if !isAcceptedPublicKeyHex(ecSigner.PublicKeyHex()) || !isAcceptedPublicKeyHex(edSigner.PublicKeyHex()) {
		t.Fatal("both published public keys must be accepted shapes for the keyring")
	}
}

// A non-P256 EC key is refused rather than silently signing under a curve verifiers do not check.
func TestNewSignerFromCryptoRejectsWrongCurve(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := NewSignerFromCrypto(k); err == nil {
		t.Fatal("a P-384 key must be refused — the verifiers only do P-256")
	}
}
