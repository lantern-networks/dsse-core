package agentpolicy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// The config-signing key cannot enter a PKCS#11 token as Ed25519 (no crypto11 binding supports it, checked
// through v1.7.0-rc1), so HSM custody requires ECDSA. The verifier must accept an ECDSA-P256 signature keyed
// by the ecdsa-p256-sha256 prefix, in addition to Ed25519 — additively, so the eventual switch is only
// "start signing ECDSA". These tests exercise the verify side end to end with a locally-held ECDSA key.
func ecdsaEnvelope(t *testing.T, key *ecdsa.PrivateKey, payload []byte) Envelope {
	t.Helper()
	sum := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return Envelope{
		Type:          EnvelopeType,
		Version:       "1",
		PayloadSHA256: hex.EncodeToString(sum[:]),
		PayloadB64:    base64.StdEncoding.EncodeToString(payload),
		Signature:     ECDSAP256SignaturePrefix + base64.RawURLEncoding.EncodeToString(sig),
	}
}

func ecdsaPubHex(key *ecdsa.PrivateKey) string {
	return hex.EncodeToString(elliptic.Marshal(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y))
}

func TestVerifyAcceptsECDSAP256AndRejectsMismatches(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	payload := []byte(`{"schema_version":"x"}`)
	env := ecdsaEnvelope(t, key, payload)
	pub := ecdsaPubHex(key)

	got, err := Verify(env, pub)
	if err != nil || string(got) != string(payload) {
		t.Fatalf("a valid ECDSA-P256 envelope must verify: got %q err %v", got, err)
	}

	// Wrong ECDSA key of the same shape: refused.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := Verify(env, ecdsaPubHex(other)); err == nil {
		t.Fatal("a different ECDSA key must not verify")
	}

	// An Ed25519 key against an ECDSA signature: refused for the shape mismatch, not silently tried.
	if _, err := Verify(env, hex.EncodeToString(make([]byte, 32))); err == nil {
		t.Fatal("an Ed25519 key must not verify an ECDSA signature")
	}

	// Tampered payload: checksum mismatch before any curve math.
	bad := env
	bad.PayloadB64 = base64.StdEncoding.EncodeToString([]byte(`{"schema_version":"y"}`))
	if _, err := Verify(bad, pub); err == nil {
		t.Fatal("a payload that does not match its checksum must be refused")
	}

	// An off-curve "public key" of the right length must be rejected, not accepted as a point.
	offCurve := "04" + hex.EncodeToString(make([]byte, 64))
	if _, err := Verify(env, offCurve); err == nil {
		t.Fatal("an off-curve point must not be accepted as an ECDSA key")
	}
}

// VerifyAny must treat an ECDSA key as a first-class member of the rotation set, and keep dropping malformed
// entries rather than trying or reporting them.
func TestVerifyAnyMixesEd25519AndECDSAKeys(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	payload := []byte(`{"schema_version":"z"}`)
	env := ecdsaEnvelope(t, key, payload)

	set := []string{
		hex.EncodeToString(make([]byte, 32)), // a (wrong) Ed25519 key — valid shape, tried, fails
		"garbage",                            // malformed — dropped
		ecdsaPubHex(key),                     // the ECDSA key that actually signed — accepted
	}
	if _, err := VerifyAny(env, set); err != nil {
		t.Fatalf("VerifyAny must accept when the ECDSA member verifies: %v", err)
	}
	// A set with only malformed/unusable-shape entries is "no keys", never a pass.
	if _, err := VerifyAny(env, []string{"garbage", "zz"}); err == nil {
		t.Fatal("a set with no usable key must be an error, not a pass")
	}
}

// The published keyring must carry an ECDSA next-key, not drop it — otherwise the token key could never be
// advertised for adoption and the switch could never begin.
func TestNormalisePolicyKeysAcceptsAnECDSANextKey(t *testing.T) {
	ed := hex.EncodeToString(make([]byte, 32)) // valid Ed25519 shape (the current key)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ec := ecdsaPubHex(key)
	got := normalisePolicyKeys(ed, []string{ec, "garbage"})
	if len(got) != 2 || got[0] != ed || got[1] != ec {
		t.Fatalf("keyring must be [own, ecdsa-next], malformed dropped: %v", got)
	}
}
