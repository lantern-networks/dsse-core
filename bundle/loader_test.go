package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/signedconfig"
)

func TestValidateAcceptsActivePolicyBundle(t *testing.T) {
	b := testPolicyBundle()
	now := time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC)

	if err := Validate(b, now); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
}

func TestValidateRejectsExpiredPolicyBundle(t *testing.T) {
	b := testPolicyBundle()
	b.ExpiresAt = "2026-05-21T00:00:00Z"
	now := time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC)

	err := Validate(b, now)
	if err == nil {
		t.Fatal("Validate returned nil, want expiry error")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("error = %q, want expired", err.Error())
	}
}

func TestValidateRequiresPolicyIDs(t *testing.T) {
	b := testPolicyBundle()
	b.PolicyIDs = nil
	now := time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC)

	err := Validate(b, now)
	if err == nil {
		t.Fatal("Validate returned nil, want policy_ids error")
	}
	if !strings.Contains(err.Error(), "policy_ids") {
		t.Fatalf("error = %q, want policy_ids", err.Error())
	}
}

func TestValidateAcceptsCanonicalChecksum(t *testing.T) {
	b := testPolicyBundle()
	checksum, err := CanonicalChecksum(b)
	if err != nil {
		t.Fatalf("CanonicalChecksum returned error: %v", err)
	}
	b.Checksum = checksum

	if err := Validate(b, time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
}

func TestSignaturePayloadUsesCanonicalJSON(t *testing.T) {
	b := testPolicyBundle()
	b.Signature = ""
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	expected, err := signedconfig.CanonicalJSON(raw)
	if err != nil {
		t.Fatalf("CanonicalJSON returned error: %v", err)
	}
	payload, err := SignaturePayload(b)
	if err != nil {
		t.Fatalf("SignaturePayload returned error: %v", err)
	}
	if !bytes.Equal(payload, expected) {
		t.Fatalf("SignaturePayload = %s, want %s", string(payload), string(expected))
	}
}

func TestValidateRejectsChecksumMismatch(t *testing.T) {
	b := testPolicyBundle()
	b.Checksum = "sha256:bad"

	err := Validate(b, time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC))
	if err == nil {
		t.Fatal("Validate returned nil, want checksum mismatch")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("error = %q, want checksum mismatch", err.Error())
	}
}

func TestValidateAcceptsEd25519Signature(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	b := testPolicyBundle()
	b.SigningKeyID = signedconfig.SigningKeyIDPrefix + base64.RawURLEncoding.EncodeToString(publicKey)
	checksum, err := CanonicalChecksum(b)
	if err != nil {
		t.Fatalf("CanonicalChecksum returned error: %v", err)
	}
	b.Checksum = checksum
	payload, err := SignaturePayload(b)
	if err != nil {
		t.Fatalf("SignaturePayload returned error: %v", err)
	}
	b.Signature = signedconfig.SignaturePrefix + base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload))

	if err := Validate(b, time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
}

func TestValidateRejectsEd25519SignatureMismatch(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	b := testPolicyBundle()
	b.SigningKeyID = signedconfig.SigningKeyIDPrefix + base64.RawURLEncoding.EncodeToString(publicKey)
	checksum, err := CanonicalChecksum(b)
	if err != nil {
		t.Fatalf("CanonicalChecksum returned error: %v", err)
	}
	b.Checksum = checksum
	payload, err := SignaturePayload(b)
	if err != nil {
		t.Fatalf("SignaturePayload returned error: %v", err)
	}
	b.Signature = signedconfig.SignaturePrefix + base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	b.Version = "tampered"

	err = Validate(b, time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC))
	if err == nil {
		t.Fatal("Validate returned nil, want signature or checksum error")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") && !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("error = %q, want signature/checksum failure", err.Error())
	}
}

func TestValidateWithTrustedKeysAcceptsKeyID(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	b := testPolicyBundle()
	b.SigningKeyID = "lab-key-001"
	checksum, err := CanonicalChecksum(b)
	if err != nil {
		t.Fatalf("CanonicalChecksum returned error: %v", err)
	}
	b.Checksum = checksum
	payload, err := SignaturePayload(b)
	if err != nil {
		t.Fatalf("SignaturePayload returned error: %v", err)
	}
	b.Signature = signedconfig.SignaturePrefix + base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload))

	if err := ValidateWithTrustedKeys(b, time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC), map[string]ed25519.PublicKey{"lab-key-001": publicKey}); err != nil {
		t.Fatalf("ValidateWithTrustedKeys returned error: %v", err)
	}
}

// Review #6: an EMPTY keyring passed to the enforcing entrypoint used to fall through to the self-verifying
// lab path (the bundle's own embedded key) — a real-but-untrusted key then "verified". The enforcing path
// must instead refuse outright.
func TestValidateWithTrustedKeysRejectsEmptyKeyring(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	b := testPolicyBundle()
	// A well-formed self-signed bundle: signing_key_id embeds the (attacker's) public key.
	b.SigningKeyID = signedconfig.SigningKeyIDPrefix + base64.RawURLEncoding.EncodeToString(publicKey)
	checksum, err := CanonicalChecksum(b)
	if err != nil {
		t.Fatalf("CanonicalChecksum returned error: %v", err)
	}
	b.Checksum = checksum
	payload, err := SignaturePayload(b)
	if err != nil {
		t.Fatalf("SignaturePayload returned error: %v", err)
	}
	b.Signature = signedconfig.SignaturePrefix + base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload))

	now := time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC)
	if err := ValidateWithTrustedKeys(b, now, nil); err == nil {
		t.Fatal("nil keyring must be refused, not demoted to self-verification")
	}
	if err := ValidateWithTrustedKeys(b, now, map[string]ed25519.PublicKey{}); err == nil {
		t.Fatal("empty keyring must be refused, not demoted to self-verification")
	}
	// And with a real keyring that does NOT contain this signer, the self-signed bundle must be rejected.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := ValidateWithTrustedKeys(b, now, map[string]ed25519.PublicKey{"trusted-key-001": otherPub}); err == nil {
		t.Fatal("self-signed bundle with an untrusted signer must be rejected")
	}
}

func TestValidateWithTrustedKeysRejectsMockSignature(t *testing.T) {
	b := testPolicyBundle()
	err := ValidateWithTrustedKeys(b, time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC), map[string]ed25519.PublicKey{"lab-key-001": make(ed25519.PublicKey, ed25519.PublicKeySize)})
	if err == nil {
		t.Fatal("ValidateWithTrustedKeys returned nil, want mock signature error")
	}
	if !strings.Contains(err.Error(), "mock signature") {
		t.Fatalf("error = %q, want mock signature", err.Error())
	}
}

func testPolicyBundle() model.PolicyBundle {
	return model.PolicyBundle{
		ID:                  "pb_lab_20260522_001",
		TenantID:            "tenant_lab_001",
		Version:             "2026.05.22.001",
		PolicySchemaVersion: "2026.05.22",
		Checksum:            "sha256:mock-checksum",
		Signature:           "mock-signature",
		SigningKeyID:        "mock-local-signing-key",
		TargetScope: model.TargetScope{
			TargetType: "local_edge",
		},
		PolicyIDs:         []string{"pol_https_allow_001"},
		CompiledPolicyRef: "samples/phase1/policy_lab_https_allow.json",
		BundleType:        "standard",
		ExpiresAt:         "2030-01-01T00:00:00Z",
		CreatedAt:         "2026-05-22T00:00:00Z",
		Status:            "active",
	}
}
