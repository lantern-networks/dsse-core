package bundle

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/signedconfig"
)

const (
	MockChecksum     = "sha256:mock-checksum"
	MockSignature    = "mock-signature"
	MockSigningKeyID = "mock-local-signing-key"
)

// Load is the LAB loader: it accepts the Mock* sentinels and, for a real signature, derives the
// verification key from the bundle's OWN signing_key_id — the bundle vouches for itself, which proves
// integrity (the signed bytes match the embedded key) but NOT authenticity (anyone can sign with their own
// key and embed its public half). An enforcing deployment must use LoadWithTrustedKeys so the signer is
// checked against an out-of-band keyring; callers that stay on Load should say so loudly (log) at startup.
func Load(path string) (model.PolicyBundle, error) {
	return load(path, nil, true)
}

// LoadWithTrustedKeys is the ENFORCING loader: the signing key must be in the supplied keyring (which must
// be non-empty) and the lab Mock* sentinels are rejected.
func LoadWithTrustedKeys(path string, trustedKeys map[string]ed25519.PublicKey) (model.PolicyBundle, error) {
	return load(path, trustedKeys, false)
}

func load(path string, trustedKeys map[string]ed25519.PublicKey, allowLabMock bool) (model.PolicyBundle, error) {
	var b model.PolicyBundle

	data, err := os.ReadFile(path)
	if err != nil {
		return b, fmt.Errorf("read policy bundle: %w", err)
	}
	if err := json.Unmarshal(data, &b); err != nil {
		return b, fmt.Errorf("parse policy bundle: %w", err)
	}
	if err := validate(b, time.Now().UTC(), trustedKeys, allowLabMock); err != nil {
		return b, err
	}

	return b, nil
}

// Validate is the LAB validation path — see Load for what that trusts (and does not).
func Validate(b model.PolicyBundle, now time.Time) error {
	return validate(b, now, nil, true)
}

func ValidateWithTrustedKeys(b model.PolicyBundle, now time.Time, trustedKeys map[string]ed25519.PublicKey) error {
	// An EMPTY keyring must not silently demote this to the self-verifying lab path (publicKeyForBundle
	// falls back to the bundle's embedded key when the ring is empty) — the caller asked for enforcement.
	if len(trustedKeys) == 0 {
		return fmt.Errorf("policy bundle trusted-key validation requires a non-empty keyring")
	}
	return validate(b, now, trustedKeys, false)
}

func validate(b model.PolicyBundle, now time.Time, trustedKeys map[string]ed25519.PublicKey, allowLabMock bool) error {
	if b.ID == "" {
		return fmt.Errorf("policy bundle id is required")
	}
	if b.TenantID == "" {
		return fmt.Errorf("policy bundle tenant_id is required")
	}
	if b.Version == "" {
		return fmt.Errorf("policy bundle version is required")
	}
	if b.Checksum == "" {
		return fmt.Errorf("policy bundle checksum is required")
	}
	if b.Checksum != MockChecksum {
		expected, err := CanonicalChecksum(b)
		if err != nil {
			return err
		}
		if b.Checksum != expected {
			return fmt.Errorf("policy bundle checksum mismatch: got %s expected %s", b.Checksum, expected)
		}
	}
	if b.Signature == "" {
		return fmt.Errorf("policy bundle signature is required")
	}
	if b.SigningKeyID == "" {
		return fmt.Errorf("policy bundle signing_key_id is required")
	}
	if isMockSignature(b) {
		if !allowLabMock {
			return fmt.Errorf("policy bundle mock signature is not accepted with trusted key validation")
		}
	} else {
		if err := VerifySignatureWithTrustedKeys(b, trustedKeys); err != nil {
			return err
		}
	}
	if b.TargetScope.TargetType == "" {
		return fmt.Errorf("policy bundle target_scope.target_type is required")
	}
	if b.CompiledPolicyRef == "" {
		return fmt.Errorf("policy bundle compiled_policy_ref is required")
	}
	if len(b.PolicyIDs) == 0 {
		return fmt.Errorf("policy bundle policy_ids must contain at least one policy")
	}
	if b.Status != "active" {
		return fmt.Errorf("policy bundle %s is not active: %s", b.ID, b.Status)
	}
	if b.ExpiresAt != "" {
		expiresAt, err := time.Parse(time.RFC3339, b.ExpiresAt)
		if err != nil {
			return fmt.Errorf("parse policy bundle expires_at: %w", err)
		}
		if now.After(expiresAt) {
			return fmt.Errorf("policy bundle %s expired at %s", b.ID, b.ExpiresAt)
		}
	}

	return nil
}

func VerifySignature(b model.PolicyBundle) error {
	return VerifySignatureWithTrustedKeys(b, nil)
}

func VerifySignatureWithTrustedKeys(b model.PolicyBundle, trustedKeys map[string]ed25519.PublicKey) error {
	if !strings.HasPrefix(b.Signature, signedconfig.SignaturePrefix) {
		return fmt.Errorf("policy bundle signature must use %s prefix", signedconfig.SignaturePrefix)
	}
	signature, err := signedconfig.DecodeRawURLBase64(strings.TrimPrefix(b.Signature, signedconfig.SignaturePrefix))
	if err != nil {
		return fmt.Errorf("decode policy bundle signature: %w", err)
	}
	publicKey, err := publicKeyForBundle(b, trustedKeys)
	if err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("policy bundle signing key length is %d", len(publicKey))
	}
	payload, err := SignaturePayload(b)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), payload, signature) {
		return fmt.Errorf("policy bundle signature verification failed")
	}
	return nil
}

func publicKeyForBundle(b model.PolicyBundle, trustedKeys map[string]ed25519.PublicKey) (ed25519.PublicKey, error) {
	if len(trustedKeys) > 0 {
		publicKey, ok := trustedKeys[b.SigningKeyID]
		if !ok {
			return nil, fmt.Errorf("policy bundle signing_key_id %s is not trusted", b.SigningKeyID)
		}
		return publicKey, nil
	}
	if !strings.HasPrefix(b.SigningKeyID, signedconfig.SigningKeyIDPrefix) {
		return nil, fmt.Errorf("policy bundle signing_key_id must use %s prefix", signedconfig.SigningKeyIDPrefix)
	}
	publicKey, err := signedconfig.DecodeRawURLBase64(strings.TrimPrefix(b.SigningKeyID, signedconfig.SigningKeyIDPrefix))
	if err != nil {
		return nil, fmt.Errorf("decode policy bundle signing key: %w", err)
	}
	return ed25519.PublicKey(publicKey), nil
}

func SignaturePayload(b model.PolicyBundle) ([]byte, error) {
	b.Signature = ""
	data, err := canonicalJSONFromBundle(b)
	if err != nil {
		return nil, fmt.Errorf("canonicalize policy bundle for signature: %w", err)
	}
	return data, nil
}

func CanonicalChecksum(b model.PolicyBundle) (string, error) {
	b.Checksum = ""
	b.Signature = ""
	data, err := canonicalJSONFromBundle(b)
	if err != nil {
		return "", fmt.Errorf("canonicalize policy bundle for checksum: %w", err)
	}
	sum := sha256.Sum256(data)
	return signedconfig.ChecksumPrefix + strings.ToLower(fmt.Sprintf("%x", sum[:])), nil
}

func isMockSignature(b model.PolicyBundle) bool {
	return b.Signature == MockSignature && b.SigningKeyID == MockSigningKeyID
}

func canonicalJSONFromBundle(b model.PolicyBundle) ([]byte, error) {
	data, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	return signedconfig.CanonicalJSON(data)
}
