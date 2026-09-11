package signedconfig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	ChecksumPrefix     = "sha256:"
	SignaturePrefix    = "ed25519:"
	SigningKeyIDPrefix = "ed25519-public:"
)

type Envelope struct {
	Type         string          `json:"type"`
	Version      string          `json:"version"`
	Payload      json.RawMessage `json:"payload"`
	Checksum     string          `json:"checksum"`
	Signature    string          `json:"signature"`
	SigningKeyID string          `json:"signing_key_id"`
	CreatedAt    string          `json:"created_at"`
	ExpiresAt    string          `json:"expires_at"`
	Status       string          `json:"status"`
	Metadata     map[string]any  `json:"metadata"`
}

func Validate(env Envelope, expectedType string, now time.Time, trustedKeys map[string]ed25519.PublicKey) error {
	if env.Type == "" {
		return fmt.Errorf("signed config type is required")
	}
	if expectedType != "" && env.Type != expectedType {
		return fmt.Errorf("signed config type %s does not match expected type %s", env.Type, expectedType)
	}
	if env.Version == "" {
		return fmt.Errorf("signed config version is required")
	}
	if len(env.Payload) == 0 {
		return fmt.Errorf("signed config payload is required")
	}
	if env.Checksum == "" {
		return fmt.Errorf("signed config checksum is required")
	}
	expectedChecksum, err := PayloadChecksum(env.Payload)
	if err != nil {
		return err
	}
	if env.Checksum != expectedChecksum {
		return fmt.Errorf("signed config checksum mismatch: got %s expected %s", env.Checksum, expectedChecksum)
	}
	if env.Signature == "" {
		return fmt.Errorf("signed config signature is required")
	}
	if env.SigningKeyID == "" {
		return fmt.Errorf("signed config signing_key_id is required")
	}
	if env.Status != "active" {
		return fmt.Errorf("signed config %s is not active: %s", env.Type, env.Status)
	}
	if env.ExpiresAt != "" {
		expiresAt, err := time.Parse(time.RFC3339, env.ExpiresAt)
		if err != nil {
			return fmt.Errorf("parse signed config expires_at: %w", err)
		}
		if now.After(expiresAt) {
			return fmt.Errorf("signed config %s expired at %s", env.Type, env.ExpiresAt)
		}
	}
	return VerifySignature(env, trustedKeys)
}

func PayloadChecksum(payload json.RawMessage) (string, error) {
	canonical, err := CanonicalJSON(payload)
	if err != nil {
		return "", fmt.Errorf("canonicalize signed config payload: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return ChecksumPrefix + fmt.Sprintf("%x", sum[:]), nil
}

func SignaturePayload(env Envelope) ([]byte, error) {
	env.Signature = ""
	env.Metadata = normalizeMetadata(env.Metadata)
	data, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("marshal signed config for signature: %w", err)
	}
	return data, nil
}

func VerifySignature(env Envelope, trustedKeys map[string]ed25519.PublicKey) error {
	if !strings.HasPrefix(env.Signature, SignaturePrefix) {
		return fmt.Errorf("signed config signature must use %s prefix", SignaturePrefix)
	}
	signature, err := DecodeRawURLBase64(strings.TrimPrefix(env.Signature, SignaturePrefix))
	if err != nil {
		return fmt.Errorf("decode signed config signature: %w", err)
	}
	publicKey, err := publicKeyForEnvelope(env, trustedKeys)
	if err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("signed config signing key length is %d", len(publicKey))
	}
	payload, err := SignaturePayload(env)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return fmt.Errorf("signed config signature verification failed")
	}
	return nil
}

func Sign(env Envelope, privateKey ed25519.PrivateKey) (Envelope, error) {
	payload, err := SignaturePayload(env)
	if err != nil {
		return env, err
	}
	env.Signature = SignaturePrefix + base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	return env, nil
}

func PayloadInto[T any](env Envelope) (T, error) {
	var value T
	if err := json.Unmarshal(env.Payload, &value); err != nil {
		return value, fmt.Errorf("parse signed config payload: %w", err)
	}
	return value, nil
}

func publicKeyForEnvelope(env Envelope, trustedKeys map[string]ed25519.PublicKey) (ed25519.PublicKey, error) {
	if len(trustedKeys) == 0 {
		return nil, fmt.Errorf("signed config trusted keyring is required")
	}
	publicKey, ok := trustedKeys[env.SigningKeyID]
	if !ok {
		return nil, fmt.Errorf("signed config signing_key_id %s is not trusted", env.SigningKeyID)
	}
	return publicKey, nil
}

// CanonicalJSON preserves JSON numbers and rejects trailing values before
// marshaling through Go's encoding/json. It is sufficient for Phase 1 ASCII-key
// payloads, but it is not a full RFC 8785 implementation for non-ASCII object
// key ordering.
func CanonicalJSON(payload json.RawMessage) ([]byte, error) {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("multiple JSON values are not allowed")
		}
		return nil, err
	}
	return json.Marshal(value)
}

func normalizeMetadata(metadata map[string]any) map[string]any {
	if metadata == nil {
		return map[string]any{}
	}
	return metadata
}

func DecodeRawURLBase64(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err == nil {
		return decoded, nil
	}
	return base64.StdEncoding.DecodeString(value)
}
