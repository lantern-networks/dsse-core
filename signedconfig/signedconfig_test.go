package signedconfig

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestValidateRejectsSignedEnvelopeWithoutTrustedKeyring(t *testing.T) {
	publicKey, privateKey := generateKey(t)
	env := testEnvelope(t, publicKey)
	signed, err := Sign(env, privateKey)
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}

	err = Validate(signed, "agent_config", time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC), nil)
	if err == nil {
		t.Fatal("Validate returned nil, want trusted keyring error")
	}
	if !strings.Contains(err.Error(), "trusted keyring is required") {
		t.Fatalf("error = %q", err.Error())
	}
	if err := Validate(signed, "agent_config", time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC), map[string]ed25519.PublicKey{signed.SigningKeyID: publicKey}); err != nil {
		t.Fatalf("Validate with trusted key returned error: %v", err)
	}
}

func TestValidateRejectsTamperedPayload(t *testing.T) {
	publicKey, privateKey := generateKey(t)
	env := testEnvelope(t, publicKey)
	signed, err := Sign(env, privateKey)
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}
	signed.Payload = json.RawMessage(`{"edge_url":"https://evil.example.local"}`)

	err = Validate(signed, "agent_config", time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC), nil)
	if err == nil {
		t.Fatal("Validate returned nil, want checksum mismatch")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestValidateUsesTrustedKeyID(t *testing.T) {
	publicKey, privateKey := generateKey(t)
	env := testEnvelope(t, publicKey)
	env.SigningKeyID = "cfgsign_lab_001"
	signed, err := Sign(env, privateKey)
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}

	if err := Validate(signed, "agent_config", time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC), map[string]ed25519.PublicKey{"cfgsign_lab_001": publicKey}); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
}

func TestValidateRejectsExpiredEnvelope(t *testing.T) {
	publicKey, privateKey := generateKey(t)
	env := testEnvelope(t, publicKey)
	env.ExpiresAt = "2020-01-01T00:00:00Z"
	signed, err := Sign(env, privateKey)
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}

	err = Validate(signed, "agent_config", time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC), nil)
	if err == nil {
		t.Fatal("Validate returned nil, want expired error")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestCanonicalJSONPreservesLargeNumbers(t *testing.T) {
	canonical, err := CanonicalJSON(json.RawMessage(`{"small":1,"big":900719925474099312345,"nested":{"precise":123456789012345678901234567890}}`))
	if err != nil {
		t.Fatalf("CanonicalJSON returned error: %v", err)
	}
	got := string(canonical)
	for _, want := range []string{
		`"big":900719925474099312345`,
		`"precise":123456789012345678901234567890`,
		`"small":1`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("CanonicalJSON = %s, missing %s", got, want)
		}
	}
	if strings.Contains(got, "9.007199254740993e+20") || strings.Contains(got, "1.2345678901234568e+29") {
		t.Fatalf("CanonicalJSON rounded large numbers: %s", got)
	}
}

func TestCanonicalJSONRejectsTrailingValues(t *testing.T) {
	if _, err := CanonicalJSON(json.RawMessage(`{"ok":true} {"extra":true}`)); err == nil || !strings.Contains(err.Error(), "multiple JSON values") {
		t.Fatalf("CanonicalJSON trailing value error = %v, want multiple JSON values", err)
	}
}

func testEnvelope(t *testing.T, publicKey ed25519.PublicKey) Envelope {
	t.Helper()
	payload := json.RawMessage(`{"edge_url":"https://edge.lab.example.local","tenant_id":"tenant_lab_001"}`)
	checksum, err := PayloadChecksum(payload)
	if err != nil {
		t.Fatalf("PayloadChecksum returned error: %v", err)
	}
	return Envelope{
		Type:         "agent_config",
		Version:      "2026.05.22.001",
		Payload:      payload,
		Checksum:     checksum,
		SigningKeyID: SigningKeyIDPrefix + base64.RawURLEncoding.EncodeToString(publicKey),
		CreatedAt:    "2026-05-22T00:00:00Z",
		ExpiresAt:    "2030-01-01T00:00:00Z",
		Status:       "active",
		Metadata:     map[string]any{"source": "test"},
	}
}

func generateKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	return publicKey, privateKey
}
