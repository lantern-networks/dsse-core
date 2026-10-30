package bundle

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/signedconfig"
)

func TestEveryTrustedBundleEntrypointRejectsEmptyKeyring(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b := testPolicyBundle()
	b.SigningKeyID = signedconfig.SigningKeyIDPrefix + base64.RawURLEncoding.EncodeToString(pub)
	b.Checksum, err = CanonicalChecksum(b)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := SignaturePayload(b)
	if err != nil {
		t.Fatal(err)
	}
	b.Signature = signedconfig.SignaturePrefix + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, payload))
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bundle.json")
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	for _, keys := range []map[string]ed25519.PublicKey{nil, {}} {
		if _, err := LoadWithTrustedKeys(path, keys); err == nil {
			t.Error("enforcing loader accepted attacker-embedded key with empty keyring")
		}
		if err := VerifySignatureWithTrustedKeys(b, keys); err == nil {
			t.Error("enforcing verifier accepted attacker-embedded key with empty keyring")
		}
	}
	keys := map[string]ed25519.PublicKey{b.SigningKeyID: pub}
	if _, err := LoadWithTrustedKeys(path, keys); err != nil {
		t.Fatal(err)
	}
	if err := VerifySignatureWithTrustedKeys(b, keys); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("explicit lab loader changed: %v", err)
	}
	if err := VerifySignature(b); err != nil {
		t.Fatalf("explicit lab verifier changed: %v", err)
	}
}

func TestBundleExpiresAtItsDeadline(t *testing.T) {
	b := testPolicyBundle()
	deadline, err := time.Parse(time.RFC3339, b.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(b, deadline); err == nil {
		t.Fatal("expired bundle accepted at deadline")
	}
}
