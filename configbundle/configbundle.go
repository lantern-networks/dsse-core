// Package configbundle is the control-plane config-distribution wire format and helpers. A control
// plane serves a Bundle (the current config snapshot for a tenant); edges periodically pull it and
// apply any newer generation. The generation is a monotonic counter the control plane bumps on every
// config mutation, so an edge applies a bundle only when it is newer than the one it last applied.
package configbundle

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/signedconfig"
)

// Bundle is the config snapshot a control plane serves and an edge applies.
//
// Signature/SigningKeyID authenticate the snapshot itself (Ed25519 over the canonical JSON of the bundle
// with the signature field emptied — so Generation and every policy byte are covered). Transport auth
// (TLS + bearer token) alone means a compromised path or CP front can feed an edge arbitrary policy; the
// signature pins config authority to the holder of the CP signing key. The signed, monotonic Generation is
// also the anti-rollback epoch: an edge that persists its last-applied generation cannot be served an older
// (signed, once-valid) snapshot after a restart. Both fields are empty in an unsigned lab deployment.
type Bundle struct {
	Generation   uint64                     `json:"generation"`
	Policies     []model.Policy             `json:"policies"`
	TenantConfig *policy.TenantConfigBundle `json:"tenant_config,omitempty"`
	Signature    string                     `json:"signature,omitempty"`      // "ed25519:" + base64url
	SigningKeyID string                     `json:"signing_key_id,omitempty"` // key id in the edge's trusted keyring
}

// signaturePayload is the canonical byte string the signature covers: the bundle with Signature emptied
// (SigningKeyID stays in, so a verifier also authenticates WHICH key the CP claimed).
func signaturePayload(b Bundle) ([]byte, error) {
	b.Signature = ""
	data, err := json.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("marshal config bundle for signature: %w", err)
	}
	return signedconfig.CanonicalJSON(data)
}

// Sign returns b with Signature/SigningKeyID set.
func Sign(b Bundle, keyID string, privateKey ed25519.PrivateKey) (Bundle, error) {
	b.SigningKeyID = keyID
	payload, err := signaturePayload(b)
	if err != nil {
		return b, err
	}
	b.Signature = signedconfig.SignaturePrefix + base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	return b, nil
}

// Verify checks b's signature against a non-empty trusted keyring. It fails on an UNSIGNED bundle too: an
// edge configured with trusted keys must not accept a bundle that simply omits the signature.
func Verify(b Bundle, trustedKeys map[string]ed25519.PublicKey) error {
	if len(trustedKeys) == 0 {
		return fmt.Errorf("config bundle verification requires a non-empty trusted keyring")
	}
	if b.Signature == "" || b.SigningKeyID == "" {
		return fmt.Errorf("config bundle is unsigned (signature and signing_key_id are required when trusted keys are configured)")
	}
	if !strings.HasPrefix(b.Signature, signedconfig.SignaturePrefix) {
		return fmt.Errorf("config bundle signature must use %s prefix", signedconfig.SignaturePrefix)
	}
	signature, err := signedconfig.DecodeRawURLBase64(strings.TrimPrefix(b.Signature, signedconfig.SignaturePrefix))
	if err != nil {
		return fmt.Errorf("decode config bundle signature: %w", err)
	}
	publicKey, ok := trustedKeys[b.SigningKeyID]
	if !ok {
		return fmt.Errorf("config bundle signing_key_id %s is not trusted", b.SigningKeyID)
	}
	payload, err := signaturePayload(b)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return fmt.Errorf("config bundle signature verification failed")
	}
	return nil
}

// KeyIDFor derives a stable key id from a public key (same shape as agentpolicy.KeyIDFor), so the CP and
// the edges agree on the keyring entry name without extra coordination.
func KeyIDFor(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "cp-config-" + hex.EncodeToString(sum[:8])
}

// LoadOrGenerateSigningKey loads an Ed25519 seed (32-byte hex) from path, generating and persisting one
// when the file does not exist (the key edges pin stays stable across CP restarts). Any other read error
// is returned — NOT treated as absent — so a transient I/O failure cannot silently rotate the key.
func LoadOrGenerateSigningKey(path string) (string, ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		seed, derr := hex.DecodeString(strings.TrimSpace(string(data)))
		if derr != nil || len(seed) != ed25519.SeedSize {
			return "", nil, fmt.Errorf("config signing key %q must be a %d-byte hex seed", path, ed25519.SeedSize)
		}
		priv := ed25519.NewKeyFromSeed(seed)
		return KeyIDFor(priv.Public().(ed25519.PublicKey)), priv, nil
	}
	if !os.IsNotExist(err) {
		return "", nil, fmt.Errorf("read config signing key %q: %w", path, err)
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return "", nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(seed)), 0o600); err != nil {
		return "", nil, fmt.Errorf("persist config signing key %q: %w", path, err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return KeyIDFor(priv.Public().(ed25519.PublicKey)), priv, nil
}

// ParseTrustedKeys parses a comma-separated "key_id=base64url_public_key" list (the CLI keyring form the
// localclient also uses) into a keyring for Verify.
func ParseTrustedKeys(value string) (map[string]ed25519.PublicKey, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	keys := map[string]ed25519.PublicKey{}
	for _, part := range strings.Split(value, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		keyID, encoded, ok := strings.Cut(trimmed, "=")
		if !ok || keyID == "" || encoded == "" {
			return nil, fmt.Errorf("trusted key must be key_id=base64url_public_key")
		}
		decoded, err := signedconfig.DecodeRawURLBase64(encoded)
		if err != nil {
			return nil, fmt.Errorf("decode trusted key %s: %w", keyID, err)
		}
		if len(decoded) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("trusted key %s length is %d", keyID, len(decoded))
		}
		keys[keyID] = ed25519.PublicKey(decoded)
	}
	return keys, nil
}

// FromStore builds the current Bundle for a tenant from a policy store.
func FromStore(store *policy.Store, tenantID string) Bundle {
	cfg := store.SnapshotTenantConfig(tenantID)
	return Bundle{
		Generation:   store.ConfigGeneration(),
		Policies:     store.Snapshot(tenantID),
		TenantConfig: &cfg,
	}
}

// Fetch pulls a Bundle from a control plane's config-bundle endpoint, presenting the bearer token.
func Fetch(ctx context.Context, client *http.Client, url, token string) (Bundle, error) {
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Bundle{}, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return Bundle{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return Bundle{}, fmt.Errorf("config-bundle fetch: unexpected status %d", resp.StatusCode)
	}
	var b Bundle
	if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
		return Bundle{}, fmt.Errorf("config-bundle decode: %w", err)
	}
	return b, nil
}
