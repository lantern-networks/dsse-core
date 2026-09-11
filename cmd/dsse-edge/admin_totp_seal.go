package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/lantern-networks/dsse-core/edgeplane"
)

// admin_totp_seal.go seals admin TOTP shared secrets AT REST. A TOTP secret is a bearer credential: anyone
// holding it can mint valid 2FA codes forever, defeating the second factor. Persisted plaintext (the
// totp_secret column / durable store) it is only as protected as the DB file perms. When the root KEK is
// configured (-interception-root-kek-file — the same KEK that seals interception root keys), the secret is
// sealed with AES-256-GCM and only the ciphertext is stored; the plaintext exists in process memory only.
// With no KEK the secret is stored unchanged (backwards compatible — protected by storage perms alone).
//
// Sealed values carry a version prefix so seal/unseal is idempotent and an unsealed store can be migrated in
// place (re-seal on next write). password_hash and recovery_code_hashes are already one-way hashes, so only
// the (reversible-by-design) TOTP secret needs sealing.
const sealedTOTPSecretPrefix = "dsse-totp-v1:"

// sealTOTPSecretForStore returns the at-rest form of a base32 TOTP secret: sealed when a KEK is configured,
// the value unchanged otherwise. Empty input (not-yet-enrolled) and already-sealed input pass through.
func sealTOTPSecretForStore(secret string) (string, error) {
	if secret == "" || strings.HasPrefix(secret, sealedTOTPSecretPrefix) {
		return secret, nil
	}
	kek := edgeplane.GetInterceptionRootKEK()
	if len(kek) == 0 {
		return secret, nil
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return "", fmt.Errorf("totp seal KEK: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(secret), nil)
	return sealedTOTPSecretPrefix + base64.StdEncoding.EncodeToString(sealed), nil
}

// unsealTOTPSecretFromStore returns the plaintext base32 secret from an at-rest value. Unsealed values pass
// through. A sealed value with no KEK configured is a fail-closed error (the secret cannot be recovered).
func unsealTOTPSecretFromStore(stored string) (string, error) {
	if !strings.HasPrefix(stored, sealedTOTPSecretPrefix) {
		return stored, nil
	}
	kek := edgeplane.GetInterceptionRootKEK()
	if len(kek) == 0 {
		return "", fmt.Errorf("totp secret is sealed but no KEK is configured (-interception-root-kek-file)")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, sealedTOTPSecretPrefix))
	if err != nil {
		return "", fmt.Errorf("decode sealed totp secret: %w", err)
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return "", fmt.Errorf("totp seal KEK: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", fmt.Errorf("sealed totp secret is truncated")
	}
	nonce, ct := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("unseal totp secret (wrong KEK or corrupt): %w", err)
	}
	return string(plain), nil
}
