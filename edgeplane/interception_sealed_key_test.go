package edgeplane

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSealUnsealInterceptionKeyRoundTrip(t *testing.T) {
	kek := make([]byte, 32)
	rand.Read(kek)
	plain := []byte("-----BEGIN PRIVATE KEY-----\nMOCK\n-----END PRIVATE KEY-----\n")

	sealed, err := sealInterceptionKeyPEM(plain, kek)
	if err != nil {
		t.Fatal(err)
	}
	if !isSealedInterceptionKeyPEM(sealed) {
		t.Fatal("sealed output not detected as sealed")
	}
	if bytes.Contains(sealed, []byte("MOCK")) {
		t.Fatal("plaintext leaked into the sealed blob")
	}
	out, err := unsealInterceptionKeyPEM(sealed, kek)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, plain) {
		t.Fatal("roundtrip mismatch")
	}
	// Wrong KEK must fail (AEAD auth).
	wrong := make([]byte, 32)
	rand.Read(wrong)
	if _, err := unsealInterceptionKeyPEM(sealed, wrong); err == nil {
		t.Fatal("unseal with the wrong KEK must fail")
	}
}

// TestInterceptionRootKeySealedAtRest proves the integration: with a KEK configured, a persisted root key is
// CIPHERTEXT on disk, the edge reloads it correctly, and without the KEK the load fails closed.
func TestInterceptionRootKeySealedAtRest(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC) }
	kek := make([]byte, 32)
	rand.Read(kek)
	SetInterceptionRootKEK(kek)
	t.Cleanup(func() { SetInterceptionRootKEK(nil) })

	dir := t.TempDir()
	certPath := filepath.Join(dir, "root.pem")
	material, err := GenerateNetworkExtensionLabTLSRootMaterial(now)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteNetworkExtensionLabTLSPersistentRootMaterial(certPath, material); err != nil {
		t.Fatal(err)
	}
	// On disk the key file must be a sealed blob, NOT a plaintext private key.
	keyOnDisk, err := os.ReadFile(NetworkExtensionLabTLSRootKeyPath(certPath))
	if err != nil {
		t.Fatal(err)
	}
	if !isSealedInterceptionKeyPEM(keyOnDisk) {
		t.Fatal("key on disk is not sealed")
	}
	if bytes.Contains(keyOnDisk, []byte("PRIVATE KEY")) {
		t.Fatal("plaintext PRIVATE KEY block on disk despite KEK")
	}
	// With the KEK, reload succeeds and matches.
	loaded, reused, err := LoadNetworkExtensionLabTLSPersistentRootMaterial(certPath, now)
	if err != nil || !reused || loaded.Cert == nil {
		t.Fatalf("reload sealed root: err=%v reused=%v", err, reused)
	}
	if !bytes.Equal(loaded.Cert.Raw, material.Cert.Raw) {
		t.Fatal("reloaded cert mismatch")
	}
	// Without the KEK, the load fails closed.
	SetInterceptionRootKEK(nil)
	if _, _, err := LoadNetworkExtensionLabTLSPersistentRootMaterial(certPath, now); err == nil {
		t.Fatal("sealed key must not load without the KEK")
	}
}
