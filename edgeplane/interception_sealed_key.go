package edgeplane

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"sync"
)

// Interception root keys are the crown jewel. By default they persist as plaintext PEM (protected only by file
// perms). When a KEK (key-encryption key) is configured, the key is SEALED at rest with AES-256-GCM: the bytes
// on disk are ciphertext, and the plaintext key exists only in process memory after the edge unseals it with the
// KEK at startup. This removes "plaintext private key on disk" (a stated PKI gap). It does NOT put the key in an
// HSM — the plaintext is still in process memory — but the KEK can come from a secret manager and the same load
// path is where a PKCS#11/KMS provider (key never leaves hardware) would later plug in via the crypto.Signer seam.
const sealedInterceptionKeyPEMType = "DSSE SEALED INTERCEPTION KEY"

var (
	interceptionRootKEKMu sync.RWMutex
	interceptionRootKEK   []byte
)

func SetInterceptionRootKEK(kek []byte) {
	interceptionRootKEKMu.Lock()
	defer interceptionRootKEKMu.Unlock()
	interceptionRootKEK = append([]byte(nil), kek...)
}

func GetInterceptionRootKEK() []byte {
	interceptionRootKEKMu.RLock()
	defer interceptionRootKEKMu.RUnlock()
	return interceptionRootKEK
}

// LoadInterceptionRootKEKFromFile reads a 32-byte (AES-256) KEK from path, accepting raw 32 bytes, base64(std),
// or 64-char hex. Fail-closed: a wrong-sized key is rejected.
func LoadInterceptionRootKEKFromFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read interception root KEK: %w", err)
	}
	if len(data) == 32 {
		return data, nil
	}
	s := strings.TrimSpace(string(data))
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	return nil, fmt.Errorf("interception root KEK must be 32 bytes (raw, base64, or hex); got %d bytes", len(data))
}

func sealInterceptionKeyPEM(plainPEM, kek []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("interception KEK: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nonce, nonce, plainPEM, nil)
	return pem.EncodeToMemory(&pem.Block{Type: sealedInterceptionKeyPEMType, Bytes: sealed}), nil
}

func unsealInterceptionKeyPEM(blobPEM, kek []byte) ([]byte, error) {
	blk, _ := pem.Decode(blobPEM)
	if blk == nil || blk.Type != sealedInterceptionKeyPEMType {
		return nil, fmt.Errorf("not a sealed interception key")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("interception KEK: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(blk.Bytes) < gcm.NonceSize() {
		return nil, fmt.Errorf("sealed interception key is truncated")
	}
	nonce, ct := blk.Bytes[:gcm.NonceSize()], blk.Bytes[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("unseal interception key (wrong KEK or corrupt): %w", err)
	}
	return plain, nil
}

func isSealedInterceptionKeyPEM(pemBytes []byte) bool {
	blk, _ := pem.Decode(pemBytes)
	return blk != nil && blk.Type == sealedInterceptionKeyPEMType
}

// maybeSealInterceptionKeyForDisk returns the on-disk bytes for an interception key: sealed when a KEK is
// configured, else the plaintext PEM unchanged.
func maybeSealInterceptionKeyForDisk(plainPEM []byte) ([]byte, error) {
	kek := GetInterceptionRootKEK()
	if len(kek) == 0 {
		return plainPEM, nil
	}
	return sealInterceptionKeyPEM(plainPEM, kek)
}

// maybeUnsealInterceptionKeyFromDisk returns the plaintext key PEM from on-disk bytes: decrypts when the bytes
// are sealed (requires the KEK — fail-closed if absent), else returns them unchanged.
func maybeUnsealInterceptionKeyFromDisk(diskBytes []byte) ([]byte, error) {
	if !isSealedInterceptionKeyPEM(diskBytes) {
		return diskBytes, nil
	}
	kek := GetInterceptionRootKEK()
	if len(kek) == 0 {
		return nil, fmt.Errorf("interception root key is sealed but no KEK is configured (-interception-root-kek-file)")
	}
	return unsealInterceptionKeyPEM(diskBytes, kek)
}
