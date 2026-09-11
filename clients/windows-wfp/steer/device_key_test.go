package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The portable seam: on any platform the file path must produce a usable ECDSA signer and PEM, and the storage
// labels must be unambiguous. (The TPM path itself is exercised by the windows-tagged tests against a real chip.)
func TestNewFileDeviceKey(t *testing.T) {
	dk, err := newFileDeviceKey()
	if err != nil {
		t.Fatal(err)
	}
	if dk.hardware || dk.container != "" || len(dk.keyPEM) == 0 {
		t.Fatalf("file key material looks wrong: %+v", dk)
	}
	pub, err := expectedECDSAPublicKey(dk.signer)
	if err != nil {
		t.Fatal(err)
	}
	// It signs, and the signature verifies against its own public key.
	digest := sha256.Sum256([]byte("device key"))
	sig, err := dk.signer.Sign(rand.Reader, digest[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatal("file key signature did not verify")
	}
	if got := dk.storageLabel(); !strings.HasPrefix(got, "FILE") {
		t.Fatalf("file storage label = %q", got)
	}
}

// A hardware key material labels itself as TPM with its container; the token forms are distinct.
func TestDeviceKeyStorageLabels(t *testing.T) {
	tpm := deviceKeyMaterial{hardware: true, container: "dsse-device-win-dev-1-abcdef"}
	if !strings.HasPrefix(tpm.storageLabel(), "TPM") || !strings.Contains(tpm.storageLabel(), "abcdef") {
		t.Fatalf("tpm label = %q", tpm.storageLabel())
	}
	if deviceKeyStorageKind(true) != "tpm" || deviceKeyStorageKind(false) != "file" {
		t.Fatal("storage kind tokens wrong")
	}
	// Container names are unique per call so a renewal never collides with the key it is replacing.
	if deviceKeyContainerName("win-dev-1") == deviceKeyContainerName("win-dev-1") {
		t.Fatal("container names must be unique per generation")
	}
}

// A TPM identity pointer names a container and NO key file; readIdentityPointer must accept it, and reject a
// pointer that names neither — the check that used to require a key file would have refused every TPM identity.
func TestReadIdentityPointerAcceptsTPMContainer(t *testing.T) {
	dir := t.TempDir()
	write := func(p deviceIdentityPointer) {
		raw, _ := json.MarshalIndent(p, "", "  ")
		if err := os.WriteFile(filepath.Join(dir, renewalPointerFile), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	write(deviceIdentityPointer{CertFile: filepath.Join(dir, "device.crt"), KeyContainer: "dsse-device-win-dev-1-abcdef", KeyStorage: "tpm"})
	if p, err := readIdentityPointer(dir); err != nil || p.KeyContainer == "" {
		t.Fatalf("a TPM pointer (container, no key file) was rejected: %v", err)
	}
	if got := pointerStorageLabel(mustReadPointer(t, dir)); !strings.HasPrefix(got, "TPM") {
		t.Fatalf("pointer storage label = %q", got)
	}

	write(deviceIdentityPointer{CertFile: filepath.Join(dir, "device.crt"), KeyFile: filepath.Join(dir, "device.key"), KeyStorage: "file"})
	if p, err := readIdentityPointer(dir); err != nil || p.KeyFile == "" {
		t.Fatalf("a file pointer was rejected: %v", err)
	}

	// Neither key file nor container: unusable, must error.
	write(deviceIdentityPointer{CertFile: filepath.Join(dir, "device.crt")})
	if _, err := readIdentityPointer(dir); err == nil {
		t.Fatal("a pointer naming no key was accepted")
	}
}

// candidateFromIssued must assemble a usable tls.Certificate from an issued PEM and a signer, with the leaf
// parsed — a TPM key has no file for tls.LoadX509KeyPair to read.
func TestCandidateFromIssued(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	certPEM := mintFor(t, &key.PublicKey, "win-dev-1", now.Add(-time.Hour), now.Add(24*time.Hour))
	cand, err := candidateFromIssued(certPEM, key)
	if err != nil {
		t.Fatal(err)
	}
	if cand.Leaf == nil || cand.Leaf.Subject.CommonName != "win-dev-1" {
		t.Fatalf("candidate leaf = %+v", cand.Leaf)
	}
	if len(cand.Certificate) == 0 || cand.PrivateKey == nil {
		t.Fatal("candidate missing chain or key")
	}
	if _, err := x509.ParseCertificate(cand.Certificate[0]); err != nil {
		t.Fatalf("candidate chain[0] not a certificate: %v", err)
	}
}

func mustReadPointer(t *testing.T, dir string) deviceIdentityPointer {
	t.Helper()
	p, err := readIdentityPointer(dir)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
