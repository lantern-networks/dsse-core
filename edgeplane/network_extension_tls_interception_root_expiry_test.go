package edgeplane

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func persistentRootPairHashes(t *testing.T, certPath string) ([32]byte, [32]byte) {
	t.Helper()
	cert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(NetworkExtensionLabTLSRootKeyPath(certPath))
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(cert), sha256.Sum256(key)
}

func TestPersistentRootNearExpiryKeepsExistingTrustedPair(t *testing.T) {
	for _, offset := range []time.Duration{-time.Second, 0, NetworkExtensionLabTLSRootRotateBefore - time.Second} {
		t.Run(offset.String(), func(t *testing.T) {
			current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			clock := func() time.Time { return current }
			certPath := filepath.Join(t.TempDir(), "root.pem")
			first, err := NewNetworkExtensionLabTLSInterceptionWithPersistentRoot([]string{"example.com"}, clock, certPath)
			if err != nil {
				t.Fatal(err)
			}
			certHash, keyHash := persistentRootPairHashes(t, certPath)
			current = first.rootCert.NotAfter.Add(-NetworkExtensionLabTLSRootRotateBefore).Add(offset)
			second, err := NewNetworkExtensionLabTLSInterceptionWithPersistentRoot([]string{"example.com"}, clock, certPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(first.rootCert.Raw, second.rootCert.Raw) {
				t.Fatal("startup silently replaced the root before it expired")
			}
			gotCertHash, gotKeyHash := persistentRootPairHashes(t, certPath)
			if gotCertHash != certHash || gotKeyHash != keyHash {
				t.Fatal("startup changed the trusted root certificate or private key")
			}
		})
	}
}

func TestExpiredPersistentRootRefusesWithoutChangingFiles(t *testing.T) {
	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return current }
	certPath := filepath.Join(t.TempDir(), "root.pem")
	first, err := NewNetworkExtensionLabTLSInterceptionWithPersistentRoot([]string{"example.com"}, clock, certPath)
	if err != nil {
		t.Fatal(err)
	}
	certHash, keyHash := persistentRootPairHashes(t, certPath)
	current = first.rootCert.NotAfter
	if _, reused, err := LoadNetworkExtensionLabTLSPersistentRootMaterial(certPath, clock); err == nil || reused {
		t.Fatal("expired persisted root must be refused, not treated as absent")
	}
	if _, err := NewNetworkExtensionLabTLSInterceptionWithPersistentRoot([]string{"example.com"}, clock, certPath); err == nil {
		t.Fatal("expired persisted root was silently replaced on startup")
	}
	gotCertHash, gotKeyHash := persistentRootPairHashes(t, certPath)
	if gotCertHash != certHash || gotKeyHash != keyHash {
		t.Fatal("expired root refusal changed the existing pair")
	}
}

func TestPersistentRootFirstCreationAndInvalidPairBoundaries(t *testing.T) {
	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return current }
	certPath := filepath.Join(t.TempDir(), "root.pem")
	if _, reused, err := LoadNetworkExtensionLabTLSPersistentRootMaterial(certPath, clock); err != nil || reused {
		t.Fatalf("an actually empty pair is the only initial state: reused=%v err=%v", reused, err)
	}
	first, err := NewNetworkExtensionLabTLSInterceptionWithPersistentRoot([]string{"example.com"}, clock, certPath)
	if err != nil {
		t.Fatal(err)
	}
	certHash, keyHash := persistentRootPairHashes(t, certPath)
	if _, reused, err := LoadNetworkExtensionLabTLSPersistentRootMaterial(certPath, clock); err != nil || !reused {
		t.Fatalf("first creation did not persist a reusable pair: reused=%v err=%v", reused, err)
	}
	other, err := GenerateNetworkExtensionLabTLSRootMaterial(clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, other.CertPEM, 0600); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewNetworkExtensionLabTLSInterceptionWithPersistentRoot([]string{"example.com"}, clock, certPath)
	if err != nil {
		t.Fatalf("a mismatched compatibility view should be recovered from the authoritative snapshot: %v", err)
	}
	gotCertHash, gotKeyHash := persistentRootPairHashes(t, certPath)
	if gotCertHash != certHash || gotCertHash == sha256.Sum256(other.CertPEM) || gotKeyHash != keyHash || !bytes.Equal(restarted.rootCert.Raw, first.rootCert.Raw) {
		t.Fatal("recovery did not restore the committed root pair")
	}
}

func TestPerTenantPersistentRootNearExpiryKeepsExistingTrustedPair(t *testing.T) {
	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return current }
	base, err := GenerateNetworkExtensionLabTLSRootMaterial(clock)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	first := NewTenantInterceptionRootRegistry(NewFileInterceptionRootProvider(base), clock)
	first.SetStateDir(dir)
	info, err := first.Provision("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, sanitizeRootKey("tenant-a")+".pem")
	certHash, keyHash := persistentRootPairHashes(t, certPath)
	cert, err := ParseInterceptionCertPEM([]byte(info.CertPEM))
	if err != nil {
		t.Fatal(err)
	}
	current = cert.NotAfter.Add(-NetworkExtensionLabTLSRootRotateBefore)
	second := NewTenantInterceptionRootRegistry(NewFileInterceptionRootProvider(base), clock)
	second.SetStateDir(dir)
	newInfo, err := second.Provision("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if newInfo.CertPEM != info.CertPEM {
		t.Fatal("tenant root was replaced before expiry")
	}
	gotCertHash, gotKeyHash := persistentRootPairHashes(t, certPath)
	if gotCertHash != certHash || gotKeyHash != keyHash {
		t.Fatal("tenant root files changed during startup")
	}
	current = cert.NotAfter
	third := NewTenantInterceptionRootRegistry(NewFileInterceptionRootProvider(base), clock)
	third.SetStateDir(dir)
	if _, err := third.Provision("tenant-a"); err == nil {
		t.Fatal("expired tenant root was silently replaced")
	}
	gotCertHash, gotKeyHash = persistentRootPairHashes(t, certPath)
	if gotCertHash != certHash || gotKeyHash != keyHash {
		t.Fatal("expired tenant root refusal changed the old pair")
	}
}
