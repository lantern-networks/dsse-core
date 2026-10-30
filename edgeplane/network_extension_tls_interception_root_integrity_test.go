package edgeplane

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPersistentInterceptionRootRecoversIncompleteCompatibilityView(t *testing.T) {
	for _, missing := range []string{"certificate", "key"} {
		t.Run(missing, func(t *testing.T) {
			certPath := filepath.Join(t.TempDir(), "interception-root.pem")
			first, err := NewNetworkExtensionLabTLSInterceptionWithPersistentRoot([]string{"example.com"}, time.Now, certPath)
			if err != nil {
				t.Fatal(err)
			}
			keyPath := NetworkExtensionLabTLSRootKeyPath(certPath)
			missingPath, survivorPath := certPath, keyPath
			if missing == "key" {
				missingPath, survivorPath = keyPath, certPath
			}
			survivor, err := os.ReadFile(survivorPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(missingPath); err != nil {
				t.Fatal(err)
			}
			restarted, err := NewNetworkExtensionLabTLSInterceptionWithPersistentRoot([]string{"example.com"}, time.Now, certPath)
			if err != nil {
				t.Fatalf("a committed snapshot must recover its missing compatibility view: %v", err)
			}
			if !bytes.Equal(first.rootCert.Raw, restarted.rootCert.Raw) {
				t.Fatal("recovery changed the trusted root")
			}
			got, err := os.ReadFile(survivorPath)
			if err != nil || !bytes.Equal(got, survivor) {
				t.Fatal("recovery changed the intact view")
			}
			if _, err := os.Stat(missingPath); err != nil {
				t.Fatalf("missing view was not rebuilt: %v", err)
			}
			if len(first.rootCertPEM) == 0 {
				t.Fatal("initial empty state did not produce a root")
			}
		})
	}
}

func TestPerTenantInterceptionRootRecoversIncompleteCompatibilityView(t *testing.T) {
	dir := t.TempDir()
	material, err := GenerateNetworkExtensionLabTLSRootMaterial(time.Now)
	if err != nil {
		t.Fatal(err)
	}
	first := NewTenantInterceptionRootRegistry(NewFileInterceptionRootProvider(material), time.Now)
	first.SetStateDir(dir)
	if _, err := first.Provision("tenant-A"); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, sanitizeRootKey("tenant-A")+".pem")
	if err := os.Remove(NetworkExtensionLabTLSRootKeyPath(certPath)); err != nil {
		t.Fatal(err)
	}
	second := NewTenantInterceptionRootRegistry(NewFileInterceptionRootProvider(material), time.Now)
	second.SetStateDir(dir)
	got, err := second.Provision("tenant-A")
	if err != nil {
		t.Fatalf("tenant root snapshot did not recover missing key view: %v", err)
	}
	if got.CertPEM == "" {
		t.Fatal("tenant root was not recovered")
	}
}

func TestDirectoryInterceptionRootSelectionRefusesIncompleteCandidates(t *testing.T) {
	for _, state := range []string{"current-key-only-with-legacy-pair", "legacy-certificate-only", "legacy-key-only", "current-certificate-stat-error", "legacy-pair-only"} {
		t.Run(state, func(t *testing.T) {
			dir := t.TempDir()
			legacyCert := filepath.Join(dir, networkExtensionLabTLSRootCertLegacyFilenames[0])
			legacy, err := NewNetworkExtensionLabTLSInterceptionWithPersistentRoot([]string{"example.com"}, time.Now, legacyCert)
			if err != nil {
				t.Fatal(err)
			}
			currentCert := filepath.Join(dir, NetworkExtensionLabTLSRootCertFilename)
			switch state {
			case "current-key-only-with-legacy-pair":
				key, err := os.ReadFile(NetworkExtensionLabTLSRootKeyPath(legacyCert))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(NetworkExtensionLabTLSRootKeyPath(currentCert), key, 0600); err != nil {
					t.Fatal(err)
				}
			case "legacy-certificate-only":
				if err := os.Remove(NetworkExtensionLabTLSRootKeyPath(legacyCert)); err != nil {
					t.Fatal(err)
				}
			case "legacy-key-only":
				if err := os.Remove(legacyCert); err != nil {
					t.Fatal(err)
				}
			case "current-certificate-stat-error":
				if err := os.Symlink(currentCert, currentCert); err != nil {
					t.Fatal(err)
				}
			}
			got, err := NewNetworkExtensionLabTLSInterceptionWithPersistentRoot([]string{"example.com"}, time.Now, dir)
			if state == "legacy-pair-only" || state == "legacy-certificate-only" || state == "legacy-key-only" {
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got.rootCertPEM, legacy.rootCertPEM) {
					t.Fatal("legacy snapshot must retain the same root while recovering its views")
				}
				return
			}
			if err == nil {
				t.Fatal("an incomplete or unreadable current/legacy root must not be skipped to select or mint another root")
			}
		})
	}
}
