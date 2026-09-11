package edgeplane

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// C9: the root PEM's filename changed with the branding. A deployment that names the DIRECTORY must keep
// using the root already on disk — minting a fresh one reads as success while every device that pinned the
// old root silently stops trusting what is served.
func TestARenamedRootFileIsStillFoundAndReused(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "domestic_sse_lab_tls_root_ca.pem")

	// Stand up a root under the previous name by letting the Edge create one, then renaming both halves.
	first, err := NewNetworkExtensionLabTLSInterceptionWithPersistentRoot([]string{"example.com"}, time.Now,
		filepath.Join(dir, NetworkExtensionLabTLSRootCertFilename))
	if err != nil {
		t.Fatal(err)
	}
	before := string(first.rootCertPEM)
	for from, to := range map[string]string{
		filepath.Join(dir, NetworkExtensionLabTLSRootCertFilename):                                    legacy,
		NetworkExtensionLabTLSRootKeyPath(filepath.Join(dir, NetworkExtensionLabTLSRootCertFilename)): NetworkExtensionLabTLSRootKeyPath(legacy),
	} {
		if err := os.Rename(from, to); err != nil {
			t.Fatal(err)
		}
	}

	// Point at the DIRECTORY, as the exposed deployment shape does.
	second, err := NewNetworkExtensionLabTLSInterceptionWithPersistentRoot([]string{"example.com"}, time.Now, dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(second.rootCertPEM); got != before {
		t.Fatal("the root on disk must be reused under its previous name, not replaced by a new one")
	}
	if _, err := os.Stat(filepath.Join(dir, NetworkExtensionLabTLSRootCertFilename)); err == nil {
		t.Fatal("a second root must not be minted alongside the one devices already trust")
	}
}
