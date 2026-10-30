package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestBundleReadFailureKeepsExistingSigningMaterial(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "authority"), 0700); err != nil {
		t.Fatal(err)
	}
	paths := []string{authorityPath(dir, "bundle-signing.key"), filepath.Join(dir, "bundle-signing.pub")}
	for _, path := range paths {
		if err := os.WriteFile(path, []byte("existing signing material\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// A present but unreadable-as-a-document path is not a fresh installation.
	if err := os.Mkdir(filepath.Join(dir, "policy-bundle.json"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeBundle(dir); err == nil {
		t.Fatal("unreadable bundle accepted")
	}
	for _, path := range paths {
		body, err := os.ReadFile(path)
		if err != nil || string(body) != "existing signing material\n" {
			t.Errorf("bundle read failure changed %s", filepath.Base(path))
		}
	}
}

func TestEnvironmentReplacementPublishesPrivateFileWithoutRewritingOldInode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "deployment.env")
	old := "# retained comment\nEDGE_CP_TOKEN=old-token\nUNCHANGED=value\n"
	if err := os.WriteFile(path, []byte(old), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	previous := filepath.Join(dir, "previous-env")
	if err := os.Link(path, previous); err != nil {
		t.Fatal(err)
	}
	if err := replaceEnvValue(path, "EDGE_CP_TOKEN", "new-token"); err != nil {
		t.Fatal(err)
	}
	prior, err := os.ReadFile(previous)
	if err != nil || string(prior) != old {
		t.Error("replacement rewrote the old inode instead of publishing a complete new file")
	}
	body, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(body), "EDGE_CP_TOKEN=new-token\n") || !strings.Contains(string(body), "UNCHANGED=value\n") {
		t.Fatal("replacement did not preserve the remaining configuration")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Errorf("secret-bearing environment mode=%o, want 0600", info.Mode().Perm())
	}
}
