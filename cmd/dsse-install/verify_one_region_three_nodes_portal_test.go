package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOneRegionThreeNodesRejectsMissingOrInvalidBrowserPortalCertificate(t *testing.T) {
	dir := t.TempDir()
	env := map[string]string{"DSSE_NODE_PORTAL_NAME": "portal-a.example.test"}
	if got := verifyOneRegionThreeNodesPortalCertificate(dir, env); got.ok || !strings.Contains(got.note, "read browser certificate") {
		t.Fatalf("missing browser certificate passed: %+v", got)
	}
	if err := os.MkdirAll(filepath.Join(dir, "clientless"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "clientless", "tls.crt"), []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "clientless", "tls.key"), []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := verifyOneRegionThreeNodesPortalCertificate(dir, env); got.ok || !strings.Contains(got.note, "certificate/key pair") {
		t.Fatalf("invalid browser certificate passed: %+v", got)
	}
}
