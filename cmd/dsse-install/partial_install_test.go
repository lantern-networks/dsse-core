package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIncompleteInitialInstallCannotReportSuccessOnRetry(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "schemas")
	if err := os.WriteFile(blocker, []byte("blocks schema directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err == nil {
		t.Fatal("initial install unexpectedly succeeded despite blocked schema directory")
	}
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("retry must identify an incomplete install, got %v", err)
	}
}
