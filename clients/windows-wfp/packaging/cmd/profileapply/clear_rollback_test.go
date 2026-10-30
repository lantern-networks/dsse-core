package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUninstallClearsTornPackagesAndOrphanMarkers(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"dsse-agent-1.0.0.msi", "dsse-agent-0.9.0.msi.accepts-rollback-intent", "foreign.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		if err := clearRollbackPackages(dir); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "foreign.txt" {
		t.Fatalf("%v %v", entries, err)
	}
}

func TestUninstallRollbackStoreRefusesAmbiguousPackageDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "dsse-agent-1.0.0.msi"), 0700); err != nil {
		t.Fatal(err)
	}
	err := clearRollbackPackages(dir)
	if err == nil || !strings.Contains(err.Error(), "material remains") {
		t.Fatal(err)
	}
	if err := clearRollbackPackages(filepath.Join(dir, "absent")); err != nil {
		t.Fatal(err)
	}
}
