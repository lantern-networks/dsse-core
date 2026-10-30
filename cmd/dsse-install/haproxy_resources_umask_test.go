//go:build darwin || linux

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestHAProxyResourceEntrypointWithPrivateUmask(t *testing.T) {
	dir := t.TempDir()
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	path := filepath.Join(dir, "haproxy-resource-entrypoint.sh")

	if err := writeHAProxyResourceEntrypoint(dir, false); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("new launcher must be container-readable: info=%v err=%v", info, err)
	}

	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeHAProxyResourceEntrypoint(dir, false); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("unchanged generated launcher must be repaired: info=%v err=%v", info, err)
	}

	if err := os.WriteFile(path, []byte("#!/bin/sh\n# operator replacement\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeHAProxyResourceEntrypoint(dir, false); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("operator replacement must retain its mode: info=%v err=%v", info, err)
	}
}
