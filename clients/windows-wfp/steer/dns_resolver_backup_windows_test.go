//go:build windows

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestResolverBackupLockRefusesConcurrentOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backup.json")
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- withDNSBackupLock(path, func() error { close(entered); <-release; return nil })
	}()
	<-entered
	if err := withDNSBackupLock(path, func() error { t.Fatal("second owner entered critical section"); return nil }); err == nil {
		t.Fatal("concurrent DNS backup owner accepted")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// These tests only exercise backup files. They never modify system DNS.
func TestResolverBackupNoReplaceAndVerifiedRemoval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backup.json")
	first := []resolverEntry{{IfIndex: "1", Family: "IPv4", Loopback: "127.0.0.1", Servers: "192.0.2.1"}}
	owner := &resolverManager{backup: path}
	if err := owner.publishSnapshot(first); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if entries, err := decodeResolverBackup(original); err != nil || len(entries) != 1 {
		t.Fatalf("published backup invalid: count=%d, err=%v", len(entries), err)
	}
	other := &resolverManager{backup: path}
	if err := other.publishSnapshot([]resolverEntry{{IfIndex: "2", Family: "IPv4", Loopback: "127.0.0.1", Servers: "192.0.2.2"}}); err == nil {
		t.Fatal("second first-writer replaced an existing original")
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, original) {
		t.Fatal("existing original changed after refused publication")
	}
	second := append(first, resolverEntry{IfIndex: "3", Family: "IPv6", Loopback: "::1", Servers: "2001:db8::1"})
	if err := owner.publishSnapshot(second); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(path); err != nil || bytes.Equal(got, original) {
		t.Fatal("owner's replacement was not published")
	}
	if err := owner.removeSnapshot(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("verified backup still present: %v", err)
	}
}

func TestResolverBackupRejectsChangedOrInvalidOriginal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backup.json")
	owner := &resolverManager{backup: path}
	first := []resolverEntry{{IfIndex: "1", Family: "IPv4", Loopback: "127.0.0.1", Servers: "192.0.2.1"}}
	if err := owner.publishSnapshot(first); err != nil {
		t.Fatal(err)
	}
	other := []byte(`{"entries":[{"ifIndex":"2","family":"IPv4","loopback":"127.0.0.1","servers":"192.0.2.2"}]}`)
	if err := os.WriteFile(path, other, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := owner.publishSnapshot(first); err == nil {
		t.Fatal("changed original accepted")
	}
	if err := owner.removeSnapshot(); err == nil {
		t.Fatal("changed original removed")
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, other) {
		t.Fatal("changed original was not preserved")
	}
	if _, err := decodeResolverBackup([]byte("broken backup")); err == nil {
		t.Fatal("invalid backup accepted")
	}
}
