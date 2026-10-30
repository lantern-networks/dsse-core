package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRenewBeforeRejectsInvalidStoredDeclaration(t *testing.T) {
	for name, raw := range map[string]string{
		"truncated":    `{"schema_version":`,
		"null":         `null`,
		"empty":        `{}`,
		"wrong_schema": `{"schema_version":"future.v99","renew_certificates_issued_before":"2026-10-23T01:00:00Z"}`,
		"invalid_time": `{"schema_version":"admin_renew_before.v1","renew_certificates_issued_before":"invalid"}`,
		"duplicate":    `{"schema_version":"admin_renew_before.v1","renew_certificates_issued_before":"2026-10-23T01:00:00Z","renew_certificates_issued_before":""}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "renew.json")
			if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
			if s, err := newRenewBeforeSetting(path); err == nil || s != nil {
				t.Fatal("invalid stored declaration was accepted as a usable renewal setting")
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != raw {
				t.Fatalf("stored declaration changed: %q, %v", got, err)
			}
		})
	}
}

func mustRenewBeforeSetting(t *testing.T, path string) *renewBeforeSetting {
	t.Helper()
	s, err := newRenewBeforeSetting(path)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRenewBeforeRejectsUnreadableStoredDeclaration(t *testing.T) {
	if s, err := newRenewBeforeSetting(t.TempDir()); err == nil || s != nil {
		t.Fatal("unreadable stored declaration accepted")
	}
}
