package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Tests for the file-backed credentialPersistence (admin_local_credential_file.go). Secret material (password
// hash, TOTP secret) is round-trip-checked but NEVER printed — assertions compare and report the field NAME only.

func newTestFileCredential() *localAdminCredential {
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	return &localAdminCredential{
		PrincipalID:         "prn-abc",
		TenantID:            "tenant-1",
		Email:               "admin@example.com",
		Roles:               []string{"owner", "auditor"},
		Status:              credentialStatusActive,
		PasswordHash:        "$2a$12$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
		TOTPSecret:          "JBSWY3DPEHPK3PXP",
		TOTPEnrolled:        true,
		RecoveryCodeHashes:  []string{"$2a$12$recoveryhashone", "$2a$12$recoveryhashtwo"},
		FailedAttempts:      2,
		ActivationTokenHash: "tok-hash",
		CreatedAt:           now,
		UpdatedAt:           now,
	}
}

// TestLocalCredentialFilePersistenceRestartSurvival proves a credential written through one file-backed
// persistence is returned by LoadAll on a FRESH instance over the same file (i.e. survives an Edge restart), and
// that the round-trip preserves the password hash and TOTP secret exactly.
func TestLocalCredentialFilePersistenceRestartSurvival(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creds.json")
	ctx := context.Background()

	writer := newFileCredentialPersistence(path)
	if _, err := writer.LoadAll(ctx); err != nil { // first boot: missing file => empty, no error
		t.Fatalf("LoadAll on missing file: %v", err)
	}
	want := newTestFileCredential()
	if err := writer.Upsert(ctx, want); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// Fresh instance over the same file == a restart with a cold in-memory store.
	reader := newFileCredentialPersistence(path)
	got, err := reader.LoadAll(ctx)
	if err != nil {
		t.Fatalf("LoadAll after restart: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 credential after restart, got %d", len(got))
	}
	c := got[0]
	if c.Email != want.Email || c.TenantID != want.TenantID || c.PrincipalID != want.PrincipalID {
		t.Fatalf("identity fields not preserved: email/tenant/principal mismatch")
	}
	if c.Status != want.Status || c.TOTPEnrolled != want.TOTPEnrolled || c.FailedAttempts != want.FailedAttempts {
		t.Fatalf("scalar fields not preserved after restart")
	}
	if len(c.Roles) != 2 || c.Roles[0] != "owner" || c.Roles[1] != "auditor" {
		t.Fatalf("roles not preserved after restart")
	}
	// Durability must not corrupt secrets. Compare values; report only field names on failure.
	if c.PasswordHash != want.PasswordHash {
		t.Fatalf("password hash not preserved exactly across restart")
	}
	if c.TOTPSecret != want.TOTPSecret {
		t.Fatalf("TOTP secret not preserved exactly across restart")
	}
	if len(c.RecoveryCodeHashes) != len(want.RecoveryCodeHashes) {
		t.Fatalf("recovery code hashes not preserved across restart")
	}
	for i := range want.RecoveryCodeHashes {
		if c.RecoveryCodeHashes[i] != want.RecoveryCodeHashes[i] {
			t.Fatalf("recovery code hash %d not preserved across restart", i)
		}
	}
}

// TestLocalCredentialFilePersistenceDeletePersists proves a Delete is durable: after deleting through one
// instance, a fresh instance does not see the account.
func TestLocalCredentialFilePersistenceDeletePersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creds.json")
	ctx := context.Background()

	p := newFileCredentialPersistence(path)
	if _, err := p.LoadAll(ctx); err != nil {
		t.Fatalf("initial LoadAll: %v", err)
	}
	cred := newTestFileCredential()
	if err := p.Upsert(ctx, cred); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := p.Delete(ctx, cred.TenantID, cred.Email); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	reader := newFileCredentialPersistence(path)
	got, err := reader.LoadAll(ctx)
	if err != nil {
		t.Fatalf("LoadAll after delete: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 credentials after delete+restart, got %d", len(got))
	}
}

// TestLocalCredentialFilePersistenceDeleteTenantScoped proves a delete never reaches across tenants: a delete
// with the wrong tenant id leaves the account intact (parity with the Postgres email+tenant_id predicate).
func TestLocalCredentialFilePersistenceDeleteTenantScoped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creds.json")
	ctx := context.Background()

	p := newFileCredentialPersistence(path)
	if _, err := p.LoadAll(ctx); err != nil {
		t.Fatalf("initial LoadAll: %v", err)
	}
	cred := newTestFileCredential()
	if err := p.Upsert(ctx, cred); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := p.Delete(ctx, "some-other-tenant", cred.Email); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	got, err := newFileCredentialPersistence(path).LoadAll(ctx)
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("cross-tenant delete should not remove the account; got %d accounts", len(got))
	}
}

// TestLocalCredentialFilePersistenceEmptyAndParse proves first-boot (missing/empty file) returns an empty slice
// with no error, and that a corrupt snapshot is returned as an error (fail-closed) rather than silently emptied.
func TestLocalCredentialFilePersistenceEmptyAndParse(t *testing.T) {
	ctx := context.Background()

	// Missing file.
	missing := newFileCredentialPersistence(filepath.Join(t.TempDir(), "creds.json"))
	if got, err := missing.LoadAll(ctx); err != nil || len(got) != 0 {
		t.Fatalf("missing file: want empty/no-error, got len=%d err=%v", len(got), err)
	}

	// Corrupt file => parse error returned (fail-closed).
	corruptPath := filepath.Join(t.TempDir(), "creds.json")
	if err := os.WriteFile(corruptPath, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write corrupt file: %v", err)
	}
	if _, err := newFileCredentialPersistence(corruptPath).LoadAll(ctx); err == nil {
		t.Fatalf("corrupt snapshot must fail closed, got nil error")
	}
}
