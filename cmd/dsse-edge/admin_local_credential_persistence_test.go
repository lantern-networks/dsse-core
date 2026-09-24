package main

import (
	"context"
	"testing"
	"time"
)

// fakeCredentialPersistence is an in-memory stand-in for the Postgres backing store, so the durability
// (write-through + load-on-startup) logic is testable without a database.
type fakeCredentialPersistence struct {
	rows map[string]*localAdminCredential
}

func newFakeCredentialPersistence() *fakeCredentialPersistence {
	return &fakeCredentialPersistence{rows: map[string]*localAdminCredential{}}
}

func (f *fakeCredentialPersistence) LoadAll(context.Context) ([]*localAdminCredential, error) {
	out := make([]*localAdminCredential, 0, len(f.rows))
	for _, c := range f.rows {
		cp := *c // copy so the store cannot alias the backing row
		cp.Roles = append([]string(nil), c.Roles...)
		cp.RecoveryCodeHashes = append([]string(nil), c.RecoveryCodeHashes...)
		out = append(out, &cp)
	}
	return out, nil
}

func (f *fakeCredentialPersistence) Upsert(_ context.Context, c *localAdminCredential) error {
	cp := *c
	cp.Roles = append([]string(nil), c.Roles...)
	cp.RecoveryCodeHashes = append([]string(nil), c.RecoveryCodeHashes...)
	f.rows[credentialEmailKey(c.Email)] = &cp
	return nil
}

func (f *fakeCredentialPersistence) Delete(_ context.Context, tenantID, email string, _ int64) error {
	key := credentialEmailKey(email)
	if row, ok := f.rows[key]; ok && row.TenantID == tenantID {
		delete(f.rows, key)
	}
	return nil
}

// TestCredentialStoreSurvivesRestart exercises the exact failure the user hit: a control-plane restart must
// not lose an activated admin account. Activate fully against one store (write-through), then build a NEW
// store from the same persistence (a "restart") and confirm login still works.
func TestCredentialStoreSurvivesRestart(t *testing.T) {
	p := newFakeCredentialPersistence()
	now := time.Now().UTC()
	email := "nagi@example.com"
	password := "lab-admin-passphrase-2026"

	s1, err := newLocalAdminCredentialStoreWithPersistence("Lantern DSSE", p)
	if err != nil {
		t.Fatal(err)
	}
	token, err := s1.Invite(email, "tenant_x", "adm_1", []string{"admin"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.SetActivationPassword(token, password, now); err != nil {
		t.Fatal(err)
	}
	secret, _, err := s1.BeginTOTPEnrollment(token, now)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := totpCodeForCounter(secret, uint64(now.Unix())/totpPeriod)
	if _, err := s1.CompleteActivation(token, code, now); err != nil {
		t.Fatal(err)
	}

	// persistence must now hold the activated account
	if got := len(p.rows); got != 1 {
		t.Fatalf("persistence rows = %d, want 1", got)
	}

	// "restart": a brand-new store loaded from the same durable persistence
	s2, err := newLocalAdminCredentialStoreWithPersistence("Lantern DSSE", p)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := s2.VerifyPassword(email, password, now)
	if err != nil {
		t.Fatalf("password login after restart failed: %v", err)
	}
	if cred.PrincipalID != "adm_1" || cred.Status != credentialStatusActive {
		t.Fatalf("restored credential wrong: %+v", cred)
	}
	code2, _ := totpCodeForCounter(secret, uint64(now.Unix())/totpPeriod)
	if _, err := s2.VerifyTOTP(email, code2, now); err != nil {
		t.Fatalf("TOTP login after restart failed: %v", err)
	}
}

// TestCredentialStoreNilPersistenceIsMemoryOnly confirms back-compat: a nil persistence behaves like the
// in-memory store and does not panic on mutations.
func TestCredentialStoreNilPersistenceIsMemoryOnly(t *testing.T) {
	s, err := newLocalAdminCredentialStoreWithPersistence("Lantern DSSE", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Invite("x@y.com", "t", "p", []string{"admin"}, time.Now()); err != nil {
		t.Fatal(err)
	}
}
