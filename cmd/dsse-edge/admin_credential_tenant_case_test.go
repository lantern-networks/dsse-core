package main

import (
	"errors"
	"testing"
	"time"
)

func TestCredentialInviteCannotMoveCaseDistinctTenant(t *testing.T) {
	s := newLocalAdminCredentialStore("test")
	now := time.Now().UTC()
	token, err := s.Invite("admin@example.test", "Acme", "upper", []string{"admin"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Invite("ADMIN@example.test", "acme", "lower", []string{"analyst"}, now); !errors.Is(err, errCredentialBelongsToAnotherTenant) {
		t.Fatalf("case-distinct tenant replaced an administrator: %v", err)
	}
	if _, err = s.ActivationEmail(token, now); err != nil {
		t.Fatalf("original invitation changed: %v", err)
	}
	rows := s.List("Acme")
	if len(rows) != 1 || rows[0].PrincipalID != "upper" {
		t.Fatal("original account changed")
	}
	if _, err = s.Invite("ADMIN@example.test", "Acme", "ignored", []string{"admin"}, now); err != nil {
		t.Fatalf("same-tenant reinvite rejected: %v", err)
	}
}

func TestCredentialPurgeKeepsCaseDistinctTenant(t *testing.T) {
	s := newLocalAdminCredentialStore("test")
	now := time.Now().UTC()
	for tenant, email := range map[string]string{"Acme": "upper@example.test", "acme": "lower@example.test"} {
		if _, err := s.Invite(email, tenant, tenant+"-admin", []string{"admin"}, now); err != nil {
			t.Fatal(err)
		}
	}
	removed, err := s.DeleteAllForTenant("Acme")
	if err != nil || len(removed) != 1 || removed[0] != "upper@example.test" {
		t.Fatalf("wrong accounts removed: %v, %v", removed, err)
	}
	if len(s.List("acme")) != 1 {
		t.Fatal("case-distinct tenant lost its administrator")
	}
}
