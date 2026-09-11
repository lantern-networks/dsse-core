package main

import (
	"errors"
	"testing"
	"time"
)

// ★ THE MEASURED DEFECT, HELD SHUT (2026-08-15). Invite() keyed on the email and overwrote whatever it
// found — tenant, roles, password — so inviting an address that already administered ANOTHER organization
// moved that principal into the caller's, erased its password, replaced its roles, and answered 201. It was
// reproduced on the lab in both directions before this was written. Inviting roles:["admin"] does not
// require admin.tenant.admin, so the whole thing was reachable by an ordinary tenant administrator who knew
// nothing but the address.
func TestInviteRefusesAnEmailThatBelongsToAnotherTenant(t *testing.T) {
	store := newLocalAdminCredentialStore("Lantern DSSE")
	now := time.Now()

	if _, err := store.Invite("shared@corp.example", "tenant_a", "adm_a", []string{"admin"}, now); err != nil {
		t.Fatalf("first invite: %v", err)
	}
	// Activate it, so the credential carries the state a real account would: a password and an active status.
	cred, ok := store.byEmail["shared@corp.example"]
	if !ok {
		t.Fatal("the first invite did not create a credential")
	}
	cred.PasswordHash = "not-empty"
	cred.Status = credentialStatusActive

	_, err := store.Invite("shared@corp.example", "tenant_b", "adm_b", []string{"auditor"}, now)
	if !errors.Is(err, errCredentialBelongsToAnotherTenant) {
		t.Fatalf("cross-tenant invite err = %v, want errCredentialBelongsToAnotherTenant", err)
	}

	// And nothing about the existing account moved. This is the half that mattered: the old behaviour did not
	// merely allow the invite, it took the account over.
	after := store.byEmail["shared@corp.example"]
	switch {
	case after.TenantID != "tenant_a":
		t.Fatalf("tenant = %q, want tenant_a — a refused invite must not move the account", after.TenantID)
	case after.PrincipalID != "adm_a":
		t.Fatalf("principal = %q, want adm_a", after.PrincipalID)
	case len(after.Roles) != 1 || after.Roles[0] != "admin":
		t.Fatalf("roles = %v, want [admin]", after.Roles)
	case after.PasswordHash != "not-empty":
		t.Fatal("the password was erased by a refused invite")
	case after.Status != credentialStatusActive:
		t.Fatalf("status = %q, want it untouched", after.Status)
	}
}

// Re-inviting an address that is already in THIS tenant stays allowed: that is how an administrator whose
// activation link expired or was lost gets a new one. The guard is about crossing tenants, not about
// inviting twice.
func TestInviteInTheSameTenantStillReissues(t *testing.T) {
	store := newLocalAdminCredentialStore("Lantern DSSE")
	now := time.Now()

	first, err := store.Invite("alice@corp.example", "tenant_a", "adm_a", []string{"admin"}, now)
	if err != nil {
		t.Fatalf("first invite: %v", err)
	}
	second, err := store.Invite("alice@corp.example", "tenant_a", "adm_a2", []string{"auditor"}, now)
	if err != nil {
		t.Fatalf("re-invite in the same tenant must be allowed: %v", err)
	}
	if first == second {
		t.Fatal("a re-invite must mint a fresh activation token")
	}
	if cred := store.byEmail["alice@corp.example"]; cred.TenantID != "tenant_a" || len(cred.Roles) != 1 || cred.Roles[0] != "auditor" {
		t.Fatalf("a same-tenant re-invite should update roles in place, got %#v", cred)
	}
}

// An address nobody has invited is free, and the comparison ignores case and padding the way an email does.
func TestInviteAcceptsAFreeAddressAndNormalisesTheTenantComparison(t *testing.T) {
	store := newLocalAdminCredentialStore("Lantern DSSE")
	now := time.Now()

	if _, err := store.Invite("new@corp.example", "tenant_a", "adm_1", []string{"admin"}, now); err != nil {
		t.Fatalf("inviting a free address: %v", err)
	}
	// Same tenant, differently spelled. This must NOT read as a cross-tenant collision, or an operator whose
	// header carries a stray space locks themselves out of their own organization.
	if _, err := store.Invite("new@corp.example", " Tenant_A ", "adm_1", []string{"admin"}, now); err != nil {
		t.Fatalf("same tenant with different spacing/case must be allowed: %v", err)
	}
}
