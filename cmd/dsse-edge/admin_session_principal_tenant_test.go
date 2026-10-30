package main

import (
	"testing"
	"time"
)

func TestAdminSessionRejectsPrincipalFromAnotherTenantWithSameID(t *testing.T) {
	store := newAdminAuthStore()
	now := time.Now().UTC()
	store.UpsertPrincipal(adminPrincipal{ID: "shared-id", TenantID: "Acme", Status: "active"})
	store.UpsertSession(adminSession{
		ID: "acme-session", TenantID: "Acme", AdminPrincipalID: "shared-id",
		Roles: []string{"admin"}, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	})
	if _, ok := store.IdentityForSession("acme-session", "Acme", now); !ok {
		t.Fatal("same-tenant active principal did not support the session")
	}
	store.UpsertPrincipal(adminPrincipal{ID: "shared-id", TenantID: "acme", Status: "active"})
	if _, ok := store.IdentityForSession("acme-session", "Acme", now); ok {
		t.Fatal("another tenant's active principal kept the original tenant's session valid")
	}
}
