package main

import (
	"testing"
	"time"
)

// ★ EVERY OTHER ORGANIZATION'S API TOKENS WERE UNUSABLE (found 2026-08-16). The token lookup required the
// caller to already know which tenant the token belonged to, and the only caller passed the NODE's tenant —
// so an administrator of any other organization could sign in to the Console and then find every API token
// they minted answering "admin authentication is required". No automation, no scripted rotation, no CI, and a
// 401 that reads as a bad token.
//
// This is the SAME defect that was found and fixed for admin SESSIONS on 2026-08-15. The session lookup and
// the token lookup sit forty lines apart and had the same shape; only one of them was fixed, and the gate that
// should have caught the other asserted the broken shape as correct. Found while making the device CA
// tenant-manageable — the first test of "the customer can operate its own PKI" authenticates as that customer.
//
// The tenant filter was never the isolation control here: a token hash is an unguessable credential, holding
// it IS the authorisation, and the identity that comes back carries the token's own tenant, which is what
// every handler then scopes to.
func TestAnAPITokenOfAnotherTenantResolvesToItsOwnTenant(t *testing.T) {
	store := newAdminAuthStore()
	now := time.Now().UTC()
	store.UpsertPrincipal(adminPrincipal{
		ID: "adm_nw", TenantID: "tenant_northwind", Subject: "sub_nw", Email: "admin@northwind.invalid",
		Roles: []string{"admin"}, IDPID: "keycloak_lab", Status: "active",
		CreatedAt: now.Add(-time.Hour).Format(time.RFC3339),
	})
	store.UpsertAPIToken(adminAPIToken{
		ID: "tok_nw", TenantID: "tenant_northwind", Name: "northwind automation",
		TokenHash: adminTokenHash("northwind-raw-token"), Roles: []string{"admin"}, Scopes: []string{"*"},
		CreatedByAdminPrincipalID: "adm_nw",
		CreatedAt:                 now.Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt:                 now.Add(time.Hour).Format(time.RFC3339), Status: "active",
	})

	// No tenant given — the way the request path now asks, because it does not know whose token this is.
	identity, ok := store.IdentityForAPIToken("northwind-raw-token", "", now)
	if !ok {
		t.Fatal("a valid token of another organization did not authenticate at all")
	}
	if identity.TenantID != "tenant_northwind" {
		t.Fatalf("identity tenant = %q; the token's OWN tenant is what every handler scopes to", identity.TenantID)
	}

	// And an EXPLICIT tenant still filters, because that is a caller saying "this tenant's token" and is a
	// real isolation check the property tests rely on.
	if _, ok := store.IdentityForAPIToken("northwind-raw-token", "tenant_someone_else", now); ok {
		t.Fatal("a token was accepted for an organization it does not belong to")
	}

	// An unknown secret is still nothing, with or without a tenant.
	if _, ok := store.IdentityForAPIToken("not-a-real-token", "", now); ok {
		t.Fatal("an unknown token authenticated once the tenant filter was relaxed")
	}
}
