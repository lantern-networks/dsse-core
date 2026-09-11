package main

import (
	"context"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// ★ THE MEASURED DEFECT (2026-08-15). Authentication never consulted the tenant registry, so deleting an
// organization did not touch its administrators: tenant_delprobe2 was removed from the control plane and both
// Edges, and its administrator logged in seconds later carrying a tenant_id no plane had heard of. The account
// could not even be cleaned up afterwards — "cannot delete the last administrator able to manage admins in
// this tenant" is an invariant that outlived the tenant, so deleting the organization locked the orphan in.
func TestAnAdministratorOfADeletedTenantIsRefused(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	store := newAdminTenantModelStore(model.PolicyBundle{}, now)
	if _, err := store.Put(ctx, adminTenantModel{TenantID: "tenant_acme", DisplayName: "Acme", Status: "active"}, now); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if _, refuse := adminTenantIsGone(ctx, store, "tenant_acme"); refuse {
		t.Fatal("an administrator of a tenant that exists must be let in")
	}
	reason, refuse := adminTenantIsGone(ctx, store, "tenant_delprobe2")
	if !refuse {
		t.Fatal("an administrator of a tenant that is not in the registry must be refused")
	}
	if reason == "" {
		t.Fatal("the refusal must say why — a login that fails without a reason is unsupportable")
	}
}

// The refusal must never fire on "I cannot tell". A node whose registry failed to load, or which is not the
// tenant authority at all, enumerates nothing — and reading that as "every tenant was deleted" would lock
// every administrator out of the control plane, which is far worse than the defect being fixed. This is the
// same reading the config bundle gives an empty tenant section.
func TestAnEmptyOrNarrowRegistryNeverRefusesALogin(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	empty := newAdminTenantModelStore(model.PolicyBundle{}, now)
	if _, refuse := adminTenantIsGone(ctx, empty, "tenant_acme"); refuse {
		t.Fatal("an empty registry means this node is not the tenant authority, not that every tenant is gone")
	}
	if _, refuse := adminTenantIsGone(ctx, nil, "tenant_acme"); refuse {
		t.Fatal("no registry at all cannot testify to an absence")
	}
	if _, refuse := adminTenantIsGone(ctx, narrowTenantStore{}, "tenant_acme"); refuse {
		t.Fatal("a store that cannot enumerate cannot testify to an absence")
	}
}

// narrowTenantStore satisfies only the self-scoped contract: it can answer about one tenant and cannot list.
type narrowTenantStore struct{}

func (narrowTenantStore) Get(context.Context, string) (adminTenantModel, error) {
	return adminTenantModel{}, nil
}

func (narrowTenantStore) Update(context.Context, adminTenantModel, string, time.Time) (adminTenantModel, error) {
	return adminTenantModel{}, nil
}

// ★ THE MEASURED DEFECT (2026-08-15). An administrator of any organization OTHER than the node's own could
// sign in, receive a session cookie, and then be told "admin authentication is required" on every request
// carrying it. The session lookup was scoped to a tenant the caller had to supply, and the only caller passed
// the NODE's tenant — so a session minted for another organization could never be found.
//
// It was hit twice before the cause was located: once for a customer tenant's administrator, and again for
// the OPERATOR account, which by design lives in its own tenant. That second one makes the whole
// operator-separation runbook unusable — the account it tells you to create cannot use the console.
func TestASessionResolvesRegardlessOfWhichTenantTheNodeServes(t *testing.T) {
	auth := newAdminAuthStore()
	now := time.Now().UTC()
	auth.UpsertPrincipal(adminPrincipal{
		ID: "adm_ops", TenantID: "tenant_operator_001", Subject: "ops", Email: "ops@example.invalid",
		Roles: []string{"super_admin"}, IDPID: "first_party", Status: "active",
		CreatedAt: now.Add(-time.Hour).Format(time.RFC3339),
	})
	auth.UpsertSession(adminSession{
		ID: "admin_sess_ops", TenantID: "tenant_operator_001", AdminPrincipalID: "adm_ops",
		Status: "active", CreatedAt: now.Format(time.RFC3339),
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	})

	// How the middleware asks now: by session id alone.
	identity, ok := auth.IdentityForSession("admin_sess_ops", "", now)
	if !ok {
		t.Fatal("the operator's session did not resolve — that administrator cannot use the console at all")
	}
	if identity.TenantID != "tenant_operator_001" {
		t.Fatalf("the identity carries tenant %q; it must carry the SESSION's tenant, never the node's", identity.TenantID)
	}

	// And a session id that does not exist still resolves to nothing.
	if _, ok := auth.IdentityForSession("admin_sess_not_a_session", "", now); ok {
		t.Fatal("an unknown session id resolved to an identity")
	}
	// A caller that DOES name a tenant still gets the filter, so nothing that relied on it changed shape.
	if _, ok := auth.IdentityForSession("admin_sess_ops", "tenant_someone_else", now); ok {
		t.Fatal("naming the wrong tenant still resolved the session")
	}
}
