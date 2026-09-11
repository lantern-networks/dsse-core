package main

import (
	"context"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// ★ THE MEASURED DEFECT (2026-08-15). Deleting an organization on the control plane removed it there and
// nowhere else. The bundle's tenant section UPSERTs — on purpose, because an absent entry is indistinguishable
// from a truncated payload or a control plane that is not the authority for tenants — so nothing in it could
// say "this one is gone". On the lab the control plane listed 2 tenants and the Edge listed 5, and the three
// ghosts came off only by editing the Edge's file by hand.
//
// The fix carries the deletion by name. This test is the whole claim: delete on the authority, and the Edge
// stops holding it.
func TestDeletingATenantOnTheAuthorityRemovesItFromTheEdge(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	authority := newAdminTenantModelStore(model.PolicyBundle{}, now)
	edge := newAdminTenantModelStore(model.PolicyBundle{}, now)
	for _, id := range []string{"tenant_acme", "tenant_globex"} {
		if _, err := authority.Put(ctx, adminTenantModel{TenantID: id, DisplayName: id, Status: "active"}, now); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	syncTenantSection(t, authority, edge, now)
	if got := tenantIDsOf(t, edge); len(got) != 2 {
		t.Fatalf("the Edge should hold both tenants before the deletion, got %v", got)
	}

	if err := authority.Delete(ctx, "tenant_globex"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	syncTenantSection(t, authority, edge, now)

	got := tenantIDsOf(t, edge)
	if len(got) != 1 || got[0] != "tenant_acme" {
		t.Fatalf("the Edge still holds %v — a deletion on the authority must reach it", got)
	}
}

// Absence must still mean nothing. This is the property the UPSERT was protecting and the tombstone must not
// cost us: a bundle whose tenant list is empty (a control plane that is not the tenant authority, or a payload
// that was built without the section) leaves the Edge's tenants alone.
func TestAnEmptyTenantListStillDeletesNothing(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	edge := newAdminTenantModelStore(model.PolicyBundle{}, now)
	if _, err := edge.Put(ctx, adminTenantModel{TenantID: "tenant_acme", DisplayName: "Acme", Status: "active"}, now); err != nil {
		t.Fatalf("seed: %v", err)
	}

	targets := configApplyTargets{tenantModels: edge}
	if _, err := (configBundleSource{}).apply(configBundlePayload{Tenants: &tenantModelBundle{}}, targets); err != nil {
		t.Fatalf("apply: %v", err)
	}

	if got := tenantIDsOf(t, edge); len(got) != 1 {
		t.Fatalf("an empty tenant section deleted something: %v", got)
	}
}

// A tenant named as BOTH present and deleted is a contradiction, not an instruction. Keeping it is the safe
// reading: a wrongly-kept tenant is visible and fixable, a wrongly-deleted one is neither.
func TestATenantSentAsBothPresentAndDeletedIsKept(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	edge := newAdminTenantModelStore(model.PolicyBundle{}, now)
	if _, err := edge.Put(ctx, adminTenantModel{TenantID: "tenant_acme", DisplayName: "Acme", Status: "active"}, now); err != nil {
		t.Fatalf("seed: %v", err)
	}

	targets := configApplyTargets{tenantModels: edge}
	payload := configBundlePayload{Tenants: &tenantModelBundle{
		Tenants: []adminTenantModel{{TenantID: "tenant_acme", DisplayName: "Acme", Status: "active"}},
		Deleted: []tenantDeletion{{TenantID: "tenant_acme", DeletedAt: now.Format(time.RFC3339)}},
	}}
	if _, err := (configBundleSource{}).apply(payload, targets); err != nil {
		t.Fatalf("apply: %v", err)
	}

	if got := tenantIDsOf(t, edge); len(got) != 1 || got[0] != "tenant_acme" {
		t.Fatalf("a contradictory payload deleted the tenant: %v", got)
	}
}

// Lockout protection, the same one the control plane's own DELETE route enforces with 409: the operator tenant
// backs cross-tenant administration, so an Edge must refuse to delete it however the instruction arrives.
func TestTheOperatorTenantIsNeverDeletedByABundle(t *testing.T) {
	now := time.Now().UTC()
	edge := newOperatorAwareAdminTenantModelStore(model.PolicyBundle{}, now, "", "tenant_operator")

	targets := configApplyTargets{tenantModels: edge}
	payload := configBundlePayload{Tenants: &tenantModelBundle{
		Deleted: []tenantDeletion{{TenantID: "tenant_operator", DeletedAt: now.Format(time.RFC3339)}},
	}}
	if _, err := (configBundleSource{}).apply(payload, targets); err != nil {
		t.Fatalf("apply: %v", err)
	}

	if got := tenantIDsOf(t, edge); len(got) != 1 || got[0] != "tenant_operator" {
		t.Fatalf("the operator tenant was deleted by a bundle (%v) — that strands cross-tenant administration", got)
	}
}

// Re-creating a tenant supersedes its deletion. Without this the tombstone outlives the delete and the next
// bundle asks every Edge to remove the tenant that was just created.
func TestRecreatingATenantClearsItsTombstone(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	authority := newAdminTenantModelStore(model.PolicyBundle{}, now)

	if _, err := authority.Put(ctx, adminTenantModel{TenantID: "tenant_acme", DisplayName: "Acme", Status: "active"}, now); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := authority.Delete(ctx, "tenant_acme"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if len(authority.DeletedTenants()) != 1 {
		t.Fatal("the deletion was not recorded, so it could never be carried")
	}
	if _, err := authority.Put(ctx, adminTenantModel{TenantID: "tenant_acme", DisplayName: "Acme", Status: "active"}, now); err != nil {
		t.Fatalf("re-create: %v", err)
	}
	if got := authority.DeletedTenants(); len(got) != 0 {
		t.Fatalf("the tombstone survived re-creation: %v", got)
	}
}

// The tombstone has to outlive a restart. If it does not, the control plane simply stops mentioning a deletion
// an Edge had not yet applied, and the tenant lives on there forever — the original defect, restored by a
// process restart.
func TestTombstonesSurviveARestart(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	path := t.TempDir() + "/tenant_models.json"

	first := newDurableAdminTenantModelStore(model.PolicyBundle{}, now, path)
	if _, err := first.Put(ctx, adminTenantModel{TenantID: "tenant_acme", DisplayName: "Acme", Status: "active"}, now); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := first.Delete(ctx, "tenant_acme"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	restarted := newDurableAdminTenantModelStore(model.PolicyBundle{}, now, path)
	got := restarted.DeletedTenants()
	if len(got) != 1 || got[0].TenantID != "tenant_acme" {
		t.Fatalf("after a restart the deletion is no longer carried: %v", got)
	}
}

// Deleting a tenant the authority no longer has is the GHOST case — the control plane lost it (or never had
// it) while an Edge still serves it. Recording the deletion anyway is the only way an operator can say so.
func TestDeletingAnAbsentTenantStillCarriesTheDeletion(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	authority := newAdminTenantModelStore(model.PolicyBundle{}, now)

	if err := authority.Delete(ctx, "tenant_ghost"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	got := authority.DeletedTenants()
	if len(got) != 1 || got[0].TenantID != "tenant_ghost" {
		t.Fatalf("deleting an absent tenant recorded nothing (%v) — the ghost on the Edge stays forever", got)
	}
}

// syncTenantSection copies the authority's tenant section into the Edge exactly as the config bundle does:
// the full list, plus the carried deletions.
func syncTenantSection(t *testing.T, authority *adminTenantModelStore, edge *adminTenantModelStore, now time.Time) {
	t.Helper()
	tenants, err := authority.List(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	payload := configBundlePayload{Tenants: &tenantModelBundle{Tenants: tenants, Deleted: authority.DeletedTenants()}}
	if _, err := (configBundleSource{}).apply(payload, configApplyTargets{tenantModels: edge}); err != nil {
		t.Fatalf("apply: %v", err)
	}
}

func tenantIDsOf(t *testing.T, store *adminTenantModelStore) []string {
	t.Helper()
	tenants, err := store.List(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	out := make([]string, 0, len(tenants))
	for _, tenant := range tenants {
		out = append(out, tenant.TenantID)
	}
	return out
}
