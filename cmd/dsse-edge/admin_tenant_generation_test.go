package main

import (
	"context"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// ★ THE MEASURED DEFECT (2026-08-15). The config bundle carries the tenant registry, and an Edge applies a
// bundle only when its generation is newer than the one it last applied. That generation is the SUM of every
// distributed store's counter — and the tenant store had no counter at all. So creating an organization
// changed the bundle's CONTENTS without changing its VERSION, and no Edge re-pulled for it: the registry row
// reached an Edge only by coincidence, when some unrelated store moved the sum or a restart forced a full
// pull. On the lab, an organization created on the control plane was still absent from the Edge a minute
// later, while an earlier one was present because a rebuild had restarted that Edge in between.
func TestTenantRegistryChangesAdvanceTheConfigGeneration(t *testing.T) {
	store := newAdminTenantModelStore(model.PolicyBundle{}, time.Now())
	ctx := context.Background()
	start := store.ConfigGeneration()

	if _, err := store.Put(ctx, adminTenantModel{TenantID: "tenant_acme", DisplayName: "Acme", Status: "active"}, time.Now()); err != nil {
		t.Fatalf("create: %v", err)
	}
	afterCreate := store.ConfigGeneration()
	if afterCreate <= start {
		t.Fatalf("creating an organization must advance the generation (%d -> %d); without it no Edge re-pulls",
			start, afterCreate)
	}

	if _, err := store.Update(ctx, adminTenantModel{TenantID: "tenant_acme", DisplayName: "Acme Corp", Status: "active"}, "tenant_acme", time.Now()); err != nil {
		t.Fatalf("update: %v", err)
	}
	afterUpdate := store.ConfigGeneration()
	if afterUpdate <= afterCreate {
		t.Fatalf("renaming an organization must advance the generation (%d -> %d)", afterCreate, afterUpdate)
	}

	if err := store.Delete(ctx, "tenant_acme"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if afterDelete := store.ConfigGeneration(); afterDelete <= afterUpdate {
		t.Fatalf("deleting an organization must advance the generation (%d -> %d)", afterUpdate, afterDelete)
	}
}

// The counter must not depend on whether a durable path happens to be configured. persistLocked returns
// early for a memory-only store, so bumping inside it would make a memory-backed control plane distribute
// nothing while reporting success — the same class of defect one level down.
func TestTenantGenerationAdvancesWithoutADurablePath(t *testing.T) {
	memory := newAdminTenantModelStore(model.PolicyBundle{}, time.Now()) // no path
	if memory.path != "" {
		t.Fatalf("this test needs a memory-only store, got path %q", memory.path)
	}
	before := memory.ConfigGeneration()
	if _, err := memory.Put(context.Background(), adminTenantModel{TenantID: "t1", DisplayName: "T1", Status: "active"}, time.Now()); err != nil {
		t.Fatalf("put: %v", err)
	}
	if memory.ConfigGeneration() <= before {
		t.Fatal("a memory-only store must still advance its generation")
	}
}

// Reading must not advance it: a generation that moves when nothing changed makes every Edge re-apply on
// every poll, which is the opposite failure and just as wrong.
func TestReadsDoNotAdvanceTheTenantGeneration(t *testing.T) {
	store := newAdminTenantModelStore(model.PolicyBundle{}, time.Now())
	ctx := context.Background()
	if _, err := store.Put(ctx, adminTenantModel{TenantID: "t1", DisplayName: "T1", Status: "active"}, time.Now()); err != nil {
		t.Fatalf("put: %v", err)
	}
	settled := store.ConfigGeneration()
	if _, err := store.Get(ctx, "t1"); err != nil {
		t.Fatalf("get: %v", err)
	}
	if _, err := store.List(ctx); err != nil {
		t.Fatalf("list: %v", err)
	}
	if _, err := store.Get(ctx, "a-tenant-that-does-not-exist"); err != nil {
		t.Fatalf("get missing: %v", err)
	}
	if now := store.ConfigGeneration(); now != settled {
		t.Fatalf("reads advanced the generation (%d -> %d)", settled, now)
	}
}
