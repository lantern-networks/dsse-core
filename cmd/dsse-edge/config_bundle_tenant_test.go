package main

import (
	"context"

	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// The control plane is the tenant authority and the Edge receives the model here. Two silent failures in one
// afternoon came from the same tenant existing independently on both planes: a timezone stored on the Edge that
// never reached the session, and one tenant showing three different names across three surfaces.
func TestTheBundleCarriesTheTenantModelFromTheControlPlane(t *testing.T) {
	store := newAdminTenantModelStore(model.PolicyBundle{TenantID: "tenant_a"}, time.Now())
	targets := configApplyTargets{tenantModels: store}
	now := time.Now()

	src := configBundleSource{}
	_, _ = src.apply(configBundlePayload{Tenants: &tenantModelBundle{Tenants: []adminTenantModel{
		{TenantID: "tenant_a", DisplayName: "Acme", Timezone: "Asia/Tokyo", Status: "active"},
	}}}, targets)

	got, err := store.Get(context.Background(), "tenant_a")
	if err != nil {
		t.Fatalf("the tenant must arrive: %v", err)
	}
	if got.DisplayName != "Acme" || got.Timezone != "Asia/Tokyo" {
		t.Fatalf("the model must arrive intact: %+v", got)
	}
	_ = now
}

// Same rule as every other section: an empty one almost always means this CP is not the authority for that,
// not that every tenant was deleted.
func TestAnEmptyTenantSectionDoesNotWipeLocalTenants(t *testing.T) {
	store := newAdminTenantModelStore(model.PolicyBundle{TenantID: "tenant_a"}, time.Now())
	store.Put(context.Background(), adminTenantModel{TenantID: "tenant_a", DisplayName: "Acme", Status: "active"}, time.Now())
	targets := configApplyTargets{tenantModels: store}

	configBundleSource{}.apply(configBundlePayload{Tenants: &tenantModelBundle{}}, targets)

	if _, err := store.Get(context.Background(), "tenant_a"); err != nil {
		t.Fatalf("an empty section must not delete tenants: %v", err)
	}
}

// A CP that does not know about tenants must leave the Edge alone rather than clearing it — the same fail-safe
// the other sections use for an older control plane.
func TestAnAbsentTenantSectionLeavesTheEdgeUntouched(t *testing.T) {
	store := newAdminTenantModelStore(model.PolicyBundle{TenantID: "tenant_a"}, time.Now())
	store.Put(context.Background(), adminTenantModel{TenantID: "tenant_a", DisplayName: "Acme", Status: "active"}, time.Now())
	targets := configApplyTargets{tenantModels: store}

	configBundleSource{}.apply(configBundlePayload{}, targets)

	got, err := store.Get(context.Background(), "tenant_a")
	if err != nil || got.DisplayName != "Acme" {
		t.Fatalf("an absent section must change nothing: %+v %v", got, err)
	}
}

// Upsert, not replace-all. Deleting a tenant is a deliberate lifecycle act with its own route and its own
// lockout protection; inferring it from absence would make a truncated payload look like a deletion.
func TestATenantMissingFromTheBundleIsNotDeleted(t *testing.T) {
	store := newAdminTenantModelStore(model.PolicyBundle{TenantID: "tenant_a"}, time.Now())
	store.Put(context.Background(), adminTenantModel{TenantID: "tenant_keep", DisplayName: "Keep", Status: "active"}, time.Now())
	targets := configApplyTargets{tenantModels: store}

	configBundleSource{}.apply(configBundlePayload{Tenants: &tenantModelBundle{Tenants: []adminTenantModel{
		{TenantID: "tenant_new", DisplayName: "New", Status: "active"},
	}}}, targets)

	if _, err := store.Get(context.Background(), "tenant_keep"); err != nil {
		t.Fatalf("a tenant absent from one bundle must survive it: %v", err)
	}
	if _, err := store.Get(context.Background(), "tenant_new"); err != nil {
		t.Fatalf("the new tenant must arrive: %v", err)
	}
}
