package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

type unavailableProfileTenantStore struct{ *adminTenantModelStore }

func (s unavailableProfileTenantStore) List(context.Context) ([]adminTenantModel, error) {
	return nil, errors.New("unavailable")
}

func TestTenantProfileRegionsRequireKnownResidency(t *testing.T) {
	store := newAdminTenantModelStore(model.PolicyBundle{TenantID: "tenant-a"}, time.Now())
	_, err := store.Put(context.Background(), adminTenantModel{TenantID: "tenant-a", AllowedRegions: []string{"region-a"}, HomeRegion: "region-a"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	catalog := mustCatalog(t, "region-a=https://a.example.test;region-b=https://b.example.test")
	for _, tc := range []struct {
		name, id string
		store    adminTenantModelRuntimeStore
	}{
		{"unknown", "missing", store}, {"case-distinct", "Tenant-A", store}, {"unavailable", "tenant-a", unavailableProfileTenantStore{store}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tenantProfileRegionEndpoints(catalog, tc.store, tc.id, "https://fallback.example.test", "region-b"); len(got) != 0 {
				t.Fatalf("unknown residency widened to %v", got)
			}
		})
	}
	got := tenantProfileRegionEndpoints(catalog, store, "tenant-a", "https://fallback.example.test", "region-b")
	if len(got) != 1 || got[0].Region != "region-a" {
		t.Fatalf("pinned tenant: %v", got)
	}
	if got := tenantProfileRegionEndpoints(nil, store, "tenant-a", "https://fallback.example.test", "region-b"); len(got) != 0 {
		t.Fatalf("single-region fallback crossed residency: %v", got)
	}
	got = tenantProfileRegionEndpoints(nil, store, "tenant-a", "https://a.example.test", "region-a")
	if len(got) != 1 || got[0].Endpoint != "https://a.example.test" {
		t.Fatalf("permitted single-region missing: %v", got)
	}
	if got := tenantProfileRegionEndpoints(nil, nil, "legacy", "https://single.example.test", ""); len(got) != 1 || got[0].Endpoint != "https://single.example.test" {
		t.Fatalf("legacy single-region changed: %v", got)
	}
}
