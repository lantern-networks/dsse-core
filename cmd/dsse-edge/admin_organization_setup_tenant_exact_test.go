package main

import (
	"context"
	"errors"
	"testing"
)

type organizationSetupListStub struct {
	adminTenantModelAdminStore
	rows     []adminTenantModel
	listErr  error
	getCalls int
}

func (s *organizationSetupListStub) List(context.Context) ([]adminTenantModel, error) {
	return s.rows, s.listErr
}

func (s *organizationSetupListStub) Get(_ context.Context, tenantID string) (adminTenantModel, error) {
	s.getCalls++
	// Both production Get implementations synthesize a row for a missing tenant.
	return adminTenantModel{TenantID: tenantID, DisplayName: tenantID}, nil
}

type organizationSetupGetOnlyStub struct {
	adminTenantModelRuntimeStore
	row adminTenantModel
}

func (s organizationSetupGetOnlyStub) Get(context.Context, string) (adminTenantModel, error) {
	return s.row, nil
}

func TestOrganizationSetupTenantKeepsCaseDistinct(t *testing.T) {
	store := &organizationSetupListStub{rows: []adminTenantModel{
		{TenantID: "Acme", HomeRegion: "region-upper"},
		{TenantID: "acme", HomeRegion: "region-lower"},
	}}
	for _, tc := range []struct{ id, wantRegion string }{
		{"Acme", "region-upper"}, {"acme", "region-lower"},
	} {
		row, ok := organizationSetupTenant(context.Background(), store, tc.id)
		if !ok || row.TenantID != tc.id || row.HomeRegion != tc.wantRegion {
			t.Fatalf("lookup %q returned row %+v, ok=%v", tc.id, row, ok)
		}
	}
	if store.getCalls != 0 {
		t.Fatal("authoritative List must not use synthesizing Get")
	}
}

func TestOrganizationSetupTenantListFailureDoesNotUseSynthesizedGet(t *testing.T) {
	store := &organizationSetupListStub{listErr: errors.New("tenant list unavailable")}
	row, ok := organizationSetupTenant(context.Background(), store, "Acme")
	if ok || row.TenantID != "Acme" || store.getCalls != 0 {
		t.Fatalf("list failure was treated as an existing tenant: %+v, ok=%v, Get calls=%d", row, ok, store.getCalls)
	}
}

func TestOrganizationSetupTenantRequiresAuthoritativeList(t *testing.T) {
	store := organizationSetupGetOnlyStub{row: adminTenantModel{TenantID: "Acme", HomeRegion: "region-upper"}}
	for _, id := range []string{"Acme", "acme"} {
		_, ok := organizationSetupTenant(context.Background(), store, id)
		if ok {
			t.Fatalf("Get-only store cannot establish existence for %q", id)
		}
	}
}
