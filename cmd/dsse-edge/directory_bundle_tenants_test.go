package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// The serve side of the same decision: the bundle must offer every organization's directory, not the one the
// Edge happened to pull as. Read the tenants from the registry rather than from the request.
func TestTheDirectorySectionIsBuiltForEveryOrganization(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	store := newAdminTenantModelStore(model.PolicyBundle{TenantID: "tenant_reference_lab"}, now)
	for _, id := range []string{"tenant_northwind", "tenant_acme"} {
		if _, err := store.Put(context.Background(), adminTenantModel{TenantID: id}, now); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}

	got := directoryBundleTenants(context.Background(), store, "tenant_reference_lab")
	for _, want := range []string{"tenant_reference_lab", "tenant_northwind", "tenant_acme"} {
		if !directoryTenantsInclude(got, want) {
			t.Fatalf("the directory section would be built for %v — %s is missing, so the Edge that enforces "+
				"for it would hold none of its people", got, want)
		}
	}

	// The control that matters more than completeness: a registry that cannot be enumerated must still serve
	// the asker its OWN directory. Serving nothing there would take a working directory away from the Edge
	// that asked, which is the failure this section exists to end.
	if only := directoryBundleTenants(context.Background(), unlistableTenantStore{}, "tenant_reference_lab"); len(only) != 1 ||
		only[0] != "tenant_reference_lab" {
		t.Fatalf("with an unlistable registry the section was built for %v, want the requesting tenant alone", only)
	}

	// And a blank request must not produce a phantom tenant.
	if none := directoryBundleTenants(context.Background(), unlistableTenantStore{}, "  "); len(none) != 0 {
		t.Fatalf("a request naming no organization produced %v", none)
	}
}

func directoryTenantsInclude(list []string, want string) bool {
	for _, item := range list {
		if strings.EqualFold(item, want) {
			return true
		}
	}
	return false
}

// unlistableTenantStore satisfies only the self-scoped surface — the shape a backend has when it cannot
// enumerate. It must not be silently treated as "there is one tenant".
type unlistableTenantStore struct{}

func (unlistableTenantStore) Get(context.Context, string) (adminTenantModel, error) {
	return adminTenantModel{}, nil
}

func (unlistableTenantStore) Update(context.Context, adminTenantModel, string, time.Time) (adminTenantModel, error) {
	return adminTenantModel{}, nil
}
