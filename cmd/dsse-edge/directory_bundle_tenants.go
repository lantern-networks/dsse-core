package main

import (
	"context"
	"sort"
	"strings"
)

// directoryBundleTenants lists the organizations whose people directory the config bundle carries.
//
// The requesting tenant is ALWAYS included, even when the registry cannot be enumerated. A control plane whose
// tenant store cannot list is not a control plane with one tenant, and serving nothing in that case would take
// a working directory away from the Edge that asked — the failure mode this section exists to end.
func directoryBundleTenants(ctx context.Context, store adminTenantModelRuntimeStore, requesting string) []string {
	models, _ := listBundleTenantModels(ctx, store)
	return directoryBundleTenantsFromModels(requesting, models)
}

// The fleet publisher must distinguish an unavailable tenant authority from an
// empty catalog. Its caller refuses to publish a partial bundle on an error.
func listBundleTenantModels(ctx context.Context, store adminTenantModelRuntimeStore) ([]adminTenantModel, error) {
	if admin, ok := store.(adminTenantModelAdminStore); ok && admin != nil {
		return admin.List(ctx)
	}
	return nil, nil
}

func directoryBundleTenantsFromModels(requesting string, models []adminTenantModel) []string {
	seen := map[string]bool{}
	tenants := []string{}
	add := func(id string) {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		tenants = append(tenants, id)
	}
	add(requesting)
	for _, model := range models {
		add(model.TenantID)
	}
	sort.Strings(tenants)
	return tenants
}
