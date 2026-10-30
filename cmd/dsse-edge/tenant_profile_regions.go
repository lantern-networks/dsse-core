package main

import (
	"context"
	"fmt"
	"strings"
)

// tenantProfileRegionEndpoints supplies the authoritative endpoint list for both
// endpoint and Connector configuration. Unknown residency must never expand into
// the full deployment catalog. A nil store is the explicit legacy single-tenant
// mode; a configured store must confirm a registered organization.
func tenantProfileRegionEndpoints(catalog *regionEndpointCatalog, store adminTenantModelRuntimeStore, tenantID, fallbackURL, fallbackRegion string) []regionEndpoint {
	endpoints, _ := tenantProfileRegionEndpointsChecked(context.Background(), catalog, store, tenantID, fallbackURL, fallbackRegion)
	return endpoints
}

// tenantProfileRegionEndpointsChecked distinguishes an authoritative empty answer from a failed tenant-model
// read. The Connector profile uses the error to return 503; it must never interpret a CP outage as a signed-off
// removal of all doors. Older agent profile callers retain their existing fail-closed empty-list behavior.
func tenantProfileRegionEndpointsChecked(ctx context.Context, catalog *regionEndpointCatalog, store adminTenantModelRuntimeStore,
	tenantID, fallbackURL, fallbackRegion string) ([]regionEndpoint, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, nil
	}
	var tenant adminTenantModel
	if store != nil {
		admin, ok := store.(adminTenantModelAdminStore)
		if !ok {
			return nil, fmt.Errorf("tenant-model authority cannot establish tenant existence")
		}
		tenants, err := admin.List(ctx)
		if err != nil {
			return nil, fmt.Errorf("read tenant-model authority: %w", err)
		}
		found := false
		for _, candidate := range tenants {
			if candidate.TenantID == tenantID {
				tenant = candidate
				found = true
				break
			}
		}
		if !found {
			return nil, nil
		}
	}
	if catalog != nil {
		return catalog.allowedRegionEndpoints(tenant.AllowedRegions, tenant.HomeRegion), nil
	}
	fallbackURL = strings.TrimSpace(fallbackURL)
	fallbackRegion = strings.ToLower(strings.TrimSpace(fallbackRegion))
	if fallbackURL == "" {
		return nil, nil
	}
	// Without a region map, the bootstrap address still belongs to this node's
	// region. A residency-pinned tenant cannot use an unidentified or other region.
	if len(tenant.AllowedRegions) > 0 {
		allowed := false
		for _, region := range tenant.AllowedRegions {
			if strings.ToLower(strings.TrimSpace(region)) == fallbackRegion && fallbackRegion != "" {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, nil
		}
	}
	return []regionEndpoint{{Region: fallbackRegion, Endpoint: fallbackURL}}, nil
}
