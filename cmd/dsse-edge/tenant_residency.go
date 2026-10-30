package main

import (
	"context"

	"github.com/lantern-networks/dsse-core/edgeplane"
)

type tenantResidencyStore interface {
	Get(context.Context, string) (adminTenantModel, error)
}

func tenantResidencyResolver(store tenantResidencyStore) edgeplane.ResidencyResolver {
	return func(tenantID string) ([]string, error) {
		if store == nil {
			return nil, nil
		}
		tenant, err := store.Get(context.Background(), tenantID)
		if err != nil {
			return nil, err
		}
		return append([]string(nil), tenant.AllowedRegions...), nil
	}
}
