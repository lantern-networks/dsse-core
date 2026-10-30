package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

type sharedFleetResidencyCheck func(context.Context, string) error

// The TCP front door cannot inspect a tenant inside mTLS. A healthy Region
// entrance is not permission to process a tenant outside its signed Region scope.
func newSharedFleetResidencyCheck(profile, region string, store adminTenantModelRuntimeStore) sharedFleetResidencyCheck {
	if profile != "three-regions-multi-edge" {
		return nil
	}
	return func(ctx context.Context, tenant string) error {
		if store == nil || strings.TrimSpace(region) == "" || strings.TrimSpace(tenant) == "" {
			return fmt.Errorf("tenant Region authority unavailable")
		}
		row, err := store.Get(ctx, tenant)
		if err != nil || row.TenantID != tenant {
			return fmt.Errorf("tenant Region authority unavailable")
		}
		if len(row.AllowedRegions) == 0 {
			return nil
		}
		for _, allowed := range row.AllowedRegions {
			if strings.EqualFold(strings.TrimSpace(allowed), region) {
				return nil
			}
		}
		return fmt.Errorf("this Edge is outside the organization's allowed Regions")
	}
}

func sharedFleetResidencyMiddleware(next http.Handler, config serverConfig, check sharedFleetResidencyCheck) http.Handler {
	if check == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tenant, ok := transportTenantFromRequest(r, config.TenantCARegistry); ok {
			if err := check(r.Context(), tenant); err != nil {
				http.Error(w, "Organization Region unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
