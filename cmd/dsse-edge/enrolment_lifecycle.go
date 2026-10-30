package main

import (
	"context"
	"fmt"
	"strings"
)

const enrolmentTenantAbsentReason = "organization is not in the registry"

// New admission needs a confirmed lifecycle decision for its assigned tenant.
// An unavailable registry is different from an administrator suspending a tenant,
// but neither permits creating a new credential. Existing devices are unaffected.
// A nil registry preserves standalone deployments without lifecycle management.
func enrolmentLifecycleRefusal(ctx context.Context, store adminTenantModelRuntimeStore, tenantID string, authoritativeAbsence bool) (string, error) {
	tenantID = strings.TrimSpace(tenantID)
	if store == nil || tenantID == "" {
		return "", nil
	}
	if authoritativeAbsence {
		if list, ok := store.(adminTenantModelAdminStore); ok {
			tenants, err := list.List(ctx)
			if err != nil {
				return "", err
			}
			found := false
			for _, tenant := range tenants {
				found = found || strings.TrimSpace(tenant.TenantID) == tenantID
			}
			// An empty legacy registry does not manage tenant existence.
			if len(tenants) != 0 && !found {
				return enrolmentTenantAbsentReason, nil
			}
		}
	}
	tenant, err := store.Get(ctx, tenantID)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(tenant.TenantID) != tenantID {
		return "", fmt.Errorf("organization lifecycle identity mismatch")
	}
	switch strings.ToLower(strings.TrimSpace(tenant.Status)) {
	case "active":
		return "", nil
	case "suspended", "archived":
		return "organization is " + strings.ToLower(strings.TrimSpace(tenant.Status)), nil
	default:
		return "", fmt.Errorf("organization lifecycle status is unavailable")
	}
}
