package tenantca

import (
	"fmt"
	"sort"
	"strings"
)

// MaterialManaged remains true across signer-cache loss and process restarts.
// Remote registry sections cannot author or remove this local ownership record.
func (r *TenantCARegistry) MaterialManaged(tenant string) bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.materialManaged[strings.ToLower(strings.TrimSpace(tenant))]
}

func (r *TenantCARegistry) materialManagedTenantsLocked() []string {
	var names []string
	for tenant, owned := range r.materialManaged {
		if owned {
			names = append(names, tenant)
		}
	}
	sort.Strings(names)
	return names
}

func (r *TenantCARegistry) restoreMaterialOwnership(names []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	owned := make(map[string]bool, len(names))
	for _, name := range names {
		tenant := strings.ToLower(strings.TrimSpace(name))
		if tenant == "" {
			return fmt.Errorf("empty material-managed tenant in CA registry")
		}
		// Explicit whole-tenant withdrawal removes the marker. Partial registry
		// snapshots must not turn an unknown owner into an asserted owner.
		found := false
		for _, owner := range r.byAnchorKey {
			if strings.EqualFold(owner, tenant) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("material-managed tenant has no admission anchors")
		}
		owned[tenant] = true
	}
	r.materialManaged = owned
	return nil
}
