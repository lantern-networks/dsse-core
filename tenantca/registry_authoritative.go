package tenantca

import (
	"encoding/json"
	"fmt"
)

// RegistryFromSnapshot validates a complete inline shared snapshot, including an
// explicitly empty set. It does not silently skip malformed or conflicting rows.
func RegistryFromSnapshot(raw []byte) (*TenantCARegistry, error) {
	var doc TenantCARegistryFile
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if doc.Tenants == nil {
		return nil, fmt.Errorf("tenant CA snapshot is incomplete")
	}
	r := NewTenantCARegistry()
	for _, entry := range doc.Tenants {
		if _, err := r.Register(entry.TenantID, []byte(entry.CAPEM)); err != nil {
			return nil, err
		}
	}
	if err := r.restoreMaterialOwnership(doc.MaterialManagedTenants); err != nil {
		return nil, err
	}
	return r, nil
}

// ReplaceAuthoritative installs a checked CP snapshot after commit or a checked
// read. An empty set removes stale anchors too. Partial local withdrawals must
// finish through their original path before replacing this cache.
func (r *TenantCARegistry) ReplaceAuthoritative(raw []byte) error {
	next, err := RegistryFromSnapshot(raw)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.pendingWithdrawals) != 0 {
		return fmt.Errorf("local CA withdrawal is pending")
	}
	same := len(r.byAnchorKey) == len(next.byAnchorKey) && len(r.materialManaged) == len(next.materialManaged)
	for key, owner := range next.byAnchorKey {
		if r.byAnchorKey[key] != owner {
			same = false
		}
	}
	for key, owned := range next.materialManaged {
		if r.materialManaged[key] != owned {
			same = false
		}
	}
	r.authoritativeLoaded = true
	if same {
		return nil
	}
	r.byAnchorKey, r.anchors, r.Pool = next.byAnchorKey, next.anchors, next.Pool
	r.materialManaged, r.TenantCount = next.materialManaged, next.TenantCount
	r.generation++
	return nil
}

// AuthoritativeLoaded distinguishes a known empty row from first initialization.
func (r *TenantCARegistry) AuthoritativeLoaded() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.authoritativeLoaded
}
