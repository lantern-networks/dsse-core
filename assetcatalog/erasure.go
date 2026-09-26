package assetcatalog

import "context"

// CountTenantRecords includes authored objects and stored alias metadata. The
// inventory-owned endpoint view and immutable built-ins are not durable records
// of this store. Aliases are counted separately from their objects.
func (s *Store) CountTenantRecords(tenant string) (int, error) {
	if s == nil {
		return 0, nil
	}
	if err := s.RefreshShared(); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return countTenantCatalogRecords(s.authoredStateLocked(), tenant), nil
}

func countTenantCatalogRecords(s persistedCatalog, tenant string) int {
	return len(s.Endpoints[tenant]) + len(s.Groups[tenant]) + len(s.Services[tenant]) + len(s.Aliases[tenant]) + len(s.EnrolledAliases[tenant])
}

// RemoveTenantContext removes only this tenant's authored state and alias
// metadata, using the same latest-row/accepted-term path as ordinary edits.
// The inventory must already be retired before invoking tenant erasure.
func (s *Store) RemoveTenantContext(ctx context.Context, tenant string) (int, error) {
	if s == nil {
		return 0, nil
	}
	return mutateCatalogContext(ctx, s, func(n *Store) (int, error) {
		count := countTenantCatalogRecords(n.authoredStateLocked(), tenant)
		changed := len(n.endpoints[tenant])+len(n.groups[tenant])+len(n.services[tenant])+len(n.aliases[tenant])+len(n.enrolledAliases[tenant]) > 0
		delete(n.endpoints, tenant)
		delete(n.groups, tenant)
		delete(n.services, tenant)
		delete(n.aliases, tenant)
		delete(n.enrolledAliases, tenant)
		if changed {
			n.generation++
		}
		return count, nil
	})
}
