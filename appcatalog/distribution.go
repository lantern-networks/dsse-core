package appcatalog

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// ExportSnapshot is a complete fleet snapshot, for the authenticated control-plane
// distribution path. Tenant-facing handlers must scope it before serialization.
func (store *Store) ExportSnapshot(context.Context) (map[string]map[string]Entry, error) {
	return store.Snapshot(), nil
}

// ReplaceFromAuthority installs the complete control-plane catalog, including
// removals. Validate before changing any tenant and roll back on persistence error.
func (store *Store) ReplaceFromAuthority(snapshot map[string]map[string]Entry) error {
	next := make(map[string]map[string]Entry, len(snapshot))
	for tenant, entries := range snapshot {
		if tenant == "" || tenant != strings.TrimSpace(tenant) {
			return fmt.Errorf("application snapshot tenant is invalid")
		}
		next[tenant] = map[string]Entry{}
		for id, entry := range entries {
			if entry.TenantID != tenant || id != entry.ApplicationID || id != strings.TrimSpace(id) {
				return fmt.Errorf("application snapshot identity does not match its tenant/key")
			}
			normalized, err := normalize(entry, tenant, time.Now())
			if err != nil {
				return err
			}
			normalized.UpdatedAt = entry.UpdatedAt
			next[tenant][id] = copyEntry(normalized)
		}
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	previous := store.applications
	store.applications = next
	if err := store.persistLocked(); err != nil {
		store.applications = previous
		return err
	}
	return nil
}
