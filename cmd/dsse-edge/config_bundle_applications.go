package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/lantern-networks/dsse-core/appcatalog"
)

type applicationCatalogBundle struct {
	Entries  map[string]map[string]appcatalog.Entry `json:"entries"`
	Complete bool                                   `json:"complete"`
}

// The catalog's content contributes a monotonic counter within this CP process's
// bundle epoch. Re-reading the shared DB detects writes made through another CP;
// content hashing also detects deletion of the last application. A failed read
// never publishes an empty catalog. No database migration is needed for a counter
// whose comparisons are explicitly bounded by the existing process epoch.
type applicationBundleState struct {
	mu         sync.Mutex
	hash       [32]byte
	generation uint64
}

func (state *applicationBundleState) read(ctx context.Context, store appcatalog.RuntimeStore) (*applicationCatalogBundle, uint64, error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if store == nil {
		return nil, 0, nil
	}
	source, ok := store.(interface {
		ExportSnapshot(context.Context) (map[string]map[string]appcatalog.Entry, error)
	})
	if !ok {
		return nil, state.generation, fmt.Errorf("application catalog cannot export a complete fleet snapshot")
	}
	entries, err := source.ExportSnapshot(ctx)
	if err != nil {
		return nil, state.generation, err
	}
	if entries == nil {
		entries = map[string]map[string]appcatalog.Entry{}
	}
	data, err := json.Marshal(entries)
	if err != nil {
		return nil, state.generation, err
	}
	hash := sha256.Sum256(data)
	if state.generation == 0 || hash != state.hash {
		state.generation++
		state.hash = hash
	}
	return &applicationCatalogBundle{Entries: entries, Complete: true}, state.generation, nil
}

func scopeApplicationBundle(section *applicationCatalogBundle, tenant string, fleet bool) *applicationCatalogBundle {
	if section == nil || fleet {
		return section
	}
	entries := map[string]map[string]appcatalog.Entry{}
	if own, ok := section.Entries[tenant]; ok {
		entries[tenant] = own
	}
	return &applicationCatalogBundle{Entries: entries, Complete: false}
}

func applyApplicationBundle(store appcatalog.RuntimeStore, section *applicationCatalogBundle) error {
	if section == nil {
		return nil
	}
	if !section.Complete {
		return fmt.Errorf("application catalog snapshot is incomplete; keeping local catalog")
	}
	target, ok := store.(interface {
		ReplaceFromAuthority(map[string]map[string]appcatalog.Entry) error
	})
	if !ok {
		return fmt.Errorf("application catalog cannot accept a fleet snapshot")
	}
	return target.ReplaceFromAuthority(section.Entries)
}

func (p *postgresApplicationCatalogStore) ExportSnapshot(ctx context.Context) (map[string]map[string]appcatalog.Entry, error) {
	// One SELECT is one PostgreSQL statement snapshot; no per-tenant paging can
	// silently truncate the catalog or combine different points in time.
	rows, err := p.db.QueryContext(ctx, "SELECT "+applicationCatalogColumns+" FROM application_catalog ORDER BY tenant_id, application_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	seed, err := json.Marshal(p.seed)
	if err != nil {
		return nil, err
	}
	out := map[string]map[string]appcatalog.Entry{}
	if err := json.Unmarshal(seed, &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = map[string]map[string]appcatalog.Entry{}
	}
	for rows.Next() {
		entry, err := scanApplicationCatalogRow(rows.Scan)
		if err != nil {
			return nil, err
		}
		if out[entry.TenantID] == nil {
			out[entry.TenantID] = map[string]appcatalog.Entry{}
		}
		out[entry.TenantID][entry.ApplicationID] = entry
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
