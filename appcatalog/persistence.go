package appcatalog

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// SetStatePath enables durable persistence. The application catalog is SEEDED from config (route profiles +
// SaaS catalog) on every boot, so loadLocked MERGES the persisted set on top of the seed: config-seeded
// entries stay present, while operator-authored applications (and operator edits) survive an edge restart.
// Call this AFTER the config seed so the overlay wins.
func (store *Store) SetStatePath(path string) error {
	path = strings.TrimSpace(path)
	store.mu.Lock()
	defer store.mu.Unlock()
	// Capture the config-derived seed BEFORE loading the authored overlay: at this point the store holds only the
	// entries the caller built from config (route profiles + SaaS catalog), so these are exactly the ids Delete
	// must refuse to remove (they would be reconstructed on the next boot). Done for both the file path and the
	// in-memory "" path so the lab default also protects its seed.
	store.captureSeedLocked()
	store.statePath = path
	if path == "" {
		return nil
	}
	return store.loadLocked()
}

// captureSeedLocked snapshots the current application ids as the non-deletable config seed. The caller must hold
// store.mu.
func (store *Store) captureSeedLocked() {
	seed := make(map[string]map[string]struct{}, len(store.applications))
	for tenantID, byID := range store.applications {
		ids := make(map[string]struct{}, len(byID))
		for id := range byID {
			ids[id] = struct{}{}
		}
		seed[tenantID] = ids
	}
	store.seed = seed
}

func (store *Store) loadLocked() error {
	data, err := os.ReadFile(store.statePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(data) == 0 {
		return nil
	}
	var snapshot map[string]map[string]Entry
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return err
	}
	for tenantID, byID := range snapshot {
		if store.applications[tenantID] == nil {
			store.applications[tenantID] = map[string]Entry{}
		}
		for id, entry := range byID {
			store.applications[tenantID][id] = entry
		}
	}
	return nil
}

// persistLocked atomically snapshots the application catalog. The error MUST reach the mutating caller: a
// swallowed write meant an operator-authored application was acknowledged while nothing hit disk, silently
// vanishing on restart. Caller holds store.mu.
func (store *Store) persistLocked() error {
	if store.statePath == "" {
		return nil
	}
	data, err := json.MarshalIndent(store.applications, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal application-catalog snapshot: %w", err)
	}
	tmp := store.statePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("persist application catalog: %w", err)
	}
	if err := os.Rename(tmp, store.statePath); err != nil {
		return fmt.Errorf("persist application catalog (rename): %w", err)
	}
	return nil
}
