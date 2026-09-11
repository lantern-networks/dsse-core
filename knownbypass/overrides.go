package knownbypass

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
)

// Override is a per-tenant decision on a single predefined catalog entry. The default (no override) leaves the
// entry as a no-decrypt bypass; an override re-asserts inspection (force_inspect) or disables the bypass.
type Override struct {
	EntryID   string `json:"entry_id"`
	Mode      string `json:"mode"` // force_inspect | disabled
	Reason    string `json:"reason,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// OverrideStore holds per-tenant catalog overrides with optional durable persistence (so a tenant's decision
// to force-inspect a pinned entry survives an edge restart). Keyed by (tenant, entry id) — one override per
// entry; setting again replaces it.
type OverrideStore struct {
	mu        sync.RWMutex
	overrides map[string]map[string]Override // tenant -> entryID -> override
	persister blobstore.Persister
}

func NewOverrideStore() *OverrideStore {
	return &OverrideStore{overrides: map[string]map[string]Override{}}
}

func validOverrideMode(mode string) bool {
	switch strings.TrimSpace(mode) {
	case OverrideForceInspect, OverrideDisabled:
		return true
	}
	return false
}

// Set records (or replaces) a tenant's override for a catalog entry. The entry must exist in the catalog and
// the mode must be valid; an unknown entry or mode is rejected so the override set cannot drift from the catalog.
func (s *OverrideStore) Set(tenantID string, o Override, now time.Time) (Override, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return Override{}, fmt.Errorf("tenant_id is required")
	}
	o.EntryID = strings.TrimSpace(o.EntryID)
	o.Mode = strings.TrimSpace(o.Mode)
	if _, ok := EntryByID(o.EntryID); !ok {
		return Override{}, fmt.Errorf("unknown catalog entry %q", o.EntryID)
	}
	if !validOverrideMode(o.Mode) {
		return Override{}, fmt.Errorf("invalid override mode %q (want %s or %s)", o.Mode, OverrideForceInspect, OverrideDisabled)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	o.UpdatedAt = now.UTC().Format(time.RFC3339)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.overrides[tenantID] == nil {
		s.overrides[tenantID] = map[string]Override{}
	}
	s.overrides[tenantID][o.EntryID] = o
	s.persistLocked()
	return o, nil
}

// Clear removes a tenant's override for an entry, restoring the catalog default (bypass). Returns whether an
// override existed.
func (s *OverrideStore) Clear(tenantID, entryID string) bool {
	tenantID = strings.TrimSpace(tenantID)
	entryID = strings.TrimSpace(entryID)
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.overrides[tenantID]
	if m == nil {
		return false
	}
	if _, ok := m[entryID]; !ok {
		return false
	}
	delete(m, entryID)
	s.persistLocked()
	return true
}

// List returns a tenant's overrides.
func (s *OverrideStore) List(tenantID string) []Override {
	tenantID = strings.TrimSpace(tenantID)
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Override{}
	for _, o := range s.overrides[tenantID] {
		out = append(out, o)
	}
	return out
}

// EffectiveBypassHosts returns the tenant's effective bypass host set over the built-in default catalog: the
// default minus any entries the tenant overrode to force_inspect/disabled.
func (s *OverrideStore) EffectiveBypassHosts(tenantID string) []string {
	return EffectiveBypassHosts(s.List(tenantID))
}

// EffectiveBypassHostsFrom is EffectiveBypassHosts over an explicit effective catalog (e.g. a feed-supplied
// catalog instead of the built-in default).
func (s *OverrideStore) EffectiveBypassHostsFrom(entries []Group, tenantID string) []string {
	return EffectiveBypassHostsFrom(entries, s.List(tenantID))
}

// SetStatePath enables durable persistence and loads any existing overrides.
func (s *OverrideStore) SetStatePath(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return s.SetPersister(nil)
	}
	return s.SetPersister(blobstore.FilePersister{Path: path})
}

// SetPersister enables durable persistence via any Persister (file or shared Postgres): bypass-catalog overrides
// survive a restart — and, on a shared persister, a CP failover.
func (s *OverrideStore) SetPersister(p blobstore.Persister) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.persister = p
	if p == nil {
		return nil
	}
	data, err := p.Load()
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	var snapshot map[string]map[string]Override
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return err
	}
	if snapshot != nil {
		s.overrides = snapshot
	}
	return nil
}

func (s *OverrideStore) persistLocked() {
	if s.persister == nil {
		return
	}
	data, err := json.MarshalIndent(s.overrides, "", "  ")
	if err != nil {
		return
	}
	_ = s.persister.Save(data)
}

// CountForTenant returns how many bypass-catalog overrides this organization still has, and RemoveTenant
// erases them. Both exist because "completely deleted" was measured leaving tenant-scoped stores behind
// (2026-08-18): a store nobody counts contributes nothing to "what is left", so an erasure over it answers
// complete=true whatever it still holds. This one is keyed by tenant at the top level, so it is exact.
func (s *OverrideStore) CountForTenant(tenantID string) int {
	if s == nil {
		return 0
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.overrides[tenantID])
}

func (s *OverrideStore) RemoveTenant(tenantID string) int {
	if s == nil {
		return 0
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.overrides[tenantID])
	if n == 0 {
		return 0
	}
	delete(s.overrides, tenantID)
	s.persistLocked()
	return n
}
