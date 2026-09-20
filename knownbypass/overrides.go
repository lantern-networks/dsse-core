package knownbypass

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/lantern-networks/dsse-core/blobstore"
)

// ErrPersistence means the requested snapshot could not be confirmed saved.
var ErrPersistence = errors.New("catalog override persistence failed")

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
	dirty     bool // a failed save may have changed storage; retry even an otherwise empty deletion
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
	return s.SetContext(context.Background(), tenantID, o, now)
}

func (s *OverrideStore) SetContext(ctx context.Context, tenantID string, o Override, now time.Time) (Override, error) {
	return s.SetFromCatalogContext(ctx, tenantID, o, Catalog().Entries, now)
}

// SetFromCatalog records an override for an entry in the supplied effective catalog.
// Callers must provide a trusted catalog and serialize catalog updates with this call.
func (s *OverrideStore) SetFromCatalog(tenantID string, o Override, entries []Group, now time.Time) (Override, error) {
	return s.SetFromCatalogContext(context.Background(), tenantID, o, entries, now)
}

func (s *OverrideStore) SetFromCatalogContext(ctx context.Context, tenantID string, o Override, entries []Group, now time.Time) (Override, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" || !utf8.ValidString(tenantID) {
		return Override{}, fmt.Errorf("tenant_id is required")
	}
	o.EntryID = strings.TrimSpace(o.EntryID)
	o.Mode = strings.TrimSpace(o.Mode)
	found := false
	for _, entry := range entries {
		if entry.ID == o.EntryID {
			found = true
			break
		}
	}
	if !found {
		return Override{}, fmt.Errorf("unknown catalog entry %q", o.EntryID)
	}
	if !validOverrideMode(o.Mode) {
		return Override{}, fmt.Errorf("invalid override mode %q (want %s or %s)", o.Mode, OverrideForceInspect, OverrideDisabled)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	o.UpdatedAt = now.UTC().Format(time.RFC3339)
	if !validStoredOverride(o) {
		return Override{}, fmt.Errorf("invalid catalog override fields")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.mutateLocked(ctx, func(next map[string]map[string]Override) {
		if next[tenantID] == nil {
			next[tenantID] = map[string]Override{}
		}
		next[tenantID][o.EntryID] = o
	})
	if err != nil {
		return Override{}, err
	}
	return o, nil
}

// Clear removes a tenant's override, restoring the catalog default, only after saving.
// The returned bool reports a confirmed removal, never an unconfirmed write.
func (s *OverrideStore) Clear(tenantID, entryID string) (bool, error) {
	return s.ClearContext(context.Background(), tenantID, entryID)
}

func (s *OverrideStore) ClearContext(ctx context.Context, tenantID, entryID string) (bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	entryID = strings.TrimSpace(entryID)
	s.mu.Lock()
	defer s.mu.Unlock()
	exists := false
	err := s.mutateLocked(ctx, func(next map[string]map[string]Override) {
		_, exists = next[tenantID][entryID]
		delete(next[tenantID], entryID)
		if len(next[tenantID]) == 0 {
			delete(next, tenantID)
		}
	})
	if err != nil {
		return false, err
	}
	return exists, nil
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

// Snapshot copies every tenant's overrides for an atomic engine rebuild.
func (s *OverrideStore) Snapshot() map[string][]Override {
	out := map[string][]Override{}
	if s == nil {
		return out
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for tenant, entries := range s.overrides {
		for _, entry := range entries {
			out[tenant] = append(out[tenant], entry)
		}
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
	if s.dirty {
		return fmt.Errorf("%w: retry saving before replacing storage", ErrPersistence)
	}
	if p == nil {
		s.persister = nil
		return nil
	}
	data, err := p.Load()
	if err != nil {
		return err
	}
	if data == nil {
		s.persister = p
		return nil
	}
	snapshot, err := decodeOverrideSnapshot(data)
	if err != nil {
		return err
	}
	s.overrides = snapshot
	s.persister = p
	return nil
}

func (s *OverrideStore) cloneLocked() map[string]map[string]Override {
	next := make(map[string]map[string]Override, len(s.overrides))
	for tenant, entries := range s.overrides {
		next[tenant] = maps.Clone(entries)
	}
	return next
}

// Hold the lock across save and publication so a later mutation cannot persist an
// unconfirmed change. Save errors can include an uncertain commit; keep live state
// and require a successful retry before changing writers or acknowledging no-op removal.
func (s *OverrideStore) commitLocked(next map[string]map[string]Override) error {
	if s.persister != nil {
		data, err := json.MarshalIndent(next, "", "  ")
		if err == nil {
			err = s.persister.Save(data)
		}
		if err != nil {
			s.dirty = true
			return fmt.Errorf("%w: %w", ErrPersistence, err)
		}
	}
	s.overrides = next
	s.dirty = false
	return nil
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

// RemoveTenant reports erasure only after the resulting snapshot is saved.
func (s *OverrideStore) RemoveTenant(tenantID string) (int, error) {
	return s.RemoveTenantContext(context.Background(), tenantID)
}

func (s *OverrideStore) RemoveTenantContext(ctx context.Context, tenantID string) (int, error) {
	if s == nil {
		return 0, nil
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	err := s.mutateLocked(ctx, func(next map[string]map[string]Override) {
		n = len(next[tenantID])
		delete(next, tenantID)
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}
