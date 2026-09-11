package main

import (
	"encoding/json"
	"sort"
	"sync"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/dlp"
)

// dlpAllowlistRuntimeStore holds the operator-declared KNOWN-SAFE values per tenant (slice F, false-positive
// tuning): test cards, sample My Numbers, benign emails that must NOT raise a DLP finding. It keeps the authored
// values (durable, serves the admin API and the Console so the operator can manage the list) and a compiled
// *dlp.Allowlist (salted hashes) for the scan path, hot-swapped on SetValues — mirroring dlpClassifierRuntimeStore.
//
// These are values the operator ASSERTS are non-sensitive (that is the whole point of allowlisting); they are the
// only DLP-adjacent reference data kept in the clear, and the Console labels them so real secrets are not entered.
type dlpAllowlistRuntimeStore struct {
	mu     sync.RWMutex
	values map[string][]string       // tenant -> raw safe values (operator-managed)
	sets   map[string]*dlp.Allowlist // tenant -> compiled salted-hash allowlist (data path)
	salt   string                    // edge-wide salt mixed into every hash
	// persister durably stores the per-tenant values so the allowlist survives an Edge restart.
	persister blobstore.Persister
	dirty     bool
}

func newDLPAllowlistRuntimeStore(salt string) *dlpAllowlistRuntimeStore {
	return &dlpAllowlistRuntimeStore{values: map[string][]string{}, sets: map[string]*dlp.Allowlist{}, salt: salt}
}

// AllowlistForTenant returns the live compiled allowlist for a tenant (nil = none), for the scan path.
func (s *dlpAllowlistRuntimeStore) AllowlistForTenant(tenantID string) *dlp.Allowlist {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sets[tenantID]
}

// ValuesForTenant returns a copy of the authored safe values for a tenant (admin API GET).
func (s *dlpAllowlistRuntimeStore) ValuesForTenant(tenantID string) []string {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.values[tenantID]...)
}

// SetValues replaces one tenant's allowlist and recompiles it into the live hashed set. Empty clears the tenant.
func (s *dlpAllowlistRuntimeStore) SetValues(tenantID string, values []string) {
	s.mu.Lock()
	if len(values) == 0 {
		delete(s.values, tenantID)
		delete(s.sets, tenantID)
	} else {
		s.values[tenantID] = append([]string(nil), values...)
		s.sets[tenantID] = dlp.NewAllowlist(s.salt+"\x00"+tenantID, values)
	}
	s.dirty = true
	s.mu.Unlock()
}

// Tenants returns the tenant ids that have an allowlist, ordered (admin listing).
func (s *dlpAllowlistRuntimeStore) Tenants() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.values))
	for t := range s.values {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

type allowlistStoreSnapshot struct {
	Values map[string][]string `json:"values"`
}

// SetPersister attaches durable storage and rehydrates + recompiles on boot (so the allowlist survives a restart).
func (s *dlpAllowlistRuntimeStore) SetPersister(p blobstore.Persister) error {
	s.mu.Lock()
	s.persister = p
	s.mu.Unlock()
	if p == nil {
		return nil
	}
	data, err := p.Load()
	if err != nil || len(data) == 0 {
		return err
	}
	var snap allowlistStoreSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for tenant, vals := range snap.Values {
		if len(vals) == 0 {
			continue
		}
		s.values[tenant] = vals
		s.sets[tenant] = dlp.NewAllowlist(s.salt+"\x00"+tenant, vals)
	}
	return nil
}

// PersistIfDirty writes a snapshot when there are unsaved changes. Cheap no-op when clean or persister-less.
func (s *dlpAllowlistRuntimeStore) PersistIfDirty() error {
	s.mu.Lock()
	if !s.dirty || s.persister == nil {
		s.mu.Unlock()
		return nil
	}
	snap := allowlistStoreSnapshot{Values: map[string][]string{}}
	for t, v := range s.values {
		snap.Values[t] = v
	}
	data, err := json.Marshal(snap)
	p := s.persister
	if err == nil {
		s.dirty = false
	}
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if err := p.Save(data); err != nil {
		// dirty was cleared optimistically (Save runs outside the lock); re-mark so the next periodic
		// flush retries instead of silently dropping the snapshot (review #17).
		s.mu.Lock()
		s.dirty = true
		s.mu.Unlock()
		return err
	}
	return nil
}

// dlpAllowlistProvider supplies the compiled allowlist for a tenant to the egress DLP scan path.
type dlpAllowlistProvider interface {
	AllowlistForTenant(tenantID string) *dlp.Allowlist
}
