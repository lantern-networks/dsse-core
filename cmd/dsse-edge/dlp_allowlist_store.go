package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
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
	persister  blobstore.Persister
	dirty      bool
	generation uint64
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
	s.generation++
	s.mu.Unlock()
}

const maxDLPAllowlistValues = 1000

func validatedAllowlistValues(values []string) ([]string, error) {
	if len(values) > maxDLPAllowlistValues {
		return nil, fmt.Errorf("too many allowlist values (max %d)", maxDLPAllowlistValues)
	}
	next := make([]string, 0, len(values))
	seen := map[string]bool{}
	for i, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil, fmt.Errorf("allowlist value %d is empty", i+1)
		}
		if !seen[value] {
			next = append(next, value)
			seen[value] = true
		}
	}
	return next, nil
}

// SetValuesDurable confirms configured storage before publishing suppression rules.
// Without a persister this remains in-memory only; errors do not prove disk rollback.
func (s *dlpAllowlistRuntimeStore) SetValuesDurable(tenantID string, values []string) error {
	values, err := validatedAllowlistValues(values)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.snapshotLocked()
	if len(values) == 0 {
		delete(next.Values, tenantID)
	} else {
		next.Values[tenantID] = values
	}
	if err := s.saveSnapshotLocked(next); err != nil {
		return err
	}
	s.values = next.Values
	if len(values) == 0 {
		delete(s.sets, tenantID)
	} else {
		s.sets[tenantID] = dlp.NewAllowlist(s.salt+"\x00"+tenantID, values)
	}
	s.dirty = false
	s.generation++
	return nil
}
func (s *dlpAllowlistRuntimeStore) snapshotLocked() allowlistStoreSnapshot {
	next := allowlistStoreSnapshot{Values: map[string][]string{}}
	for tenant, values := range s.values {
		next.Values[tenant] = append([]string(nil), values...)
	}
	return next
}
func (s *dlpAllowlistRuntimeStore) saveSnapshotLocked(next allowlistStoreSnapshot) error {
	if s.persister == nil {
		return nil
	}
	data, err := json.Marshal(next)
	if err != nil {
		return err
	}
	return s.persister.Save(data)
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

// PersistIfDirty serializes staged saves with admin commits and retains dirty on error.
func (s *dlpAllowlistRuntimeStore) PersistIfDirty() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty || s.persister == nil {
		return nil
	}
	if err := s.saveSnapshotLocked(s.snapshotLocked()); err != nil {
		return err
	}
	s.dirty = false
	return nil
}

// dlpAllowlistProvider supplies the compiled allowlist for a tenant to the egress DLP scan path.
type dlpAllowlistProvider interface {
	AllowlistForTenant(tenantID string) *dlp.Allowlist
}
