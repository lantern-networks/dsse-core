package main

import (
	"encoding/json"
	"sort"
	"sync"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/dlp"
)

// dlpClassifierRuntimeStore holds the operator-defined custom DLP classifiers per tenant (slice C). It keeps two
// forms in lock-step: the authored specs (durable, serves the admin API) and a compiled *dlp.ClassifierSet (the
// scan-ready form the egress data path uses). A SetSpecs recompiles + republishes atomically so the hot path
// reads a live set without a lock or restart, mirroring dlpRuleRuntimeStore. Compilation errors are surfaced to
// the caller (the admin API) but never disable the classifiers that DID compile.
type dlpClassifierRuntimeStore struct {
	mu    sync.RWMutex
	specs map[string][]dlp.ClassifierSpec
	sets  map[string]*dlp.ClassifierSet // compiled, published for the data path
	// persister durably stores the per-tenant specs so operator classifiers survive an Edge restart.
	persister  blobstore.Persister
	dirty      bool
	generation uint64
}

func newDLPClassifierRuntimeStore() *dlpClassifierRuntimeStore {
	return &dlpClassifierRuntimeStore{specs: map[string][]dlp.ClassifierSpec{}, sets: map[string]*dlp.ClassifierSet{}}
}

// ClassifierSetForTenant returns the live compiled classifier set for a tenant (nil = none), for the scan path.
func (s *dlpClassifierRuntimeStore) ClassifierSetForTenant(tenantID string) *dlp.ClassifierSet {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sets[tenantID]
}

// SpecsForTenant returns a copy of the authored specs for a tenant (admin API GET).
func (s *dlpClassifierRuntimeStore) SpecsForTenant(tenantID string) []dlp.ClassifierSpec {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]dlp.ClassifierSpec(nil), s.specs[tenantID]...)
}

// SetSpecs replaces one tenant's classifiers: it recompiles them into a live set and publishes both forms. Any
// per-classifier compile errors are returned (so the admin sees which were rejected); the published set contains
// every classifier that compiled. Empty specs clear the tenant.
func (s *dlpClassifierRuntimeStore) SetSpecs(tenantID string, specs []dlp.ClassifierSpec) []error {
	set, errs := dlp.NewClassifierSet(specs)
	s.mu.Lock()
	if len(specs) == 0 {
		delete(s.specs, tenantID)
		delete(s.sets, tenantID)
	} else {
		s.specs[tenantID] = append([]dlp.ClassifierSpec(nil), specs...)
		s.sets[tenantID] = set
	}
	s.dirty = true
	s.generation++
	s.mu.Unlock()
	return errs
}

// Tenants returns the tenant ids that have classifiers, ordered (admin listing).
func (s *dlpClassifierRuntimeStore) Tenants() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.specs))
	for t := range s.specs {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// classifierStoreSnapshot is the on-disk shape (per-tenant authored specs).
type classifierStoreSnapshot struct {
	Specs map[string][]dlp.ClassifierSpec `json:"specs"`
}

// SetPersister attaches durable storage and rehydrates + recompiles the specs on boot (so operator classifiers
// survive a restart). Call once at startup; pair with a periodic PersistIfDirty flush. A load error is non-fatal.
func (s *dlpClassifierRuntimeStore) SetPersister(p blobstore.Persister) error {
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
	var snap classifierStoreSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for tenant, specs := range snap.Specs {
		if len(specs) == 0 {
			continue
		}
		set, _ := dlp.NewClassifierSet(specs) // invalid entries are skipped; the set holds what compiled
		s.specs[tenant] = specs
		s.sets[tenant] = set
	}
	return nil
}

// PersistIfDirty writes a snapshot when there are unsaved changes. Cheap no-op when clean or persister-less.
func (s *dlpClassifierRuntimeStore) PersistIfDirty() error {
	s.mu.Lock()
	if !s.dirty || s.persister == nil {
		s.mu.Unlock()
		return nil
	}
	snap := classifierStoreSnapshot{Specs: map[string][]dlp.ClassifierSpec{}}
	for t, sp := range s.specs {
		snap.Specs[t] = sp
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

// dlpClassifierProvider supplies the compiled custom-classifier set for a tenant to the egress DLP scan path.
type dlpClassifierProvider interface {
	ClassifierSetForTenant(tenantID string) *dlp.ClassifierSet
}
