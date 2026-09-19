package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/dlp"
)

// dlpClassifierRuntimeStore holds the operator-defined custom DLP classifiers per tenant (slice C). It keeps two
// forms in lock-step: the authored specs (durable, serves the admin API) and a compiled *dlp.ClassifierSet (the
// scan-ready form the egress data path uses). Admin edits use SetSpecsDurable to save before
// publishing. Legacy SetSpecs callers stage changes for the periodic flush.
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
	return cloneClassifierSpecs(s.specs[tenantID])
}

// SetSpecs replaces one tenant's classifiers: it recompiles them into a live set and publishes both forms. Any
// per-classifier compile errors are returned to the legacy caller; the published set contains
// every classifier that compiled. Empty specs clear the tenant.
func (s *dlpClassifierRuntimeStore) SetSpecs(tenantID string, specs []dlp.ClassifierSpec) []error {
	specs = cloneClassifierSpecs(specs)
	set, errs := dlp.NewClassifierSet(specs)
	s.mu.Lock()
	if len(specs) == 0 {
		delete(s.specs, tenantID)
		delete(s.sets, tenantID)
	} else {
		s.specs[tenantID] = specs
		s.sets[tenantID] = set
	}
	s.dirty = true
	s.generation++
	s.mu.Unlock()
	return errs
}

// cloneClassifierSpecs also owns keyword lists; callers must not mutate authored
// definitions independently of the compiled scanner or the next disk snapshot.
func cloneClassifierSpecs(specs []dlp.ClassifierSpec) []dlp.ClassifierSpec {
	out := append([]dlp.ClassifierSpec(nil), specs...)
	for i := range out {
		out[i].Keywords = append([]string(nil), out[i].Keywords...)
	}
	return out
}

// SetSpecsDurable validates the entire replacement, then saves it before publishing
// either authored or compiled state. With no persister it remains in-memory only.
// A Save error may mean an unconfirmed write: do not report success or adopt it live.
func (s *dlpClassifierRuntimeStore) SetSpecsDurable(tenantID string, specs []dlp.ClassifierSpec) error {
	specs = cloneClassifierSpecs(specs)
	if len(specs) > dlp.MaxClassifiers {
		return fmt.Errorf("too many classifiers (max %d)", dlp.MaxClassifiers)
	}
	set, errs := dlp.NewClassifierSet(specs)
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.snapshotLocked()
	if len(specs) == 0 {
		delete(next.Specs, tenantID)
	} else {
		next.Specs[tenantID] = specs
	}
	if err := s.saveSnapshotLocked(next); err != nil {
		return err
	}
	s.specs = next.Specs
	if len(specs) == 0 {
		delete(s.sets, tenantID)
	} else {
		s.sets[tenantID] = set
	}
	s.dirty = false
	s.generation++
	return nil
}

func (s *dlpClassifierRuntimeStore) snapshotLocked() classifierStoreSnapshot {
	snap := classifierStoreSnapshot{Specs: map[string][]dlp.ClassifierSpec{}}
	for tenant, specs := range s.specs {
		snap.Specs[tenant] = cloneClassifierSpecs(specs)
	}
	return snap
}

func (s *dlpClassifierRuntimeStore) saveSnapshotLocked(snap classifierStoreSnapshot) error {
	if s.persister == nil {
		return nil
	}
	data, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	return s.persister.Save(data)
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

// SetPersister validates the complete library before adopting either state or
// writer. It must not publish a partly compiled snapshot or discard pending edits.
func (s *dlpClassifierRuntimeStore) SetPersister(p blobstore.Persister) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dirty {
		return fmt.Errorf("save pending classifier changes before replacing the persistence store")
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
		s.dirty = len(s.specs) > 0
		return nil
	}
	var snap classifierStoreSnapshot
	if err := decodeDLPLibrarySnapshot(data, "specs", &snap); err != nil {
		return err
	}
	next := map[string][]dlp.ClassifierSpec{}
	sets := map[string]*dlp.ClassifierSet{}
	for tenant, specs := range snap.Specs {
		if !validDLPLibraryTenant(tenant) || len(specs) > dlp.MaxClassifiers {
			return fmt.Errorf("invalid classifier snapshot")
		}
		if len(specs) == 0 {
			continue // Explicit [] or null for a tenant clears its definitions.
		}
		set, errs := dlp.NewClassifierSet(specs)
		if len(errs) > 0 {
			return fmt.Errorf("invalid classifier snapshot")
		}
		next[tenant], sets[tenant] = specs, set
	}
	if !reflect.DeepEqual(s.specs, next) {
		s.generation++
	}
	s.specs, s.sets, s.persister, s.dirty = next, sets, p, false
	return nil
}

// PersistIfDirty serializes periodic saves with admin commits, preventing an
// older snapshot from overwriting an acknowledged edit. Errors keep it dirty.
func (s *dlpClassifierRuntimeStore) PersistIfDirty() error {
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

// dlpClassifierProvider supplies the compiled custom-classifier set for a tenant to the egress DLP scan path.
type dlpClassifierProvider interface {
	ClassifierSetForTenant(tenantID string) *dlp.ClassifierSet
}
