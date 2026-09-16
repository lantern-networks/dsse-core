package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/dlp"
)

// dlpFingerprintRuntimeStore holds operator Exact-Data-Match datasets per tenant (slice E). Each named dataset is
// an operator's sensitive value list (customer record ids, employee numbers, …) fingerprinted into SALTED HASHES.
// It retains hashes rather than raw values. Hashes and salts still require protection
// against guessing; the admin API exposes only dataset names and counts. Admin
// mutations confirm configured storage before changing the compiled scan set.
type dlpFingerprintRuntimeStore struct {
	mu sync.RWMutex
	// tenant -> dataset name -> salted hashes (durable)
	datasets   map[string]map[string][]string
	sets       map[string]*dlp.FingerprintSet // compiled per tenant (data path)
	salt       string
	persister  blobstore.Persister
	dirty      bool
	generation uint64
}

func newDLPFingerprintRuntimeStore(salt string) *dlpFingerprintRuntimeStore {
	return &dlpFingerprintRuntimeStore{datasets: map[string]map[string][]string{}, sets: map[string]*dlp.FingerprintSet{}, salt: salt}
}

// FingerprintSetForTenant returns the live compiled EDM set for a tenant (nil = none), for the scan path.
func (s *dlpFingerprintRuntimeStore) FingerprintSetForTenant(tenantID string) *dlp.FingerprintSet {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sets[tenantID]
}

// dlpFingerprintDataset is the non-secret description of a dataset (name + how many values fingerprinted).
type dlpFingerprintDataset struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// DatasetsForTenant returns the tenant's datasets as name+count (NON-SECRET — never the values), for the admin API.
func (s *dlpFingerprintRuntimeStore) DatasetsForTenant(tenantID string) []dlpFingerprintDataset {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]dlpFingerprintDataset, 0, len(s.datasets[tenantID]))
	for name, hashes := range s.datasets[tenantID] {
		out = append(out, dlpFingerprintDataset{Name: name, Count: len(hashes)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// tenantSalt derives the per-tenant salt so a value fingerprints differently per tenant.
func (s *dlpFingerprintRuntimeStore) tenantSalt(tenantID string) string {
	return s.salt + "\x00" + tenantID
}

// SetDataset fingerprints raw values (transit only) into dataset `name` for a tenant, storing ONLY the hashes,
// and recompiles the tenant's live set. Returns the resulting value count.
func (s *dlpFingerprintRuntimeStore) SetDataset(tenantID, name string, values []string) int {
	s.mu.Lock()
	fp := dlp.NewFingerprint(name, s.tenantSalt(tenantID), values)
	hashes := fp.Hashes()
	if s.datasets[tenantID] == nil {
		s.datasets[tenantID] = map[string][]string{}
	}
	if len(hashes) == 0 {
		delete(s.datasets[tenantID], name)
	} else {
		s.datasets[tenantID][name] = hashes
	}
	s.recompileLocked(tenantID)
	s.dirty = true
	s.generation++
	s.mu.Unlock()
	return len(hashes)
}

// RemoveDataset deletes a named dataset for a tenant and recompiles. Reports whether it existed.
func (s *dlpFingerprintRuntimeStore) RemoveDataset(tenantID, name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.datasets[tenantID][name]; !ok {
		return false
	}
	delete(s.datasets[tenantID], name)
	if len(s.datasets[tenantID]) == 0 {
		delete(s.datasets, tenantID)
	}
	s.recompileLocked(tenantID)
	s.dirty = true
	s.generation++
	return true
}

const maxFingerprintValues = 100000

var errInvalidFingerprintDataset = errors.New("invalid fingerprint dataset")

// SetDatasetDurable refuses empty or unscannable replacements and confirms the
// configured store before publishing the new compiled set. No raw values are saved.
func (s *dlpFingerprintRuntimeStore) SetDatasetDurable(tenantID, name string, values []string) (int, error) {
	if !dlp.ValidIdentifierName(name) || len(values) > maxFingerprintValues {
		return 0, fmt.Errorf("%w: invalid name or too many values", errInvalidFingerprintDataset)
	}
	if err := dlp.ValidateFingerprintValues(values); err != nil {
		return 0, fmt.Errorf("%w: %v", errInvalidFingerprintDataset, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	hashes := dlp.NewFingerprint(name, s.tenantSalt(tenantID), values).Hashes()
	if len(hashes) == 0 {
		return 0, fmt.Errorf("%w: supply at least one supported value of five or more characters after normalization; use Delete to remove a dataset", errInvalidFingerprintDataset)
	}
	next := s.snapshotLocked()
	if next.Datasets[tenantID] == nil {
		next.Datasets[tenantID] = map[string][]string{}
	}
	next.Datasets[tenantID][name] = hashes
	if err := s.saveSnapshotLocked(next); err != nil {
		return 0, err
	}
	s.datasets = next.Datasets
	s.recompileLocked(tenantID)
	s.dirty = false
	s.generation++
	return len(hashes), nil
}

// RemoveDatasetDurable saves before removing a live dataset. A missing name is a
// no-op, but pending staged changes still have to reach the configured store.
func (s *dlpFingerprintRuntimeStore) RemoveDatasetDurable(tenantID, name string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, exists := s.datasets[tenantID][name]
	if !exists && !s.dirty {
		return false, nil
	}
	next := s.snapshotLocked()
	delete(next.Datasets[tenantID], name)
	if len(next.Datasets[tenantID]) == 0 {
		delete(next.Datasets, tenantID)
	}
	if err := s.saveSnapshotLocked(next); err != nil {
		return false, err
	}
	s.datasets = next.Datasets
	s.recompileLocked(tenantID)
	s.dirty = false
	if exists {
		s.generation++
	}
	return exists, nil
}

func (s *dlpFingerprintRuntimeStore) snapshotLocked() fingerprintStoreSnapshot {
	next := fingerprintStoreSnapshot{Datasets: map[string]map[string][]string{}}
	for tenant, datasets := range s.datasets {
		next.Datasets[tenant] = map[string][]string{}
		for name, hashes := range datasets {
			next.Datasets[tenant][name] = append([]string(nil), hashes...)
		}
	}
	return next
}
func (s *dlpFingerprintRuntimeStore) saveSnapshotLocked(next fingerprintStoreSnapshot) error {
	if s.persister == nil {
		return nil
	}
	data, err := json.Marshal(next)
	if err != nil {
		return err
	}
	return s.persister.Save(data)
}

// recompileLocked rebuilds the tenant's compiled FingerprintSet from the stored hashes. Caller holds the lock.
func (s *dlpFingerprintRuntimeStore) recompileLocked(tenantID string) {
	fps := make([]*dlp.Fingerprint, 0, len(s.datasets[tenantID]))
	for name, hashes := range s.datasets[tenantID] {
		fps = append(fps, dlp.NewFingerprintFromHashes(name, s.tenantSalt(tenantID), hashes))
	}
	if len(fps) == 0 {
		delete(s.sets, tenantID)
		return
	}
	s.sets[tenantID] = dlp.NewFingerprintSet(fps)
}

// Tenants returns the tenant ids with datasets, ordered.
func (s *dlpFingerprintRuntimeStore) Tenants() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.datasets))
	for t := range s.datasets {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

type fingerprintStoreSnapshot struct {
	Datasets map[string]map[string][]string `json:"datasets"` // tenant -> name -> hashes
}

// SetPersister attaches durable storage and rehydrates + recompiles the datasets on boot (hashes only).
func (s *dlpFingerprintRuntimeStore) SetPersister(p blobstore.Persister) error {
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
	var snap fingerprintStoreSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for tenant, ds := range snap.Datasets {
		if len(ds) == 0 {
			continue
		}
		s.datasets[tenant] = ds
		s.recompileLocked(tenant)
	}
	return nil
}

// PersistIfDirty serializes staged saves with admin commits, so an old flush
// cannot overwrite an acknowledged mutation. Failed saves retain the dirty flag.
func (s *dlpFingerprintRuntimeStore) PersistIfDirty() error {
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

// dlpFingerprintProvider supplies the compiled EDM set for a tenant to the egress DLP scan path.
type dlpFingerprintProvider interface {
	FingerprintSetForTenant(tenantID string) *dlp.FingerprintSet
}
