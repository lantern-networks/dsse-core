package main

import (
	"encoding/json"
	"sort"
	"sync"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/dlp"
)

// dlpFingerprintRuntimeStore holds operator Exact-Data-Match datasets per tenant (slice E). Each named dataset is
// an operator's sensitive value list (customer record ids, employee numbers, …) fingerprinted into SALTED HASHES.
// Unlike the classifier/allowlist stores it NEVER keeps the raw values — only the hashes — so the sensitive
// dataset is safe to persist on the edge and cannot be recovered from config; the admin API therefore exposes
// only each dataset's name + value count, never the values. Per-tenant, atomic hot-swap, durable.
type dlpFingerprintRuntimeStore struct {
	mu sync.RWMutex
	// tenant -> dataset name -> salted hashes (durable, non-secret)
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
	fp := dlp.NewFingerprint(name, s.tenantSalt(tenantID), values)
	hashes := fp.Hashes()
	s.mu.Lock()
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

// PersistIfDirty writes a snapshot when there are unsaved changes. Cheap no-op when clean or persister-less.
func (s *dlpFingerprintRuntimeStore) PersistIfDirty() error {
	s.mu.Lock()
	if !s.dirty || s.persister == nil {
		s.mu.Unlock()
		return nil
	}
	snap := fingerprintStoreSnapshot{Datasets: map[string]map[string][]string{}}
	for t, ds := range s.datasets {
		cp := map[string][]string{}
		for n, h := range ds {
			cp[n] = h
		}
		snap.Datasets[t] = cp
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

// dlpFingerprintProvider supplies the compiled EDM set for a tenant to the egress DLP scan path.
type dlpFingerprintProvider interface {
	FingerprintSetForTenant(tenantID string) *dlp.FingerprintSet
}
