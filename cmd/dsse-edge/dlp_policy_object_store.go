package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/dlp"
	"github.com/lantern-networks/dsse-core/model"
)

// validateDLPPolicyObject checks a named DLP Policy: a known action, at least one identifier (built-in, custom, or
// EDM dataset name — resolved against the tenant's library), a valid instance scope, and sane device-risk
// conditions.
func validateDLPPolicyObject(obj model.DLPPolicyObject, custom *dlp.ClassifierSet, edm *dlp.FingerprintSet) error {
	if !dlp.KnownAction(dlp.Action(obj.OnMatch)) {
		return fmt.Errorf("invalid on_match %q (want observe|warn|block|authenticate)", obj.OnMatch)
	}
	if len(obj.Identifiers) == 0 {
		return fmt.Errorf("at least one identifier is required")
	}
	edmNames := map[string]bool{}
	for _, n := range edm.Names() {
		edmNames[n] = true
	}
	for _, id := range obj.Identifiers {
		if !dlp.KnownIdentifier(dlp.IdentifierType(id)) && !custom.Has(id) && !edmNames[id] {
			return fmt.Errorf("unknown identifier %q (not a built-in, custom identifier, or EDM dataset)", id)
		}
	}
	if !dlpKnownInstanceScope(obj.InstanceScope) {
		return fmt.Errorf("invalid instance_scope %q (want any|corporate|personal)", obj.InstanceScope)
	}
	for i, c := range obj.DeviceRisk {
		if c.MinCount <= 0 && c.MinDistinctTypes <= 0 {
			return fmt.Errorf("device_risk[%d]: set min_count and/or min_distinct_types", i)
		}
		if c.DestinationClass != "" && c.DestinationClass != "any" && c.DestinationClass != "personal" {
			return fmt.Errorf("device_risk[%d]: invalid destination_class %q (want any|personal)", i, c.DestinationClass)
		}
	}
	return nil
}

// dlpPolicyObjectStore holds the reusable NAMED DLP Policy objects per tenant (S5, docs/dlp_policy_ux_integration.md
// ): each bundles detectors + action + instance scope + device-risk conditions. Egress rules SELECT one by id
// (DLPSpec.PolicyID); the edge resolves the reference at decision time. Per-tenant, atomic hot-swap, durable.
type dlpPolicyObjectStore struct {
	mu         sync.RWMutex
	byTenant   map[string]map[string]model.DLPPolicyObject // tenant -> id -> policy
	persister  blobstore.Persister
	dirty      bool
	generation uint64
}

func newDLPPolicyObjectStore() *dlpPolicyObjectStore {
	return &dlpPolicyObjectStore{byTenant: map[string]map[string]model.DLPPolicyObject{}}
}

// Get returns a named policy by id for a tenant.
func (s *dlpPolicyObjectStore) Get(tenantID, id string) (model.DLPPolicyObject, bool) {
	if s == nil {
		return model.DLPPolicyObject{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.byTenant[tenantID][id]
	return p, ok
}

// List returns a tenant's policies, ordered by name.
func (s *dlpPolicyObjectStore) List(tenantID string) []model.DLPPolicyObject {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.DLPPolicyObject, 0, len(s.byTenant[tenantID]))
	for _, p := range s.byTenant[tenantID] {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Upsert creates or replaces a named policy (id assumed set by the caller).
func (s *dlpPolicyObjectStore) Upsert(p model.DLPPolicyObject) {
	s.mu.Lock()
	if s.byTenant[p.TenantID] == nil {
		s.byTenant[p.TenantID] = map[string]model.DLPPolicyObject{}
	}
	s.byTenant[p.TenantID][p.ID] = p
	s.dirty = true
	s.generation++
	s.mu.Unlock()
}

// Delete removes a policy by id; reports whether it existed.
func (s *dlpPolicyObjectStore) Delete(tenantID, id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byTenant[tenantID][id]; !ok {
		return false
	}
	delete(s.byTenant[tenantID], id)
	s.dirty = true
	s.generation++
	return true
}

type dlpPolicyObjectSnapshot struct {
	ByTenant map[string]map[string]model.DLPPolicyObject `json:"by_tenant"`
}

// SetPersister attaches durable storage and rehydrates on boot.
func (s *dlpPolicyObjectStore) SetPersister(p blobstore.Persister) error {
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
	var snap dlpPolicyObjectSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if snap.ByTenant != nil {
		s.byTenant = snap.ByTenant
	}
	return nil
}

// PersistIfDirty writes a snapshot when there are unsaved changes.
func (s *dlpPolicyObjectStore) PersistIfDirty() error {
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

// Keep snapshot writes serialized with acknowledged edits, so a periodic flush
// cannot overwrite a newer, already-saved admin change.
func (s *dlpPolicyObjectStore) snapshotLocked() dlpPolicyObjectSnapshot {
	next := dlpPolicyObjectSnapshot{ByTenant: map[string]map[string]model.DLPPolicyObject{}}
	for tenant, rows := range s.byTenant {
		next.ByTenant[tenant] = map[string]model.DLPPolicyObject{}
		for id, obj := range rows {
			next.ByTenant[tenant][id] = obj
		}
	}
	return next
}
func (s *dlpPolicyObjectStore) saveSnapshotLocked(next dlpPolicyObjectSnapshot) error {
	if s.persister == nil {
		return nil
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	return s.persister.Save(raw)
}
func (s *dlpPolicyObjectStore) UpsertDurable(obj model.DLPPolicyObject) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.snapshotLocked()
	if next.ByTenant[obj.TenantID] == nil {
		next.ByTenant[obj.TenantID] = map[string]model.DLPPolicyObject{}
	}
	next.ByTenant[obj.TenantID][obj.ID] = obj
	if err := s.saveSnapshotLocked(next); err != nil {
		return err
	}
	s.byTenant, s.dirty = next.ByTenant, false
	s.generation++
	return nil
}
func (s *dlpPolicyObjectStore) DeleteDurable(tenant, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byTenant[tenant][id]; !ok {
		return false, nil
	}
	next := s.snapshotLocked()
	delete(next.ByTenant[tenant], id)
	if err := s.saveSnapshotLocked(next); err != nil {
		return false, err
	}
	s.byTenant, s.dirty = next.ByTenant, false
	s.generation++
	return true, nil
}

// dlpPolicyObjectResolver resolves a named DLP policy for a tenant (consumed by the egress hook).
type dlpPolicyObjectResolver interface {
	Get(tenantID, id string) (model.DLPPolicyObject, bool)
}
