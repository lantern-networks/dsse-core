package main

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/dlp"
	"github.com/lantern-networks/dsse-core/model"
)

// validateDLPPolicyObject checks a named DLP Policy: a known action, at least one identifier (built-in, custom, or
// EDM dataset name — resolved against the tenant's library), a valid instance scope, and sane device-risk
// conditions.
func validateDLPPolicyObject(obj model.DLPPolicyObject, custom *dlp.ClassifierSet, edm *dlp.FingerprintSet) error {
	if err := validateDLPPolicyShape(obj); err != nil {
		return err
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
	return nil
}

// Shape validation is independent of library load order. Linked detector
// existence is checked by the admin and bundle validators once libraries exist.
func validateDLPPolicyShape(obj model.DLPPolicyObject) error {
	if obj.ID != "" && !validDLPLibraryTenant(obj.ID) {
		return fmt.Errorf("invalid policy id")
	}
	if !dlp.KnownAction(dlp.Action(obj.OnMatch)) {
		return fmt.Errorf("invalid on_match %q (want observe|warn|block|authenticate)", obj.OnMatch)
	}
	if len(obj.Identifiers) == 0 {
		return fmt.Errorf("at least one identifier is required")
	}
	for _, id := range obj.Identifiers {
		if id != strings.TrimSpace(id) || (!dlp.KnownIdentifier(dlp.IdentifierType(id)) && !dlp.ValidIdentifierName(id)) {
			return fmt.Errorf("invalid identifier name")
		}
	}
	if obj.MinCount < 0 {
		return fmt.Errorf("min_count must not be negative")
	}
	if !dlpKnownInstanceScope(obj.InstanceScope) {
		return fmt.Errorf("invalid instance_scope %q (want any|corporate|personal)", obj.InstanceScope)
	}
	if obj.Status != "" && !strings.EqualFold(obj.Status, "active") && !strings.EqualFold(obj.Status, "disabled") {
		return fmt.Errorf("invalid policy status (want active|disabled)")
	}
	for i, c := range obj.DeviceRisk {
		if c.MinCount < 0 || c.MinDistinctTypes < 0 || c.WindowSeconds < 0 {
			return fmt.Errorf("device_risk[%d]: thresholds and window must not be negative", i)
		}
		if c.MinCount <= 0 && c.MinDistinctTypes <= 0 {
			return fmt.Errorf("device_risk[%d]: set min_count and/or min_distinct_types", i)
		}
		if c.DestinationClass != "" && c.DestinationClass != "any" && c.DestinationClass != "personal" {
			return fmt.Errorf("device_risk[%d]: invalid destination_class %q (want any|personal)", i, c.DestinationClass)
		}
	}
	return nil
}

// Normalize metadata at the write boundary to the same JSON values used by
// disk and bundle restores; reject unsupported values before changing state.
func prepareDLPPolicyObject(p model.DLPPolicyObject) (model.DLPPolicyObject, error) {
	if !validDLPLibraryTenant(p.TenantID) || !validDLPLibraryTenant(p.ID) {
		return model.DLPPolicyObject{}, fmt.Errorf("invalid policy identity")
	}
	if err := validateDLPPolicyShape(p); err != nil {
		return model.DLPPolicyObject{}, err
	}
	if p.Metadata != nil {
		raw, err := json.Marshal(p.Metadata)
		if err != nil {
			return model.DLPPolicyObject{}, fmt.Errorf("policy metadata must be JSON")
		}
		p.Metadata = nil
		if err := json.Unmarshal(raw, &p.Metadata); err != nil {
			return model.DLPPolicyObject{}, fmt.Errorf("policy metadata must be JSON")
		}
	}
	p.Identifiers = slices.Clone(p.Identifiers)
	p.DeviceRisk = slices.Clone(p.DeviceRisk)
	return p, nil
}

func cloneDLPPolicyJSON(v any) any {
	switch value := v.(type) {
	case map[string]any:
		if value == nil {
			return value
		}
		out := make(map[string]any, len(value))
		for k, item := range value {
			out[k] = cloneDLPPolicyJSON(item)
		}
		return out
	case []any:
		if value == nil {
			return value
		}
		out := make([]any, len(value))
		for i, item := range value {
			out[i] = cloneDLPPolicyJSON(item)
		}
		return out
	default:
		return v // Stored metadata contains only decoded JSON scalars here.
	}
}

func cloneDLPPolicyObject(p model.DLPPolicyObject) model.DLPPolicyObject {
	p.Identifiers = slices.Clone(p.Identifiers)
	p.DeviceRisk = slices.Clone(p.DeviceRisk)
	if p.Metadata != nil {
		p.Metadata = cloneDLPPolicyJSON(p.Metadata).(map[string]any)
	}
	return p
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
	if !ok || p.TenantID != tenantID || p.ID != id {
		return model.DLPPolicyObject{}, false
	}
	return cloneDLPPolicyObject(p), true
}

// List returns a tenant's policies, ordered by name.
func (s *dlpPolicyObjectStore) List(tenantID string) []model.DLPPolicyObject {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.DLPPolicyObject, 0, len(s.byTenant[tenantID]))
	for id, p := range s.byTenant[tenantID] {
		if p.TenantID != tenantID || p.ID != id {
			continue
		}
		out = append(out, cloneDLPPolicyObject(p))
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
func (s *dlpPolicyObjectStore) Upsert(p model.DLPPolicyObject) error {
	var err error
	p, err = prepareDLPPolicyObject(p)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.byTenant[p.TenantID] == nil {
		s.byTenant[p.TenantID] = map[string]model.DLPPolicyObject{}
	}
	s.byTenant[p.TenantID][p.ID] = p
	s.dirty = true
	s.generation++
	s.mu.Unlock()
	return nil
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

// SetPersister validates the complete snapshot before adopting state or writer.
// An unreadable or invalid file must not erase protection or redirect later saves.
func (s *dlpPolicyObjectStore) SetPersister(p blobstore.Persister) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dirty {
		return fmt.Errorf("save pending DLP policy changes before replacing the persistence store")
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
		s.dirty = len(s.byTenant) > 0
		return nil
	}
	var snap dlpPolicyObjectSnapshot
	if err := decodeDLPLibrarySnapshot(data, "by_tenant", &snap); err != nil {
		return err
	}
	for tenant, policies := range snap.ByTenant {
		if !validDLPLibraryTenant(tenant) || policies == nil {
			return fmt.Errorf("invalid DLP policy snapshot")
		}
		for id, obj := range policies {
			if !validDLPLibraryTenant(id) || obj.ID != id || obj.TenantID != tenant || validateDLPPolicyShape(obj) != nil {
				return fmt.Errorf("invalid DLP policy snapshot") // Never log saved content.
			}
		}
	}
	if !reflect.DeepEqual(s.byTenant, snap.ByTenant) {
		s.generation++
	}
	s.byTenant, s.persister, s.dirty = snap.ByTenant, p, false
	return nil
}

// snapshotLocked copies the maps so a failed save cannot publish the proposed edit.
func (s *dlpPolicyObjectStore) snapshotLocked() dlpPolicyObjectSnapshot {
	next := dlpPolicyObjectSnapshot{ByTenant: map[string]map[string]model.DLPPolicyObject{}}
	for tenant, items := range s.byTenant {
		next.ByTenant[tenant] = map[string]model.DLPPolicyObject{}
		for id, p := range items {
			next.ByTenant[tenant][id] = cloneDLPPolicyObject(p)
		}
	}
	return next
}

func (s *dlpPolicyObjectStore) saveSnapshotLocked(next dlpPolicyObjectSnapshot) error {
	if isDLPSharedPersister(s.persister) {
		return fmt.Errorf("shared DLP state requires a contextual mutation")
	}
	if s.persister == nil {
		return nil
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	return blobstore.UnconfirmedSave(s.persister.Save(raw))
}

// UpsertDurable acknowledges an admin edit only after the configured store accepts it.
func (s *dlpPolicyObjectStore) UpsertDurable(p model.DLPPolicyObject) error {
	return s.UpsertContext(context.Background(), p)
}
func (s *dlpPolicyObjectStore) UpsertContext(ctx context.Context, p model.DLPPolicyObject) error {
	var err error
	p, err = prepareDLPPolicyObject(p)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if isDLPSharedPersister(s.persister) {
		return s.mutateSharedLocked(ctx, func(next *dlpPolicyObjectStore) error { return next.UpsertDurable(p) })
	}
	next := s.snapshotLocked()
	if next.ByTenant[p.TenantID] == nil {
		next.ByTenant[p.TenantID] = map[string]model.DLPPolicyObject{}
	}
	next.ByTenant[p.TenantID][p.ID] = p
	if err := s.saveSnapshotLocked(next); err != nil {
		return err
	}
	s.byTenant = next.ByTenant
	s.dirty = false
	s.generation++
	return nil
}

func (s *dlpPolicyObjectStore) DeleteDurable(tenant, id string) (bool, error) {
	return s.DeleteContext(context.Background(), tenant, id)
}
func (s *dlpPolicyObjectStore) DeleteContext(ctx context.Context, tenant, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if isDLPSharedPersister(s.persister) {
		var result bool
		err := s.mutateSharedLocked(ctx, func(next *dlpPolicyObjectStore) error {
			var err error
			result, err = next.DeleteDurable(tenant, id)
			return err
		})
		if err != nil {
			return false, err
		}
		return result, err
	}
	_, existed := s.byTenant[tenant][id]
	if !existed && !s.dirty {
		return false, nil
	}
	next := s.snapshotLocked()
	delete(next.ByTenant[tenant], id)
	if err := s.saveSnapshotLocked(next); err != nil {
		return false, err
	}
	s.byTenant = next.ByTenant
	s.dirty = false
	if existed {
		s.generation++
	}
	return existed, nil
}

// Serialize periodic flushes with admin writes, so an older snapshot cannot
// overwrite a newer acknowledged edit. Failed flushes retain the dirty flag.
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

// dlpPolicyObjectResolver resolves a named DLP policy for a tenant (consumed by the egress hook).
type dlpPolicyObjectResolver interface {
	Get(tenantID, id string) (model.DLPPolicyObject, bool)
}

// sharedCandidateLocked reuses the complete restore validator and compilation.
// The detached candidate is never visible before the shared transaction commits.
func (s *dlpPolicyObjectStore) sharedCandidateLocked(raw []byte) (*dlpPolicyObjectStore, error) {
	next := newDLPPolicyObjectStore()
	if err := loadDLPSharedCandidate(raw, len(s.byTenant) > 0, next); err != nil {
		return nil, err
	}
	return next, nil
}
func (s *dlpPolicyObjectStore) adoptSharedLocked(next *dlpPolicyObjectStore) {
	if !reflect.DeepEqual(s.snapshotLocked(), next.snapshotLocked()) {
		s.generation++
	}
	s.byTenant = next.byTenant
	s.dirty = false
}
func (s *dlpPolicyObjectStore) mutateSharedLocked(ctx context.Context, edit func(*dlpPolicyObjectStore) error) error {
	if s.dirty {
		return fmt.Errorf("shared DLP state has uncommitted staged changes")
	}
	var accepted *dlpPolicyObjectStore
	err := s.persister.(dlpSharedUpdater).UpdateContext(ctx, func(raw []byte) ([]byte, error) {
		next, err := s.sharedCandidateLocked(raw)
		if err != nil {
			return nil, err
		}
		if err := edit(next); err != nil {
			return nil, err
		}
		data, err := json.Marshal(next.snapshotLocked())
		if err != nil {
			return nil, err
		}
		accepted = next
		return data, nil
	})
	if err != nil {
		return err
	}
	if accepted == nil {
		return fmt.Errorf("shared DLP mutation was not applied")
	}
	s.adoptSharedLocked(accepted)
	return nil
}
func (s *dlpPolicyObjectStore) RefreshShared() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !isDLPSharedPersister(s.persister) {
		return nil
	}
	if s.dirty {
		return fmt.Errorf("shared DLP state has uncommitted staged changes")
	}
	raw, err := s.persister.Load()
	if err != nil {
		return err
	}
	next, err := s.sharedCandidateLocked(raw)
	if err != nil {
		return err
	}
	s.adoptSharedLocked(next)
	return nil
}
