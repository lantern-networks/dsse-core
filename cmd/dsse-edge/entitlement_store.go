package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/lantern-networks/dsse-core/blobstore"
)

// Per-tenant feature entitlements — the license/contract gate for optional PAID features (starting with DLP). A
// feature is entitled when explicitly granted for the tenant, or — when the tenant has no explicit entry — by the
// configurable default, so an unlicensed deployment can default a paid feature OFF while the lab defaults it ON.
// In production a license file/server drives SetFeature; here the admin API + the default flag do. Extensible:
// add a feature constant and gate on Entitled(tenant, feature).

// Feature names (license-gated capabilities).
const featureDLP = "dlp"

// knownFeatures is the set of gateable features (for listing / validation).
var knownFeatures = []string{featureDLP}

type entitlementStore struct {
	mu        sync.RWMutex
	features  map[string]map[string]bool // tenant -> feature -> granted (explicit)
	defaults  map[string]bool            // feature -> default when the tenant has no explicit entry
	persister blobstore.Persister
	dirty     bool
}

func newEntitlementStore(defaults map[string]bool) *entitlementStore {
	d := map[string]bool{}
	for k, v := range defaults {
		d[k] = v
	}
	return &entitlementStore{features: map[string]map[string]bool{}, defaults: d}
}

// Entitled reports whether a tenant is licensed for a feature: an explicit grant if present, else the default.
func (s *entitlementStore) Entitled(tenantID, feature string) bool {
	if s == nil {
		return true // no entitlement store wired → everything entitled (backward compatible)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if tf, ok := s.features[tenantID]; ok {
		if v, ok := tf[feature]; ok {
			return v
		}
	}
	return s.defaults[feature]
}

// FeaturesForTenant returns the resolved (explicit-or-default) state of every known feature for a tenant.
func (s *entitlementStore) FeaturesForTenant(tenantID string) map[string]bool {
	out := map[string]bool{}
	for _, f := range knownFeatures {
		out[f] = s.Entitled(tenantID, f)
	}
	return out
}

// SetFeature grants or revokes a feature for a tenant (license apply / admin override).
func (s *entitlementStore) SetFeature(tenantID, feature string, granted bool) {
	s.mu.Lock()
	if s.features[tenantID] == nil {
		s.features[tenantID] = map[string]bool{}
	}
	s.features[tenantID][feature] = granted
	s.dirty = true
	s.mu.Unlock()
}

// SetFeaturesContext acknowledges only confirmed persistence. Shared storage edits
// the latest row, preserving grants made by another control plane.
func (s *entitlementStore) SetFeaturesContext(ctx context.Context, tenant string, patch map[string]bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var next entitlementSnapshot
	edit := func(raw []byte) ([]byte, error) {
		next = entitlementSnapshot{Features: map[string]map[string]bool{}}
		if raw == nil && len(s.features) > 0 {
			return nil, fmt.Errorf("entitlement authority is missing")
		}
		if raw != nil {
			if err := json.Unmarshal(raw, &next); err != nil {
				return nil, err
			}
			if next.Features == nil {
				return nil, fmt.Errorf("invalid entitlement snapshot")
			}
		}
		if next.Features[tenant] == nil {
			next.Features[tenant] = map[string]bool{}
		}
		for f, granted := range patch {
			next.Features[tenant][f] = granted
		}
		return json.Marshal(next)
	}
	if p, ok := s.persister.(interface {
		UpdateContext(context.Context, func([]byte) ([]byte, error)) error
	}); ok {
		if err := p.UpdateContext(ctx, edit); err != nil {
			return err
		}
	} else {
		raw, err := json.Marshal(entitlementSnapshot{Features: s.features})
		if err != nil {
			return err
		}
		raw, err = edit(raw)
		if err != nil {
			return err
		}
		if s.persister != nil {
			if err := s.persister.Save(raw); err != nil &&
				(!errors.Is(err, blobstore.ErrSavedWithoutAtomicity) || errors.Is(err, blobstore.ErrDurabilityUnconfirmed)) {
				return err
			}
		}
	}
	s.features, s.dirty = next.Features, false
	return nil
}

// RefreshShared reads authority before administrative reads and feature gates.
func (s *entitlementStore) RefreshShared() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.persister.(interface {
		UpdateContext(context.Context, func([]byte) ([]byte, error)) error
	}); !ok {
		return nil
	}
	raw, err := s.persister.Load()
	if err != nil {
		return err
	}
	if raw == nil && len(s.features) > 0 {
		return fmt.Errorf("entitlement authority is missing")
	}
	next := entitlementSnapshot{Features: map[string]map[string]bool{}}
	if raw != nil {
		if err := json.Unmarshal(raw, &next); err != nil {
			return err
		}
		if next.Features == nil {
			return fmt.Errorf("invalid entitlement snapshot")
		}
	}
	s.features = next.Features
	return nil
}

// Tenants returns the tenant ids with explicit entitlements, ordered.
func (s *entitlementStore) Tenants() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.features))
	for t := range s.features {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

type entitlementSnapshot struct {
	Features map[string]map[string]bool `json:"features"`
}

// SetPersister attaches durable storage and rehydrates explicit entitlements on boot.
func (s *entitlementStore) SetPersister(p blobstore.Persister) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dirty {
		return fmt.Errorf("save pending entitlements before replacing storage")
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
	var snap entitlementSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	if snap.Features == nil {
		return fmt.Errorf("invalid entitlement snapshot")
	}
	s.features, s.persister = snap.Features, p
	return nil
}

// PersistIfDirty writes a snapshot when there are unsaved changes.
func (s *entitlementStore) PersistIfDirty() error {
	s.mu.Lock()
	if !s.dirty || s.persister == nil {
		s.mu.Unlock()
		return nil
	}
	snap := entitlementSnapshot{Features: map[string]map[string]bool{}}
	for t, tf := range s.features {
		cp := map[string]bool{}
		for f, v := range tf {
			cp[f] = v
		}
		snap.Features[t] = cp
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

// entitlementReader is the read side consumed by the egress DLP hook (nil = everything entitled).
type entitlementReader interface {
	Entitled(tenantID, feature string) bool
}
