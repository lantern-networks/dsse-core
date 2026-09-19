package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/lantern-networks/dsse-core/dlp"
	"github.com/lantern-networks/dsse-core/model"
)

// The installer gives Edge a scoped API token in the operator organization.
// It may read fleet configuration without receiving cross-tenant administration
// rights. Customer tokens and ordinary browser sessions do not qualify.
func configBundleFleetReader(r *http.Request, operator string) bool {
	identity, ok := adminIdentityFromRequest(r)
	return ok && strings.TrimSpace(operator) != "" &&
		strings.EqualFold(strings.TrimSpace(identity.TenantID), strings.TrimSpace(operator)) &&
		identity.AuthMethod == "admin_api_token" &&
		adminPermissionAllowed(identity.Roles, "admin.policy.read") &&
		adminScopeAllowed(identity, "admin.policy.read")
}

// Named policies are resolved at request time, so distributing only rule IDs
// silently drops their inspection. The signed config carries the definitions and
// detector library together. EDM carries salted hashes, never source values;
// allowlists carry the operator-declared known-safe values for local compilation.
type dlpConfigBundle struct {
	Policies    map[string]map[string]model.DLPPolicyObject `json:"policies"`
	Classifiers map[string][]dlp.ClassifierSpec             `json:"classifiers"`
	Datasets    map[string]map[string][]string              `json:"datasets"`
	Allowlists  map[string][]string                         `json:"allowlists"`
	Salt        string                                      `json:"salt"`
}

type dlpConfigStores struct {
	policies     *dlpPolicyObjectStore
	classifiers  *dlpClassifierRuntimeStore
	fingerprints *dlpFingerprintRuntimeStore
	allowlist    *dlpAllowlistRuntimeStore
}

func (s *dlpConfigStores) ready() bool {
	return s != nil && s.policies != nil && s.classifiers != nil && s.fingerprints != nil && s.allowlist != nil
}
func (s *dlpConfigStores) Generation() uint64 {
	if !s.ready() {
		return 0
	}
	s.policies.mu.RLock()
	defer s.policies.mu.RUnlock()
	s.classifiers.mu.RLock()
	defer s.classifiers.mu.RUnlock()
	s.fingerprints.mu.RLock()
	defer s.fingerprints.mu.RUnlock()
	s.allowlist.mu.RLock()
	defer s.allowlist.mu.RUnlock()
	return s.policies.generation + s.classifiers.generation + s.fingerprints.generation + s.allowlist.generation
}
func (s *dlpConfigStores) Snapshot() *dlpConfigBundle {
	if !s.ready() {
		return nil
	}
	s.policies.mu.RLock()
	defer s.policies.mu.RUnlock()
	s.classifiers.mu.RLock()
	defer s.classifiers.mu.RUnlock()
	s.fingerprints.mu.RLock()
	defer s.fingerprints.mu.RUnlock()
	s.allowlist.mu.RLock()
	defer s.allowlist.mu.RUnlock()
	raw, err := json.Marshal(dlpConfigBundle{Policies: s.policies.byTenant, Classifiers: s.classifiers.specs, Datasets: s.fingerprints.datasets, Salt: s.fingerprints.salt, Allowlists: s.allowlist.values})
	if err != nil {
		panic(err)
	} // Only concrete JSON data types, no custom marshalers.
	var out dlpConfigBundle
	if err := json.Unmarshal(raw, &out); err != nil {
		panic(err)
	}
	return &out
}

func (b *dlpConfigBundle) ForTenant(tenant string) *dlpConfigBundle {
	if b == nil {
		return nil
	}
	out := &dlpConfigBundle{Policies: map[string]map[string]model.DLPPolicyObject{}, Classifiers: map[string][]dlp.ClassifierSpec{}, Datasets: map[string]map[string][]string{}, Salt: b.Salt}
	// A nil section came from an older publisher; an explicit empty map clears.
	if b.Allowlists != nil {
		out.Allowlists = map[string][]string{}
		if values, ok := b.Allowlists[tenant]; ok {
			out.Allowlists[tenant] = append([]string(nil), values...)
		}
	}
	if rows, ok := b.Policies[tenant]; ok {
		out.Policies[tenant] = rows
	}
	if rows, ok := b.Classifiers[tenant]; ok {
		out.Classifiers[tenant] = rows
	}
	if rows, ok := b.Datasets[tenant]; ok {
		out.Datasets[tenant] = rows
	}
	return out
}
func (s *dlpConfigStores) Apply(b *dlpConfigBundle) error {
	if b == nil {
		return nil
	} // Older authorities leave the last accepted definitions intact.
	if !s.ready() {
		return fmt.Errorf("receiving stores unavailable")
	}
	if b.Policies == nil || b.Classifiers == nil || b.Datasets == nil {
		return fmt.Errorf("incomplete detector library")
	}
	// Own the received values; a caller cannot change live rules after validation.
	raw, err := json.Marshal(b)
	if err != nil {
		return err
	}
	var next dlpConfigBundle
	if err = json.Unmarshal(raw, &next); err != nil {
		return err
	}
	classifiers := map[string]*dlp.ClassifierSet{}
	for tenant, specs := range next.Classifiers {
		if strings.TrimSpace(tenant) == "" {
			return fmt.Errorf("classifier has no tenant")
		}
		set, errs := dlp.NewClassifierSet(specs)
		if len(errs) > 0 {
			return fmt.Errorf("invalid classifier in tenant %s: %v", tenant, errs[0])
		}
		classifiers[tenant] = set
	}
	fingerprints := map[string]*dlp.FingerprintSet{}
	for tenant, datasets := range next.Datasets {
		if strings.TrimSpace(tenant) == "" {
			return fmt.Errorf("dataset has no tenant")
		}
		var list []*dlp.Fingerprint
		for name, hashes := range datasets {
			if strings.TrimSpace(name) == "" {
				return fmt.Errorf("dataset has no name")
			}
			list = append(list, dlp.NewFingerprintFromHashes(name, next.Salt+"\x00"+tenant, hashes))
		}
		fingerprints[tenant] = dlp.NewFingerprintSet(list)
	}
	for tenant, policies := range next.Policies {
		for id, p := range policies {
			if strings.TrimSpace(tenant) == "" || id == "" || p.TenantID != tenant || p.ID != id {
				return fmt.Errorf("policy identity mismatch")
			}
			if err := validateDLPPolicyObject(p, classifiers[tenant], fingerprints[tenant]); err != nil {
				return fmt.Errorf("invalid policy %s: %w", id, err)
			}
		}
	}
	allowlists := map[string][]string{}
	for tenant, values := range next.Allowlists {
		if strings.TrimSpace(tenant) == "" {
			return fmt.Errorf("allowlist has no tenant")
		}
		values, err := validatedAllowlistValues(values)
		if err != nil {
			return fmt.Errorf("invalid allowlist: %w", err)
		}
		if len(values) > 0 {
			allowlists[tenant] = values
		}
	}
	// Validate all sections before changing any store, and publish dependencies first.
	s.policies.mu.Lock()
	defer s.policies.mu.Unlock()
	s.classifiers.mu.Lock()
	defer s.classifiers.mu.Unlock()
	s.fingerprints.mu.Lock()
	defer s.fingerprints.mu.Unlock()
	s.allowlist.mu.Lock()
	defer s.allowlist.mu.Unlock()
	// Refuse the entire library before publication when its suppression rules
	// cannot be saved. The polling caller retries the same generation.
	if next.Allowlists != nil {
		if err := s.allowlist.saveSnapshotLocked(allowlistStoreSnapshot{Values: allowlists}); err != nil {
			return fmt.Errorf("save DLP allowlist: %w", err)
		}
		compiled := map[string]*dlp.Allowlist{}
		for tenant, values := range allowlists {
			compiled[tenant] = dlp.NewAllowlist(s.allowlist.salt+"\x00"+tenant, values)
		}
		s.allowlist.values, s.allowlist.sets = allowlists, compiled
		s.allowlist.dirty = false
		s.allowlist.generation++
	}
	s.classifiers.specs, s.classifiers.sets = next.Classifiers, classifiers
	s.fingerprints.datasets, s.fingerprints.sets, s.fingerprints.salt = next.Datasets, fingerprints, next.Salt
	s.policies.byTenant = next.Policies
	s.policies.dirty, s.classifiers.dirty, s.fingerprints.dirty = true, true, true
	s.policies.generation++
	s.classifiers.generation++
	s.fingerprints.generation++
	return nil
}
