// Package vlan implements VLAN boundary enforcement: VLAN/Subnet object definitions + inter-VLAN boundary
// policies (source class -> dest class, service family, observe|warn|deny) and a policy export to an existing
// firewall / L3 / router. Enforcement at the VLAN boundary is done by the firewall/L3 consuming the export
// (or a later network-enforcement connector); the Edge is the policy authority, not the inline PEP for
// VLAN-originated traffic.
package vlan

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/model"
)

var validClass = map[string]bool{"managed_endpoint": true, "unmanaged_endpoint": true, "server": true, "management": true}
var validMode = map[string]bool{"observe": true, "warn": true, "deny": true}

// Store holds VLAN objects + inter-VLAN boundary policies with a monotonic config generation. As a separate
// store, its generation folds into the config bundle's aggregate (the sum of per-store generations), so any
// mutation advances the bundle generation and config-pulling Edges re-pull.
type Store struct {
	mu         sync.RWMutex
	objects    map[string]model.VLANObject
	policies   map[string]model.VLANBoundaryPolicy
	generation atomic.Uint64
	// persister, when set, makes the Named Networks (VLAN objects) + boundary policies DURABLE: they survive an
	// Edge restart/recreate instead of being wiped (they used to be in-memory only, so the Networks catalog went
	// empty on every rebuild). Nil = in-memory only.
	persister blobstore.Persister
}

// vlanPersistSnapshot is the on-disk shape: the full object + policy sets.
type vlanPersistSnapshot struct {
	Objects  map[string]model.VLANObject         `json:"objects"`
	Policies map[string]model.VLANBoundaryPolicy `json:"policies"`
}

// NewStore returns an empty VLAN boundary store.
func NewStore() *Store {
	return &Store{objects: map[string]model.VLANObject{}, policies: map[string]model.VLANBoundaryPolicy{}}
}

// SetPersister enables durable persistence (Named Networks + boundary policies survive a restart). It loads any
// prior snapshot immediately, then every mutation re-saves the full set. Nil disables persistence.
// Persisted says whether this store is backed by durable storage. It answers a question a DISTRIBUTOR has to
// ask before telling anyone its set is empty: an in-memory store that has just restarted is empty for a reason
// that is not "there are none", and a receiver cannot tell the two apart from the payload alone.
func (s *Store) Persisted() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.persister != nil
}

func (s *Store) SetPersister(p blobstore.Persister) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.persister = p
	if p == nil {
		return nil
	}
	data, err := p.Load()
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	var snap vlanPersistSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	if snap.Objects != nil {
		s.objects = snap.Objects
	}
	if snap.Policies != nil {
		s.policies = snap.Policies
	}
	return nil
}

// OnPersistError, when set, logs a failed save in addition to the object's returned error.
// Other legacy mutations still use persistLocked and only report through this callback.
var OnPersistError func(error)

// ErrPersistence means a Network object change was not confirmed in storage.
// A failed save may still have reached the destination; callers must not report success.
var ErrPersistence = errors.New("network storage unconfirmed")

// saveObjectCandidateLocked saves the proposed object catalogue before publishing it to live readers.
// A non-atomic replacement warning means the bytes were saved; other errors leave live state unchanged.
func (s *Store) saveObjectCandidateLocked(objects map[string]model.VLANObject) error {
	if s.persister == nil {
		return nil
	}
	data, err := json.Marshal(vlanPersistSnapshot{Objects: objects, Policies: s.policies})
	if err == nil {
		err = s.persister.Save(data)
	}
	if err != nil && !errors.Is(err, blobstore.ErrSavedWithoutAtomicity) {
		s.reportPersistError(err)
		return fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return nil
}

// persistLocked writes the full snapshot. The CALLER must hold s.mu. No-op without a persister.
func (s *Store) persistLocked() {
	if s.persister == nil {
		return
	}
	data, err := json.Marshal(vlanPersistSnapshot{Objects: s.objects, Policies: s.policies})
	if err != nil {
		s.reportPersistError(fmt.Errorf("marshal vlan snapshot: %w", err))
		return
	}
	if err := s.persister.Save(data); err != nil {
		s.reportPersistError(fmt.Errorf("save vlan snapshot: %w", err))
	}
}

func (s *Store) reportPersistError(err error) {
	if OnPersistError != nil {
		OnPersistError(err)
	}
}

// ConfigGeneration returns the monotonic VLAN config version (bumped on each mutation).
func (s *Store) ConfigGeneration() uint64 {
	if s == nil {
		return 0
	}
	return s.generation.Load()
}

// ReplaceAll atomically replaces the WHOLE VLAN object + boundary-policy set under one lock (config
// distribution: a config-pulling Edge swaps in the control plane's authoritative set). Entries without an id
// are skipped. Bumps the generation.
func (s *Store) ReplaceAll(objects []model.VLANObject, policies []model.VLANBoundaryPolicy) {
	if s == nil {
		return
	}
	objMap := make(map[string]model.VLANObject, len(objects))
	for _, o := range objects {
		if strings.TrimSpace(o.ID) == "" {
			continue
		}
		objMap[o.ID] = o
	}
	polMap := make(map[string]model.VLANBoundaryPolicy, len(policies))
	for _, p := range policies {
		if strings.TrimSpace(p.ID) == "" {
			continue
		}
		polMap[p.ID] = p
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objects = objMap
	s.policies = polMap
	s.generation.Add(1)
	s.persistLocked()
}

func (s *Store) UpsertObject(o model.VLANObject) (model.VLANObject, error) {
	if strings.TrimSpace(o.ID) == "" {
		return model.VLANObject{}, fmt.Errorf("vlan object id is required")
	}
	if !validClass[strings.TrimSpace(o.Class)] {
		return model.VLANObject{}, fmt.Errorf("invalid class %q (want managed_endpoint|unmanaged_endpoint|server|management)", o.Class)
	}
	if len(o.CIDRs) == 0 {
		return model.VLANObject{}, fmt.Errorf("at least one cidr is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	objects := make(map[string]model.VLANObject, len(s.objects)+1)
	for id, existing := range s.objects {
		objects[id] = existing
	}
	objects[o.ID] = o
	if err := s.saveObjectCandidateLocked(objects); err != nil {
		return model.VLANObject{}, err
	}
	s.objects = objects
	s.generation.Add(1) // distributed via the config bundle: advance so Edges re-pull
	return o, nil
}

func (s *Store) UpsertPolicy(p model.VLANBoundaryPolicy) (model.VLANBoundaryPolicy, error) {
	if strings.TrimSpace(p.ID) == "" {
		return model.VLANBoundaryPolicy{}, fmt.Errorf("vlan boundary policy id is required")
	}
	if !validClass[strings.TrimSpace(p.SourceClass)] || !validClass[strings.TrimSpace(p.DestClass)] {
		return model.VLANBoundaryPolicy{}, fmt.Errorf("invalid source_class/dest_class")
	}
	mode := strings.TrimSpace(p.Mode)
	if mode == "" {
		mode = "deny"
	}
	if !validMode[mode] {
		return model.VLANBoundaryPolicy{}, fmt.Errorf("invalid mode %q (want observe|warn|deny)", p.Mode)
	}
	p.Mode = mode
	if strings.TrimSpace(p.Status) == "" {
		p.Status = "active"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies[p.ID] = p
	s.generation.Add(1) // distributed via the config bundle: advance so Edges re-pull
	s.persistLocked()
	return p, nil
}

func (s *Store) ListObjects() []model.VLANObject {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.VLANObject, 0, len(s.objects))
	for _, o := range s.objects {
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// DeleteObject removes the VLAN object (Named Network) with the given id. Reports whether it existed. Bumps the
// generation (distributed via the config bundle). Nil-safe. (Boundary policies referencing a deleted object's
// class are unaffected — they key on class, not object id.)
func (s *Store) DeleteObject(id string) (bool, error) {
	if s == nil {
		return false, nil
	}
	id = strings.TrimSpace(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.objects[id]; !ok {
		return false, nil
	}
	objects := make(map[string]model.VLANObject, len(s.objects)-1)
	for key, existing := range s.objects {
		if key != id {
			objects[key] = existing
		}
	}
	if err := s.saveObjectCandidateLocked(objects); err != nil {
		return false, err
	}
	s.objects = objects
	s.generation.Add(1)
	return true, nil
}

// GetObject returns the VLAN object (a Named Network — a named CIDR range) with the given id. Used by the
// connector route layer to resolve a binding that REFERENCES a Named Network to its CIDRs, so a subnet defined
// once here is reused for connector routing (see docs/unified_network_object_design.md). Nil-safe.
func (s *Store) GetObject(id string) (model.VLANObject, bool) {
	if s == nil {
		return model.VLANObject{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	o, ok := s.objects[strings.TrimSpace(id)]
	return o, ok
}

func (s *Store) ListPolicies() []model.VLANBoundaryPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.VLANBoundaryPolicy, 0, len(s.policies))
	for _, p := range s.policies {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ExportedFirewallRule is a normalized, firewall-agnostic rule a firewall / L3 / router (or a network
// enforcement connector) translates to its native syntax.
type ExportedFirewallRule struct {
	PolicyID      string   `json:"policy_id"`
	SourceClass   string   `json:"source_class"`
	DestClass     string   `json:"dest_class"`
	SourceCIDRs   []string `json:"source_cidrs"`
	DestCIDRs     []string `json:"dest_cidrs"`
	ServiceFamily string   `json:"service_family"`
	Ports         []int    `json:"ports"`
	Action        string   `json:"action"` // log | log_alert | deny (from observe | warn | deny)
}

// BoundaryExport is the firewall-export document expanded from the active boundary policies.
type BoundaryExport struct {
	SchemaVersion       string                 `json:"schema_version"`
	GeneratedAt         string                 `json:"generated_at"`
	RuleCount           int                    `json:"rule_count"`
	Rules               []ExportedFirewallRule `json:"rules"`
	NoSecretAttestation bool                   `json:"no_secret_attestation"`
}

var modeToAction = map[string]string{"observe": "log", "warn": "log_alert", "deny": "deny"}

// BuildBoundaryExport expands active boundary policies into concrete firewall rules by resolving
// source/destination classes to the CIDRs of the matching VLAN objects. Pure function (testable).
func BuildBoundaryExport(objects []model.VLANObject, policies []model.VLANBoundaryPolicy, generatedAt string) BoundaryExport {
	cidrsByClass := map[string][]string{}
	for _, o := range objects {
		cidrsByClass[strings.TrimSpace(o.Class)] = append(cidrsByClass[strings.TrimSpace(o.Class)], o.CIDRs...)
	}
	rules := make([]ExportedFirewallRule, 0, len(policies))
	for _, p := range policies {
		if strings.TrimSpace(p.Status) != "active" {
			continue
		}
		src := cidrsByClass[strings.TrimSpace(p.SourceClass)]
		dst := cidrsByClass[strings.TrimSpace(p.DestClass)]
		if len(src) == 0 || len(dst) == 0 {
			continue // a class with no defined VLAN object yields no concrete rule
		}
		rules = append(rules, ExportedFirewallRule{
			PolicyID: p.ID, SourceClass: p.SourceClass, DestClass: p.DestClass,
			SourceCIDRs: append([]string(nil), src...), DestCIDRs: append([]string(nil), dst...),
			ServiceFamily: p.ServiceFamily, Ports: append([]int(nil), p.Ports...),
			Action: modeToAction[p.Mode],
		})
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].PolicyID < rules[j].PolicyID })
	return BoundaryExport{
		SchemaVersion: "vlan_boundary_export.v1", GeneratedAt: generatedAt,
		RuleCount: len(rules), Rules: rules, NoSecretAttestation: true,
	}
}

// CountForTenant returns how many Named Networks and boundary policies this store still holds for a tenant.
// It is what a tenant DATA FOOTPRINT reads: a store that cannot be counted cannot appear in the answer, and a
// store that does not appear reads as "there was nothing here" — which is the one thing a footprint must never
// say by accident.
func (s *Store) CountForTenant(tenantID string) (objects int, policies int) {
	if s == nil {
		return 0, 0
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return 0, 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, o := range s.objects {
		if strings.EqualFold(strings.TrimSpace(o.TenantID), tenantID) {
			objects++
		}
	}
	for _, p := range s.policies {
		if strings.EqualFold(strings.TrimSpace(p.TenantID), tenantID) {
			policies++
		}
	}
	return objects, policies
}

// RemoveTenant erases every Named Network and boundary policy belonging to a tenant, returning the counts.
//
// ★ IT EXISTS BECAUSE "COMPLETELY DELETED" LEFT THEM BEHIND (2026-08-18, measured on the reference deployment).
// A disposable organization was created, given one Named Network, deleted, and then erased. The erasure
// answered complete=true with remaining.total=0 — and the Named Network was still there, with that
// organization's id on it. The footprint counted 34 stores and this was not one of them, so the answer could
// not have been anything else: a store nobody counts contributes nothing to "what is left".
//
// The API is per-tenant rather than per-id on purpose. DeleteObject(id) is what a handler uses; an erasure asks
// a different question — "everything of theirs" — and answering it by listing and filtering at every call site
// is how one call site ends up filtering differently.
func (s *Store) RemoveTenant(tenantID string) (objects int, policies int) {
	if s == nil {
		return 0, 0
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return 0, 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, o := range s.objects {
		if strings.EqualFold(strings.TrimSpace(o.TenantID), tenantID) {
			delete(s.objects, id)
			objects++
		}
	}
	for id, p := range s.policies {
		if strings.EqualFold(strings.TrimSpace(p.TenantID), tenantID) {
			delete(s.policies, id)
			policies++
		}
	}
	if objects+policies > 0 {
		s.generation.Add(1)
		s.persistLocked()
	}
	return objects, policies
}
