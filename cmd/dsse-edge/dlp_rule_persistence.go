package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/dlp"
	"github.com/lantern-networks/dsse-core/model"
)

// The authored rules share the DLP library's durable CP authority and signed
// config-bundle path. An explicit empty map is an authoritative clear; a nil
// bundle field means the publisher predates rule distribution.
type dlpRuleSnapshot struct {
	Rules map[string][]model.DLPRule `json:"rules"`
}

func (s *dlpRuleRuntimeStore) Generation() uint64 {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.generation
}

func (s *dlpRuleRuntimeStore) snapshotLocked() dlpRuleSnapshot {
	next := dlpRuleSnapshot{Rules: map[string][]model.DLPRule{}}
	if current := s.rules.Load(); current != nil {
		for tenant, rules := range *current {
			next.Rules[tenant] = cloneDLPRules(rules)
		}
	}
	return next
}

func (s *dlpRuleRuntimeStore) Snapshot() dlpRuleSnapshot {
	if s == nil {
		return dlpRuleSnapshot{Rules: map[string][]model.DLPRule{}}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshotLocked()
}

// Validate identity and shape without resolving custom classifier names. On
// boot the rule store is restored before classifier definitions are loaded;
// full linked validation runs at the admin and bundle apply boundaries.
func validateDLPRuleSnapshot(snap dlpRuleSnapshot) error {
	if snap.Rules == nil {
		return fmt.Errorf("DLP rule collection is missing")
	}
	for tenant, rules := range snap.Rules {
		if !validDLPLibraryTenant(tenant) {
			return fmt.Errorf("invalid DLP rule tenant")
		}
		for _, rule := range rules {
			if rule.TenantID != tenant || !dlp.KnownAction(dlp.Action(rule.OnMatch)) || len(rule.Identifiers) == 0 || !dlpKnownInstanceScope(rule.InstanceScope) || rule.MinCount < 0 {
				return fmt.Errorf("invalid DLP rule snapshot")
			}
			if rule.Status != "" && !strings.EqualFold(rule.Status, "active") && !strings.EqualFold(rule.Status, "disabled") {
				return fmt.Errorf("invalid DLP rule status")
			}
			for _, id := range rule.Identifiers {
				if id != strings.TrimSpace(id) || (!dlp.KnownIdentifier(dlp.IdentifierType(id)) && !dlp.ValidIdentifierName(id)) {
					return fmt.Errorf("invalid DLP rule identifier")
				}
			}
		}
	}
	return nil
}

func (s *dlpRuleRuntimeStore) SetPersister(p blobstore.Persister) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dirty {
		return fmt.Errorf("save pending DLP rule changes before replacing the persistence store")
	}
	if p == nil {
		s.persister = nil
		s.sharedKnown = false
		return nil
	}
	raw, err := p.Load()
	if err != nil {
		return err
	}
	if raw == nil {
		s.persister = p
		s.dirty = len(s.snapshotLocked().Rules) > 0
		return nil
	}
	var snap dlpRuleSnapshot
	if err := decodeDLPLibrarySnapshot(raw, "rules", &snap); err != nil {
		return err
	}
	if err := validateDLPRuleSnapshot(snap); err != nil {
		return err
	}
	if !reflect.DeepEqual(s.snapshotLocked().Rules, snap.Rules) {
		s.generation++
	}
	owned := map[string][]model.DLPRule{}
	for tenant, rules := range snap.Rules {
		owned[tenant] = cloneDLPRules(rules)
	}
	s.rules.Store(&owned)
	s.persister, s.dirty, s.sharedKnown = p, false, isDLPSharedPersister(p)
	return nil
}

func (s *dlpRuleRuntimeStore) saveSnapshotLocked(next dlpRuleSnapshot) error {
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

// SetRulesContext acknowledges only a confirmed save. A shared CP store uses
// the same transactional blob updater as the other detector-library stores.
func (s *dlpRuleRuntimeStore) SetRulesContext(ctx context.Context, tenant string, rules []model.DLPRule) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validDLPLibraryTenant(tenant) {
		return fmt.Errorf("invalid DLP rule tenant")
	}
	rules = cloneDLPRules(rules)
	for i := range rules {
		if rules[i].TenantID != tenant {
			return fmt.Errorf("invalid DLP rule tenant")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if isDLPSharedPersister(s.persister) {
		return s.mutateSharedLocked(ctx, func(next *dlpRuleRuntimeStore) error { return next.SetRulesContext(ctx, tenant, rules) })
	}
	next := s.snapshotLocked()
	if len(rules) == 0 {
		delete(next.Rules, tenant)
	} else {
		next.Rules[tenant] = rules
	}
	if err := validateDLPRuleSnapshot(next); err != nil {
		return err
	}
	if err := s.saveSnapshotLocked(next); err != nil {
		if errors.Is(err, blobstore.ErrDurabilityUnconfirmed) {
			s.rules.Store(&next.Rules)
			s.dirty = true
			s.generation++
		}
		return err
	}
	s.rules.Store(&next.Rules)
	s.dirty = false
	s.generation++
	return nil
}

func (s *dlpRuleRuntimeStore) PersistIfDirty() error {
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

func (s *dlpRuleRuntimeStore) sharedCandidateLocked(raw []byte) (*dlpRuleRuntimeStore, error) {
	next := newDLPRuleRuntimeStore()
	if err := loadDLPSharedCandidate(raw, s.sharedKnown || len(s.snapshotLocked().Rules) > 0, next); err != nil {
		return nil, err
	}
	return next, nil
}

func (s *dlpRuleRuntimeStore) adoptSharedLocked(next *dlpRuleRuntimeStore) {
	snapshot := next.snapshotLocked()
	if !reflect.DeepEqual(s.snapshotLocked().Rules, snapshot.Rules) {
		s.generation++
	}
	s.rules.Store(&snapshot.Rules)
	s.dirty = false
}

func (s *dlpRuleRuntimeStore) mutateSharedLocked(ctx context.Context, edit func(*dlpRuleRuntimeStore) error) error {
	if s.dirty {
		return fmt.Errorf("shared DLP state has uncommitted staged changes")
	}
	var accepted *dlpRuleRuntimeStore
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
		return fmt.Errorf("shared DLP rule mutation was not applied")
	}
	s.adoptSharedLocked(accepted)
	s.sharedKnown = true
	return nil
}

func (s *dlpRuleRuntimeStore) RefreshShared() error {
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
	s.sharedKnown = raw != nil
	return nil
}
