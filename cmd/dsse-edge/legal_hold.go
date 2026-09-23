package main

import (
	"context"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
)

// Legal hold (litigation / e-discovery): while a tenant is under hold, ALL of its logs are preserved — the
// retention pruner skips it entirely, so nothing is deleted or tiered-then-deleted, overriding the normal
// retention window. A hold is an explicit operator action that must OUTLIVE a restart (a hold that silently
// vanished on reboot would be a compliance failure), so the store is durable via a Persister (file or, for CP
// HA, shared Postgres) with an atomic write.

type legalHoldRecord struct {
	TenantID  string `json:"tenant_id"`
	HeldSince string `json:"held_since"`
	HeldBy    string `json:"held_by,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

type legalHoldStore struct {
	erasures           map[string]tenantErasureFence
	snapshotVersion    int
	writeMu            cpWriterMutex
	pendingVersion     map[string]uint64
	nextPendingVersion uint64
	sharedKnown        bool
	mu                 sync.RWMutex
	held               map[string]legalHoldRecord // confirmed tenant_id -> record
	pending            map[string]bool            // failed hold additions; local only, never snapshot-saved
	persister          blobstore.Persister
	loadErr            error
}

func newLegalHoldStore(p blobstore.Persister) *legalHoldStore {
	s := &legalHoldStore{held: map[string]legalHoldRecord{}, persister: p}
	if p == nil {
		return s
	}
	data, err := p.Load()
	if err != nil {
		s.loadErr = err
		log.Printf("legal-hold store load: %v", err)
		return s
	}
	if len(data) == 0 {
		return s
	}
	s.sharedKnown = true
	snapshot, err := decodeHoldSnapshot(data, false)
	if err != nil {
		s.loadErr = err
		log.Printf("legal-hold store parse: %v", err)
		return s
	}
	s.held, s.erasures, s.snapshotVersion = snapshot.held(), snapshot.Erasures, snapshot.Version
	if len(s.held) > 0 {
		log.Printf("legal-hold store loaded: %d tenant(s) under hold", len(s.held))
	}
	return s
}

// IsHeld is a conservative deletion guard: accepted/pending holds, erasure fences
// and unavailable state all stop retention. Admin status distinguishes these.
func (s *legalHoldStore) IsHeld(tenantID string) bool {
	return s.IsHeldContext(context.Background(), tenantID)
}

func (s *legalHoldStore) IsHeldContext(ctx context.Context, tenantID string) bool {
	if s == nil {
		return false
	}
	if err := s.refreshSharedContext(ctx); err != nil {
		return true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.loadErr != nil {
		return true
	}
	_, ok := s.held[tenantID]
	return ok || s.pending[tenantID] || s.erasures[tenantID].ID != ""
}

// Set places or releases a legal hold on a tenant and persists the change.
// Caller holds writeMu. Keep confirmed state readable while Save is blocked;
// only publish a detached candidate after persistence succeeds.
func (s *legalHoldStore) setLocal(tenantID, heldBy, reason string, active bool, now time.Time) error {
	s.mu.RLock()
	if s.loadErr != nil {
		s.mu.RUnlock()
		return fmt.Errorf("legal hold state is unavailable; restore storage and restart")
	}
	if _, busy := s.erasures[tenantID]; busy {
		s.mu.RUnlock()
		return errTenantErasureInProgress
	}
	candidate := make(map[string]legalHoldRecord, len(s.held)+1)
	for k, v := range s.held {
		candidate[k] = v
	}
	version := s.pendingVersion[tenantID]
	fences, snapshotVersion := s.erasures, s.snapshotVersion
	s.mu.RUnlock()
	if active {
		if _, exists := candidate[tenantID]; !exists {
			candidate[tenantID] = legalHoldRecord{TenantID: tenantID, HeldSince: now.UTC().Format(time.RFC3339), HeldBy: heldBy, Reason: reason}
		}
	} else {
		delete(candidate, tenantID)
	}
	// writeMu prevents concurrent confirmed policy/erasure mutations.
	raw, err := encodeHoldSnapshot(candidate, fences, snapshotVersion)
	if err == nil && s.persister != nil {
		err = s.persister.Save(raw)
	}
	if err != nil {
		if active {
			s.rememberPendingHold(tenantID)
		}
		return fmt.Errorf("persist legal hold: %w", err)
	}
	s.mu.Lock()
	s.held = candidate
	if s.pendingVersion[tenantID] == version {
		delete(s.pending, tenantID)
		delete(s.pendingVersion, tenantID)
	}
	s.mu.Unlock()
	log.Printf("legal_hold_set tenant=%s held=%t by=%q", tenantID, active, heldBy)
	return nil
}

// List returns the current holds, sorted by tenant id.
func (s *legalHoldStore) List() []legalHoldRecord {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]legalHoldRecord, 0, len(s.held))
	for _, r := range s.held {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TenantID < out[j].TenantID })
	return out
}

// An unavailable snapshot cannot authorize deletion or be overwritten with partial state.
func (s *legalHoldStore) Health() error {
	return s.HealthContext(context.Background())
}

func (s *legalHoldStore) HealthContext(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if err := s.refreshSharedContext(ctx); err != nil {
		return err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.loadErr != nil {
		return fmt.Errorf("legal hold state is unavailable; restore storage and restart")
	}
	return nil
}

func (s *legalHoldStore) Set(tenantID, heldBy, reason string, active bool, now time.Time) error {
	return s.SetContext(context.Background(), tenantID, heldBy, reason, active, now)
}

// Pending reports process-local protection whose durable save is unconfirmed.
func (s *legalHoldStore) Pending(tenant string) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pending[tenant]
}
