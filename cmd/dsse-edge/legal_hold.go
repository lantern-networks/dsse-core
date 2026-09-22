package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
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
	writeMu     sync.Mutex
	sharedKnown bool
	mu          sync.RWMutex
	held        map[string]legalHoldRecord // confirmed tenant_id -> record
	pending     map[string]bool            // failed hold additions; local only, never snapshot-saved
	persister   blobstore.Persister
	loadErr     error
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
	var records []legalHoldRecord
	if err := json.Unmarshal(data, &records); err != nil {
		s.loadErr = err
		log.Printf("legal-hold store parse: %v", err)
		return s
	}
	if records == nil {
		s.loadErr = fmt.Errorf("legal hold snapshot must be an array")
		return s
	}
	for _, r := range records {
		tenant := strings.TrimSpace(r.TenantID)
		if tenant == "" {
			s.loadErr = fmt.Errorf("legal hold record has no tenant")
			return s
		}
		if _, exists := s.held[tenant]; exists {
			s.loadErr = fmt.Errorf("duplicate legal hold tenant")
			return s
		}
		r.TenantID = tenant
		s.held[tenant] = r
	}
	if len(s.held) > 0 {
		log.Printf("legal-hold store loaded: %d tenant(s) under hold", len(s.held))
	}
	return s
}

// IsHeld reports whether a tenant's logs are under legal hold (the retention pruner must skip it).
func (s *legalHoldStore) IsHeld(tenantID string) bool {
	if s == nil {
		return false
	}
	if err := s.refreshShared(); err != nil {
		return true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.loadErr != nil {
		return true
	}
	_, ok := s.held[tenantID]
	return ok || s.pending[tenantID]
}

// Set places or releases a legal hold on a tenant and persists the change.
func (s *legalHoldStore) setLocal(tenantID, heldBy, reason string, active bool, now time.Time) error {
	if s == nil || tenantID == "" {
		return fmt.Errorf("legal hold store or tenant is unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadErr != nil {
		return fmt.Errorf("legal hold state is unavailable; restore storage and restart")
	}
	previous, existed := s.held[tenantID]
	if active {
		if _, exists := s.held[tenantID]; !exists {
			s.held[tenantID] = legalHoldRecord{TenantID: tenantID, HeldSince: now.UTC().Format(time.RFC3339), HeldBy: heldBy, Reason: reason}
		}
	} else {
		delete(s.held, tenantID)
	}
	if err := s.persistLocked(); err != nil {
		if existed {
			s.held[tenantID] = previous
		} else {
			delete(s.held, tenantID)
		}
		if active {
			if s.pending == nil {
				s.pending = map[string]bool{}
			}
			s.pending[tenantID] = true
		}
		return err
	}
	delete(s.pending, tenantID)
	if active {
		log.Printf("legal_hold_set tenant=%s held=true by=%q", tenantID, heldBy)
	} else {
		log.Printf("legal_hold_set tenant=%s held=false", tenantID)
	}
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

func (s *legalHoldStore) persistLocked() error {
	if s.persister == nil {
		return nil
	}
	records := make([]legalHoldRecord, 0, len(s.held))
	for _, r := range s.held {
		records = append(records, r)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].TenantID < records[j].TenantID })
	data, err := json.Marshal(records)
	if err != nil {
		return fmt.Errorf("marshal legal hold: %w", err)
	}
	if err := s.persister.Save(data); err != nil {
		return fmt.Errorf("persist legal hold: %w", err)
	}
	return nil
}

// An unavailable snapshot cannot authorize deletion or be overwritten with partial state.
func (s *legalHoldStore) Health() error {
	if s == nil {
		return nil
	}
	if err := s.refreshShared(); err != nil {
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
