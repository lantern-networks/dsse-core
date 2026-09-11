package main

import (
	"encoding/json"
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
	mu        sync.RWMutex
	held      map[string]legalHoldRecord // tenant_id -> record
	persister blobstore.Persister
}

func newLegalHoldStore(p blobstore.Persister) *legalHoldStore {
	s := &legalHoldStore{held: map[string]legalHoldRecord{}, persister: p}
	if p == nil {
		return s
	}
	data, err := p.Load()
	if err != nil {
		log.Printf("legal-hold store load: %v", err)
		return s
	}
	if len(data) == 0 {
		return s
	}
	var records []legalHoldRecord
	if err := json.Unmarshal(data, &records); err != nil {
		log.Printf("legal-hold store parse: %v", err)
		return s
	}
	for _, r := range records {
		if r.TenantID != "" {
			s.held[r.TenantID] = r
		}
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
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.held[tenantID]
	return ok
}

// Set places or releases a legal hold on a tenant and persists the change.
func (s *legalHoldStore) Set(tenantID, heldBy, reason string, active bool, now time.Time) {
	if s == nil || tenantID == "" {
		return
	}
	s.mu.Lock()
	if active {
		if _, exists := s.held[tenantID]; !exists {
			s.held[tenantID] = legalHoldRecord{TenantID: tenantID, HeldSince: now.UTC().Format(time.RFC3339), HeldBy: heldBy, Reason: reason}
		}
	} else {
		delete(s.held, tenantID)
	}
	s.persistLocked()
	s.mu.Unlock()
	if active {
		log.Printf("legal_hold_set tenant=%s held=true by=%q", tenantID, heldBy)
	} else {
		log.Printf("legal_hold_set tenant=%s held=false", tenantID)
	}
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

func (s *legalHoldStore) persistLocked() {
	if s.persister == nil {
		return
	}
	records := make([]legalHoldRecord, 0, len(s.held))
	for _, r := range s.held {
		records = append(records, r)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].TenantID < records[j].TenantID })
	data, err := json.Marshal(records)
	if err != nil {
		log.Printf("legal-hold persist marshal: %v", err)
		return
	}
	if err := s.persister.Save(data); err != nil {
		log.Printf("legal-hold persist save: %v", err)
	}
}
