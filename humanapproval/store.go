package humanapproval

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/model"
)

// Store is the in-memory human-approval-event store: out-of-band approval ceremony outcomes
// (upsert / lookup / active-check / revoke) backing east-west step-up authorization, FIFO-bounded by
// capacity (capacity<=0 disables the bound). Optionally durable: SetStatePath rehydrates from a JSON
// snapshot and each mutation write-throughs, so approval outcomes survive a restart.
type Store struct {
	mu        sync.RWMutex
	events    map[string]model.HumanApprovalEvent
	order     []string
	capacity  int
	persister blobstore.Persister
}

// NewStore builds a human-approval-event store with the given FIFO capacity. The bound is injected by
// cmd/edge (which reads it from the environment) so this package stays env-name-free.
func NewStore(capacity int) *Store {
	return &Store{events: map[string]model.HumanApprovalEvent{}, capacity: capacity}
}

// SetStatePath enables durable file persistence (historical behaviour) at path; empty = in-memory only. A
// back-compat convenience over SetPersister(blobstore.FilePersister{...}).
func (s *Store) SetStatePath(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return s.SetPersister(nil)
	}
	return s.SetPersister(blobstore.FilePersister{Path: path})
}

// SetPersister enables durable persistence via any Persister (file or shared Postgres): it loads any existing
// snapshot and makes subsequent mutations write-through, so approval outcomes survive a restart — and, on a
// shared persister, a CP failover.
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
	var snap map[string]model.HumanApprovalEvent
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	if snap != nil {
		s.events = snap
		s.order = s.order[:0]
		for id := range snap {
			s.order = append(s.order, id)
		}
	}
	return nil
}

// persistLocked write-throughs the current event set. The error MUST reach the mutating caller: a swallowed
// Save meant an approval outcome — or worse, a REVOKE — was acknowledged while nothing hit disk, so a
// revoked approval silently resurrected on restart. Caller holds s.mu.
func (s *Store) persistLocked() error {
	if s.persister == nil {
		return nil
	}
	data, err := json.MarshalIndent(s.events, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal human-approval snapshot: %w", err)
	}
	if err := s.persister.Save(data); err != nil {
		return fmt.Errorf("persist human approvals: %w", err)
	}
	return nil
}

func (s *Store) Upsert(event model.HumanApprovalEvent) (model.HumanApprovalEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.events[event.ID]
	if ok {
		if err := validateTransition(existing, event); err != nil {
			return model.HumanApprovalEvent{}, err
		}
	}
	if !ok {
		s.order = append(s.order, event.ID)
	}
	s.events[event.ID] = event
	s.order = evictFIFO(s.order, len(s.events), s.capacity, func(k string) { delete(s.events, k) })
	if err := s.persistLocked(); err != nil {
		return event, fmt.Errorf("approval event %s stored in memory but not persisted (will not survive a restart): %w", event.ID, err)
	}
	return event, nil
}

func (s *Store) Get(id string) (model.HumanApprovalEvent, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	event, ok := s.events[id]
	return event, ok
}

// GetForTenant treats another tenant's record as absent, including its status.
func (s *Store) GetForTenant(tenantID, id string) (model.HumanApprovalEvent, bool) {
	if s == nil || strings.TrimSpace(tenantID) == "" {
		return model.HumanApprovalEvent{}, false
	}
	event, ok := s.Get(id)
	if !ok || event.TenantID != tenantID {
		return model.HumanApprovalEvent{}, false
	}
	return event, true
}

func (s *Store) GetActive(id string, now time.Time) (model.HumanApprovalEvent, bool) {
	event, ok := s.Get(id)
	if !ok || !IsActive(event, now) {
		return model.HumanApprovalEvent{}, false
	}
	return event, true
}

func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.events)
}

// Capacity returns the configured FIFO capacity bound (<=0 means unbounded).
func (s *Store) Capacity() int { return s.capacity }

// Snapshot returns a copy of every event. Admin list views (in cmd/edge) filter/sort/convert over this
// without touching the store's internal fields.
func (s *Store) Snapshot() []model.HumanApprovalEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.HumanApprovalEvent, 0, len(s.events))
	for _, e := range s.events {
		out = append(out, e)
	}
	return out
}

// Revoke marks an event as revoked (idempotent) and returns it; ok is false if the id is absent. A non-nil
// error means the revoke IS live in memory but durability failed — the approval would RESURRECT on restart,
// which is the most security-relevant persist failure this store has, so callers must surface it.
func (s *Store) Revoke(id, reason string) (model.HumanApprovalEvent, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	event, ok := s.events[id]
	if !ok {
		return model.HumanApprovalEvent{}, false, nil
	}
	if event.ApprovalResult != "revoked" {
		event.ApprovalResult = "revoked"
		event.Reason = stringPtr(reason)
		s.events[id] = event
		if err := s.persistLocked(); err != nil {
			return event, true, fmt.Errorf("approval %s revoked in memory but not persisted (would resurrect on restart): %w", id, err)
		}
	}
	return event, true, nil
}

func validateTransition(existing, next model.HumanApprovalEvent) error {
	if resultIsTerminal(existing.ApprovalResult) && next.ApprovalResult == "approved" {
		return fmt.Errorf("human approval event %s cannot transition from %s to approved", existing.ID, existing.ApprovalResult)
	}
	if existing.ApprovalResult == "revoked" && next.ApprovalResult != "revoked" {
		return fmt.Errorf("human approval event %s cannot transition from revoked to %s", existing.ID, next.ApprovalResult)
	}
	return nil
}

func resultIsTerminal(value string) bool {
	switch value {
	case "denied", "expired", "revoked":
		return true
	default:
		return false
	}
}

// IsActive reports whether an event is an active approval (result approved, activation reached, not expired).
func IsActive(event model.HumanApprovalEvent, now time.Time) bool {
	if event.ApprovalResult != "approved" {
		return false
	}
	if event.ActivatedAt != nil && *event.ActivatedAt != "" {
		activatedAt, err := time.Parse(time.RFC3339, *event.ActivatedAt)
		// A non-empty but UNPARSEABLE activation time must NOT be treated as already-activated (fail-open review
		// finding #12): we cannot confirm activation was reached, so the approval is not yet active. Fail closed for
		// THIS record only (an empty activated_at still means "no activation gate").
		if err != nil || now.UTC().Before(activatedAt) {
			return false
		}
	}
	if event.ExpiresAt != nil && *event.ExpiresAt != "" {
		expiresAt, err := time.Parse(time.RFC3339, *event.ExpiresAt)
		// A non-empty but UNPARSEABLE expiry must NOT be treated as "never expires" (finding #12: a malformed
		// expiry left approvals enforced forever). Treat it as expired. An empty expires_at still means "no expiry".
		if err != nil || !now.UTC().Before(expiresAt) {
			return false
		}
	}
	return true
}

// evictFIFO drops oldest keys until liveLen <= capacity (replicated package-local FIFO bound).
func evictFIFO(order []string, liveLen, capacity int, del func(key string)) []string {
	if capacity <= 0 {
		return order
	}
	for liveLen > capacity && len(order) > 0 {
		oldest := order[0]
		order = order[1:]
		del(oldest)
		liveLen--
	}
	if len(order) > 2*capacity {
		order = append([]string(nil), order...)
	}
	return order
}

func stringPtr(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

// CountForTenant returns how many records this store still holds for a tenant — what a tenant DATA FOOTPRINT
// reads. A store that cannot be counted cannot appear in the answer, and a store that does not appear reads as
// "there was nothing here", which is the one thing a footprint must never say by accident.
func (s *Store) CountForTenant(tenantID string) int {
	if s == nil {
		return 0
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, v := range s.events {
		if strings.EqualFold(strings.TrimSpace(v.TenantID), tenantID) {
			n++
		}
	}
	return n
}

// RemoveTenant erases every record belonging to a tenant, returning the count.
//
// ★ IT EXISTS BECAUSE "COMPLETELY DELETED" LEFT THESE BEHIND (2026-08-18). Measured on the reference deployment
// with a disposable organization: the erasure answered complete=true with remaining.total=0 while a record of
// that organization's was still present. The store was in neither the count nor the erasure, and a store nobody
// counts contributes nothing to "what is left".
func (s *Store) RemoveTenant(tenantID string) int {
	if s == nil {
		return 0
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, v := range s.events {
		if strings.EqualFold(strings.TrimSpace(v.TenantID), tenantID) {
			delete(s.events, id)
			n++
		}
	}
	if n > 0 {
		s.persistLocked()
	}
	return n
}
