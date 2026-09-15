package humanapproval

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/model"
)

// Store is the in-memory human-approval-event store: out-of-band approval ceremony outcomes
// (upsert / lookup / active-check / revoke) backing east-west step-up authorization, admission-bounded by
// capacity (capacity<=0 disables the bound). Existing records are never evicted for a new ID.
// Optionally durable: SetStatePath rehydrates from a JSON snapshot and each mutation writes through,
// so approval outcomes survive a restart.
type Store struct {
	mu        sync.RWMutex
	events    map[string]model.HumanApprovalEvent
	capacity  int
	persister blobstore.Persister
}

// NewStore builds a human-approval-event store with the given admission capacity. The bound is injected by
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
	if p == nil {
		s.persister = nil
		return nil
	}
	data, err := p.Load()
	if err != nil {
		return err
	}
	if len(data) == 0 {
		s.persister = p
		return nil
	}
	var snap map[string]model.HumanApprovalEvent
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	if snap == nil {
		return fmt.Errorf("invalid human approval snapshot")
	}
	fresh := make(map[string]model.HumanApprovalEvent, len(snap))
	for savedKey, event := range snap {
		if err := validKey(event.TenantID, event.ID); err != nil {
			return err
		}
		key := approvalKey(event.TenantID, event.ID)
		if savedKey != event.ID && savedKey != key {
			return fmt.Errorf("invalid saved human approval key")
		}
		if _, found := fresh[key]; found {
			return fmt.Errorf("duplicate saved human approval")
		}
		fresh[key] = event
	}
	// Preserve all records even when the configured capacity has been lowered.
	s.events, s.persister = fresh, p
	return nil
}

// ErrCapacity rejects a new identity without discarding authorization or revocation state.
var ErrCapacity = errors.New("human approval store capacity reached; existing records retained")

var ErrPersistence = errors.New("human approvals could not be saved")

func approvalKey(tenant, id string) string { return tenant + "\x00" + id }
func validKey(tenant, id string) error {
	if tenant == "" || id == "" || strings.TrimSpace(tenant) != tenant || strings.TrimSpace(id) != id || strings.ContainsRune(tenant, '\x00') || strings.ContainsRune(id, '\x00') {
		return fmt.Errorf("invalid human approval tenant or ID")
	}
	return nil
}
func cloneEvents(events map[string]model.HumanApprovalEvent) map[string]model.HumanApprovalEvent {
	result := make(map[string]model.HumanApprovalEvent, len(events)+1)
	for key, event := range events {
		result[key] = event
	}
	return result
}
func (s *Store) saveLocked(events map[string]model.HumanApprovalEvent) error {
	if s.persister == nil {
		return nil
	}
	data, err := json.MarshalIndent(events, "", "  ")
	if err == nil {
		err = s.persister.Save(data)
	}
	if err != nil {
		log.Printf("human approvals save: %v", err)
		if !errors.Is(err, blobstore.ErrSavedWithoutAtomicity) {
			return ErrPersistence
		}
	}
	return nil
}

// Tenant removal retains its separate best-effort persistence contract.
func (s *Store) persistLocked() error { return s.saveLocked(s.events) }

func (s *Store) Upsert(event model.HumanApprovalEvent) (model.HumanApprovalEvent, error) {
	if err := validKey(event.TenantID, event.ID); err != nil {
		return model.HumanApprovalEvent{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := approvalKey(event.TenantID, event.ID)
	existing, ok := s.events[key]
	if ok {
		if err := validateTransition(existing, event); err != nil {
			return model.HumanApprovalEvent{}, err
		}
	}
	// Forgetting a terminal record would allow a later upsert to reactivate the same ID.
	// Reserve capacity only for new keys; updates and revocations must remain possible when full.
	if !ok && s.capacity > 0 && len(s.events) >= s.capacity {
		return model.HumanApprovalEvent{}, ErrCapacity
	}
	candidate := cloneEvents(s.events)
	candidate[key] = event
	if err := s.saveLocked(candidate); err != nil {
		return model.HumanApprovalEvent{}, err
	}
	s.events = candidate
	return event, nil
}

// Get is a compatibility lookup and refuses IDs shared by multiple tenants.
// Authenticated callers must use GetForTenant.
func (s *Store) Get(id string) (model.HumanApprovalEvent, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result model.HumanApprovalEvent
	found := false
	for _, event := range s.events {
		if event.ID == id {
			if found {
				return model.HumanApprovalEvent{}, false
			}
			result, found = event, true
		}
	}
	return result, found
}
func (s *Store) GetForTenant(tenantID, id string) (model.HumanApprovalEvent, bool) {
	if s == nil || validKey(tenantID, id) != nil {
		return model.HumanApprovalEvent{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	event, ok := s.events[approvalKey(tenantID, id)]
	return event, ok
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

// Capacity returns the configured admission capacity bound (<=0 means unbounded).
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

// Revoke is a compatibility entry point and refuses ambiguous IDs.
func (s *Store) Revoke(id, reason string) (model.HumanApprovalEvent, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := ""
	for k, event := range s.events {
		if event.ID == id {
			if key != "" {
				return model.HumanApprovalEvent{}, false, fmt.Errorf("human approval ID is ambiguous")
			}
			key = k
		}
	}
	return s.revokeLocked(key, reason)
}

// RevokeForTenant checks attribution and mutates under the same lock.
func (s *Store) RevokeForTenant(tenant, id, reason string) (model.HumanApprovalEvent, bool, error) {
	if err := validKey(tenant, id); err != nil {
		return model.HumanApprovalEvent{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revokeLocked(approvalKey(tenant, id), reason)
}
func (s *Store) revokeLocked(key, reason string) (model.HumanApprovalEvent, bool, error) {
	event, ok := s.events[key]
	if !ok {
		return model.HumanApprovalEvent{}, false, nil
	}
	// Keep an effective denial even when saving fails. Never restore an approval on a failed revoke.
	if event.ApprovalResult != "revoked" {
		event.ApprovalResult = "revoked"
		event.Reason = stringPtr(reason)
		s.events[key] = event
	}
	// Even an already-revoked event must retry the save: the previous attempt may be memory-only.
	if err := s.saveLocked(s.events); err != nil {
		return event, true, err
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
		if v.TenantID == tenantID {
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
		if v.TenantID == tenantID {
			delete(s.events, id)
			n++
		}
	}
	if n > 0 {
		s.persistLocked()
	}
	return n
}
