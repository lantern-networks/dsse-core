package humanapproval

import (
	"context"
	"errors"
	"fmt"
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
	mu                 sync.RWMutex
	events             map[string]model.HumanApprovalEvent
	capacity           int
	persister          blobstore.Persister
	authorityKnown     bool
	pendingRevocations map[string]*string
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
		s.authorityKnown = false
		return nil
	}
	data, err := p.Load()
	if err != nil {
		return err
	}
	if len(data) == 0 {
		if data == nil && s.authorityKnown {
			return fmt.Errorf("authorization authority disappeared")
		}
		if data != nil {
			return fmt.Errorf("empty human approval snapshot")
		}
		s.persister = p
		return nil
	}
	fresh, err := decodeSnapshot(data)
	if err != nil {
		return err
	}
	// Preserve all records even when the configured capacity has been lowered.
	s.applyPendingLocked(fresh)
	s.events, s.persister, s.authorityKnown = fresh, p, true
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

func (s *Store) Upsert(event model.HumanApprovalEvent) (model.HumanApprovalEvent, error) {
	return s.UpsertContext(context.Background(), event)
}
func (s *Store) UpsertContext(ctx context.Context, event model.HumanApprovalEvent) (model.HumanApprovalEvent, error) {
	if err := validKey(event.TenantID, event.ID); err != nil {
		return model.HumanApprovalEvent{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.editLocked(ctx, func(next map[string]model.HumanApprovalEvent) error {
		key := approvalKey(event.TenantID, event.ID)
		old, ok := next[key]
		if ok {
			if err := validateTransition(old, event); err != nil {
				return err
			}
		}
		if !ok && s.capacity > 0 && len(next) >= s.capacity {
			return ErrCapacity
		}
		next[key] = event
		return nil
	})
	if err != nil {
		return model.HumanApprovalEvent{}, err
	}
	return event, nil
}

// Get is a compatibility lookup and refuses IDs shared by multiple tenants.
// Authenticated callers must use GetForTenant.
func (s *Store) Get(id string) (model.HumanApprovalEvent, bool) {
	if err := s.RefreshShared(); err != nil {
		return model.HumanApprovalEvent{}, false
	}
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
	if err := s.RefreshShared(); err != nil {
		return model.HumanApprovalEvent{}, false
	}
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

// Revoke is a compatibility entry point and refuses ambiguous IDs in the latest authority.
func (s *Store) Revoke(id, reason string) (model.HumanApprovalEvent, bool, error) {
	return s.revokeContext(context.Background(), "", id, reason)
}
func (s *Store) RevokeForTenant(tenant, id, reason string) (model.HumanApprovalEvent, bool, error) {
	return s.RevokeForTenantContext(context.Background(), tenant, id, reason)
}
func (s *Store) RevokeForTenantContext(ctx context.Context, tenant, id, reason string) (model.HumanApprovalEvent, bool, error) {
	if err := validKey(tenant, id); err != nil {
		return model.HumanApprovalEvent{}, false, err
	}
	return s.revokeContext(ctx, tenant, id, reason)
}
func (s *Store) revokeContext(ctx context.Context, tenant, id, reason string) (model.HumanApprovalEvent, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result model.HumanApprovalEvent
	found := false
	err := s.editLocked(ctx, func(next map[string]model.HumanApprovalEvent) error {
		key := approvalKey(tenant, id)
		if tenant == "" {
			key = ""
			for k, v := range next {
				if v.ID == id {
					if key != "" {
						return fmt.Errorf("authorization ID is ambiguous")
					}
					key = k
				}
			}
		}
		var ok bool
		result, ok = next[key]
		if !ok {
			return errNoChange
		}
		found = true
		if result.ApprovalResult != "revoked" {
			result.ApprovalResult = "revoked"
			result.Reason = stringPtr(reason)
		}
		next[key] = result
		return nil
	})
	// A database refusal can happen before the edit callback (for example,
	// acquiring the write transaction). Preserve the existing local denial
	// contract for a known tenant-bound record, without claiming it was saved.
	if errors.Is(err, ErrPersistence) && !found && tenant != "" {
		result, found = s.events[approvalKey(tenant, id)]
		if found {
			result.ApprovalResult = "revoked"
			result.Reason = stringPtr(reason)
		}
	}
	if err != nil && found {
		if s.pendingRevocations == nil {
			s.pendingRevocations = map[string]*string{}
		}
		key := approvalKey(result.TenantID, result.ID)
		s.pendingRevocations[key] = result.Reason
		s.events[key] = result
	}
	return result, found, err
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
func (s *Store) RemoveTenant(tenantID string) int { n, _ := s.RemoveTenantChecked(tenantID); return n }

// RemoveTenantChecked confirms persistence before discarding retry targets.
func (s *Store) RemoveTenantChecked(tenant string) (int, error) {
	return s.RemoveTenantContext(context.Background(), tenant)
}
func (s *Store) RemoveTenantContext(ctx context.Context, tenant string) (int, error) {
	if s == nil || strings.TrimSpace(tenant) == "" {
		return 0, nil
	}
	tenant = strings.TrimSpace(tenant)
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	err := s.editLocked(ctx, func(next map[string]model.HumanApprovalEvent) error {
		for key, v := range next {
			if v.TenantID == tenant {
				delete(next, key)
				n++
			}
		}
		if n == 0 {
			return errNoChange
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}
