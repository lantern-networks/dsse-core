package delegatedgrant

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

type pendingRevocation struct{ at, reason string }

// Store is the in-memory delegated-access-grant store: OOB-authenticated, short-lived east-west grants
// (upsert / lookup / active-check / revoke), admission-bounded by capacity (capacity<=0 disables the bound).
// Existing records, including revoked grants, are never evicted for a new ID.
// Optionally durable: SetStatePath rehydrates from a JSON snapshot and each mutation write-throughs, so a
// revoked grant stays revoked across a restart and in-flight grants are not lost.
// Failed revocations deny locally until a confirmed retry. This pending overlay
// is process-local: a failed save is not a promise of durable or fleet-wide denial.
type Store struct {
	mu                 sync.RWMutex
	grants             map[string]model.DelegatedAccessGrant
	capacity           int
	persister          blobstore.Persister
	authorityKnown     bool
	pendingRevocations map[string]pendingRevocation
	generation         uint64 // monotonic config version (bumped on each Upsert and effective Revoke); folded into the config-bundle generation
}

// NewStore builds a delegated-grant store with the given admission capacity. The bound is injected by
// cmd/edge (which reads it from the environment) so this package stays env-name-free.
func NewStore(capacity int) *Store {
	return &Store{grants: map[string]model.DelegatedAccessGrant{}, capacity: capacity}
}

// SetStatePath enables durable persistence: it loads any existing snapshot (grants survive a restart; a
// revoked grant stays revoked) and makes subsequent mutations write-through. Empty path = in-memory only.
func (s *Store) SetStatePath(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return s.SetPersister(nil)
	}
	return s.SetPersister(blobstore.FilePersister{Path: path})
}

// SetPersister enables durable persistence via any Persister (file or shared Postgres): it loads any existing
// snapshot (grants survive a restart; a revoked grant stays revoked) and makes mutations write-through — and, on
// a shared persister, survives a CP failover.
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
			return fmt.Errorf("empty delegated grant snapshot")
		}
		s.persister = p
		return nil
	}
	fresh, err := decodeSnapshot(data)
	if err != nil {
		return err
	}
	// Preserve all records even when the configured capacity has been lowered.
	// Replace the accepted state and writer together only after a complete, valid load.
	s.applyPendingLocked(fresh)
	s.publishLocked(fresh)
	s.persister, s.authorityKnown = p, true

	return nil
}

// ErrCapacity rejects a new identity without discarding authorization or revocation state.
var ErrCapacity = errors.New("delegated grant store capacity reached; existing records retained")

var ErrPersistence = errors.New("delegated grants could not be saved")

func grantKey(tenant, id string) string { return tenant + "\x00" + id }
func validKey(tenant, id string) error {
	if tenant == "" || id == "" || strings.TrimSpace(tenant) != tenant || strings.TrimSpace(id) != id || strings.ContainsRune(tenant, '\x00') || strings.ContainsRune(id, '\x00') {
		return fmt.Errorf("invalid delegated grant tenant or ID")
	}
	return nil
}
func cloneGrants(in map[string]model.DelegatedAccessGrant) map[string]model.DelegatedAccessGrant {
	out := make(map[string]model.DelegatedAccessGrant, len(in)+1)
	for key, grant := range in {
		out[key] = grant
	}
	return out
}

// Allowing mutations publish only after persistence; failed revocations retain a local denial.

func (s *Store) Upsert(grant model.DelegatedAccessGrant) (model.DelegatedAccessGrant, error) {
	return s.UpsertContext(context.Background(), grant)
}
func (s *Store) UpsertContext(ctx context.Context, grant model.DelegatedAccessGrant) (model.DelegatedAccessGrant, error) {
	if err := validKey(grant.TenantID, grant.ID); err != nil {
		return model.DelegatedAccessGrant{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.editLocked(ctx, func(next map[string]model.DelegatedAccessGrant) error {
		key := grantKey(grant.TenantID, grant.ID)
		old, ok := next[key]
		if _, pending := s.pendingRevocations[key]; pending && grant.Status != "revoked" {
			return fmt.Errorf("delegated access grant revocation is pending persistence")
		}
		if ok {
			if err := validateTransition(old, grant); err != nil {
				return err
			}
		}
		if !ok && s.capacity > 0 && len(next) >= s.capacity {
			return ErrCapacity
		}
		next[key] = grant
		return nil
	})
	if err != nil {
		return model.DelegatedAccessGrant{}, err
	}
	return grant, nil
}

// ConfigGeneration returns the monotonic delegated-grant config version (bumped on each Upsert and effective Revoke). A
// config-bundle distributor folds it into the aggregate generation so a grant change triggers a fleet re-pull.
func (s *Store) ConfigGeneration() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.generation
}

// Get is retained for callers without tenant context and refuses ambiguous IDs.
// Authenticated callers must use GetForTenant instead.
func (s *Store) Get(id string) (model.DelegatedAccessGrant, bool) {
	if err := s.RefreshShared(); err != nil {
		return model.DelegatedAccessGrant{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result model.DelegatedAccessGrant
	found := false
	for _, grant := range s.grants {
		if grant.ID == id {
			if found {
				return model.DelegatedAccessGrant{}, false
			}
			result, found = grant, true
		}
	}
	return result, found
}
func (s *Store) GetForTenant(tenant, id string) (model.DelegatedAccessGrant, bool) {
	if err := s.RefreshShared(); err != nil {
		return model.DelegatedAccessGrant{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if validKey(tenant, id) != nil {
		return model.DelegatedAccessGrant{}, false
	}
	grant, ok := s.grants[grantKey(tenant, id)]
	return grant, ok
}

func (s *Store) GetActive(id string, now time.Time) (model.DelegatedAccessGrant, bool) {
	grant, ok := s.Get(id)
	if !ok || !IsActive(grant, now) {
		return model.DelegatedAccessGrant{}, false
	}
	return grant, true
}

func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.grants)
}

// Capacity returns the configured admission capacity bound (<=0 means unbounded).
func (s *Store) Capacity() int { return s.capacity }

// Snapshot returns a copy of every grant. Admin list views (in cmd/edge) filter/sort/convert over this
// without touching the store's internal fields.
func (s *Store) Snapshot() []model.DelegatedAccessGrant {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.DelegatedAccessGrant, 0, len(s.grants))
	for _, g := range s.grants {
		out = append(out, g)
	}
	return out
}

// Revoke is a compatibility entry point and refuses ambiguous IDs in the latest authority.
func (s *Store) Revoke(id, reason string, now time.Time) (model.DelegatedAccessGrant, error) {
	return s.revokeContext(context.Background(), "", id, reason, now)
}
func (s *Store) RevokeForTenant(tenant, id, reason string, now time.Time) (model.DelegatedAccessGrant, error) {
	return s.RevokeForTenantContext(context.Background(), tenant, id, reason, now)
}
func (s *Store) RevokeForTenantContext(ctx context.Context, tenant, id, reason string, now time.Time) (model.DelegatedAccessGrant, error) {
	if err := validKey(tenant, id); err != nil {
		return model.DelegatedAccessGrant{}, err
	}
	return s.revokeContext(ctx, tenant, id, reason, now)
}
func (s *Store) revokeContext(ctx context.Context, tenant, id, reason string, now time.Time) (model.DelegatedAccessGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result model.DelegatedAccessGrant
	found := false
	err := s.editLocked(ctx, func(next map[string]model.DelegatedAccessGrant) error {
		key := grantKey(tenant, id)
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
			return ErrAbsent
		}
		found = true
		if result.Status == "revoked" {
			if _, pending := s.pendingRevocations[key]; pending {
				return nil
			}
			return errNoChange
		}
		revokedAt := now.UTC().Format(time.RFC3339)
		result.Status, result.RevokedAt, result.RevocationReason = "revoked", &revokedAt, stringPtr(reason)
		next[key] = result
		return nil
	})
	if errors.Is(err, ErrPersistence) {
		// A rejected lease/transaction may not have invoked the edit callback.
		// Retain a tenant-scoped denial for a known local target in that case.
		if !found {
			if tenant != "" {
				result, found = s.grants[grantKey(tenant, id)]
			} else {
				for _, g := range s.grants {
					if g.ID == id {
						if found {
							return model.DelegatedAccessGrant{}, err
						}
						result, found = g, true
					}
				}
			}
		}
		if found {
			key := grantKey(result.TenantID, result.ID)
			if s.pendingRevocations == nil {
				s.pendingRevocations = map[string]pendingRevocation{}
			}
			if _, pending := s.pendingRevocations[key]; !pending {
				s.pendingRevocations[key] = pendingRevocation{now.UTC().Format(time.RFC3339), reason}
			}
			next := cloneGrants(s.grants)
			next[key] = result
			s.applyPendingLocked(next)
			s.publishLocked(next)
			return s.grants[key], err
		}
	}
	if err != nil {
		return model.DelegatedAccessGrant{}, err
	}
	return result, nil
}

func validateTransition(existing, next model.DelegatedAccessGrant) error {
	if existing.Status == "revoked" && next.Status != "revoked" {
		return fmt.Errorf("delegated access grant %s cannot transition from revoked to %s", existing.ID, next.Status)
	}
	if existing.Status == "expired" && next.Status == "active" {
		return fmt.Errorf("delegated access grant %s cannot transition from expired to active", existing.ID)
	}
	return nil
}

// IsActive reports whether a grant is currently active (status active and not past its expiry).
func IsActive(grant model.DelegatedAccessGrant, now time.Time) bool {
	if grant.Status != "active" {
		return false
	}
	if strings.TrimSpace(grant.ExpiresAt) != "" {
		expiresAt, err := time.Parse(time.RFC3339, grant.ExpiresAt)
		// A non-empty but UNPARSEABLE expiry must NOT be treated as "never expires" (fail-open review finding #12:
		// a malformed expiry left grants enforced forever). Treat it as expired. An empty expires_at is left as-is
		// ("no expiry"): a permanent grant is a mint-time policy question, not a reason to fail an authored grant
		// closed here.
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
	for _, v := range s.grants {
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
	err := s.editLocked(ctx, func(next map[string]model.DelegatedAccessGrant) error {
		for key, v := range next {
			if strings.EqualFold(strings.TrimSpace(v.TenantID), tenant) {
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
	// Only this explicit, confirmed erasure releases absent denial identifiers.
	for key := range s.pendingRevocations {
		if strings.EqualFold(strings.SplitN(key, "\x00", 2)[0], tenant) {
			delete(s.pendingRevocations, key)
		}
	}
	return n, nil
}
