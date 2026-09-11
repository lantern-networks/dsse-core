package delegatedgrant

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/model"
)

// Store is the in-memory delegated-access-grant store: OOB-authenticated, short-lived east-west grants
// (upsert / lookup / active-check / revoke), FIFO-bounded by capacity (capacity<=0 disables the bound).
// Optionally durable: SetStatePath rehydrates from a JSON snapshot and each mutation write-throughs, so a
// revoked grant stays revoked across a restart and in-flight grants are not lost.
type Store struct {
	mu         sync.RWMutex
	grants     map[string]model.DelegatedAccessGrant
	order      []string
	capacity   int
	persister  blobstore.Persister
	generation uint64 // monotonic config version (bumped on each Upsert); folded into the config-bundle generation
}

// NewStore builds a delegated-grant store with the given FIFO capacity. The bound is injected by
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
	var snap map[string]model.DelegatedAccessGrant
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	if snap != nil {
		s.grants = snap
		s.order = s.order[:0]
		for id := range snap {
			s.order = append(s.order, id)
		}
	}
	return nil
}

// persistLocked atomically write-throughs the current grant set. Caller holds s.mu. Best-effort: a write
// error leaves the in-memory state authoritative (durability at risk, but never blocks the mutation).
func (s *Store) persistLocked() {
	if s.persister == nil {
		return
	}
	data, err := json.MarshalIndent(s.grants, "", "  ")
	if err != nil {
		return
	}
	_ = s.persister.Save(data)
}

func (s *Store) Upsert(grant model.DelegatedAccessGrant) (model.DelegatedAccessGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.grants[grant.ID]
	if ok {
		if err := validateTransition(existing, grant); err != nil {
			return model.DelegatedAccessGrant{}, err
		}
	}
	if !ok {
		s.order = append(s.order, grant.ID)
	}
	s.grants[grant.ID] = grant
	s.order = evictFIFO(s.order, len(s.grants), s.capacity, func(k string) { delete(s.grants, k) })
	s.generation++
	s.persistLocked()
	return grant, nil
}

// ConfigGeneration returns the monotonic delegated-grant config version (bumped on each Upsert). A
// config-bundle distributor folds it into the aggregate generation so a grant change triggers a fleet re-pull.
func (s *Store) ConfigGeneration() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.generation
}

func (s *Store) Get(id string) (model.DelegatedAccessGrant, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	grant, ok := s.grants[id]
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

// Capacity returns the configured FIFO capacity bound (<=0 means unbounded).
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

func (s *Store) Revoke(id, reason string, now time.Time) (model.DelegatedAccessGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	grant, ok := s.grants[id]
	if !ok {
		return model.DelegatedAccessGrant{}, fmt.Errorf("delegated access grant %s is absent", id)
	}
	if grant.Status == "revoked" {
		return grant, nil
	}
	revokedAt := now.UTC().Format(time.RFC3339)
	grant.Status = "revoked"
	grant.RevokedAt = &revokedAt
	grant.RevocationReason = stringPtr(reason)
	s.grants[id] = grant
	s.persistLocked()
	return grant, nil
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
	for id, v := range s.grants {
		if strings.EqualFold(strings.TrimSpace(v.TenantID), tenantID) {
			delete(s.grants, id)
			n++
		}
	}
	if n > 0 {
		s.persistLocked()
	}
	return n
}
