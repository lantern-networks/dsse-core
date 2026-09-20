package delegatedgrant

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

// Store is the in-memory delegated-access-grant store: OOB-authenticated, short-lived east-west grants
// (upsert / lookup / active-check / revoke), admission-bounded by capacity (capacity<=0 disables the bound).
// Existing records, including revoked grants, are never evicted for a new ID.
// Optionally durable: SetStatePath rehydrates from a JSON snapshot and each mutation write-throughs, so a
// revoked grant stays revoked across a restart and in-flight grants are not lost.
type Store struct {
	mu         sync.RWMutex
	grants     map[string]model.DelegatedAccessGrant
	capacity   int
	persister  blobstore.Persister
	generation uint64 // monotonic config version (bumped on each Upsert and effective Revoke); folded into the config-bundle generation
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
		return nil
	}
	data, err := p.Load()
	if err != nil {
		return err
	}
	if len(data) == 0 {
		if data != nil {
			return fmt.Errorf("empty delegated grant snapshot")
		}
		s.persister = p
		return nil
	}
	var snap map[string]model.DelegatedAccessGrant
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	if snap == nil {
		return fmt.Errorf("invalid delegated grant snapshot")
	}
	fresh := make(map[string]model.DelegatedAccessGrant, len(snap))
	for savedKey, grant := range snap {
		if err := validKey(grant.TenantID, grant.ID); err != nil {
			return err
		}
		key := grantKey(grant.TenantID, grant.ID)
		if savedKey != grant.ID && savedKey != key {
			return fmt.Errorf("invalid saved delegated grant key")
		}
		if _, found := fresh[key]; found {
			return fmt.Errorf("duplicate saved delegated grant")
		}
		fresh[key] = grant
	}
	// Preserve all records even when the configured capacity has been lowered.
	// Replace the accepted state and writer together only after a complete, valid load.
	s.grants, s.persister = fresh, p

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

// The caller holds the write lock. Failed candidates never reach live state.
func (s *Store) saveLocked(grants map[string]model.DelegatedAccessGrant) error {
	if s.persister == nil {
		return nil
	}
	data, err := json.MarshalIndent(grants, "", "  ")
	if err == nil {
		err = s.persister.Save(data)
	}
	if err != nil {
		log.Printf("delegated grants save: %v", err)
		if !errors.Is(err, blobstore.ErrSavedWithoutAtomicity) || errors.Is(err, blobstore.ErrDurabilityUnconfirmed) {
			return ErrPersistence
		}
	}
	return nil
}

func (s *Store) Upsert(grant model.DelegatedAccessGrant) (model.DelegatedAccessGrant, error) {
	if err := validKey(grant.TenantID, grant.ID); err != nil {
		return model.DelegatedAccessGrant{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := grantKey(grant.TenantID, grant.ID)
	existing, ok := s.grants[key]
	if ok {
		if err := validateTransition(existing, grant); err != nil {
			return model.DelegatedAccessGrant{}, err
		}
	}
	// Forgetting a terminal record would allow a later upsert to reactivate the same ID.
	// Reserve capacity only for new keys; updates and revocations must remain possible when full.
	if !ok && s.capacity > 0 && len(s.grants) >= s.capacity {
		return model.DelegatedAccessGrant{}, ErrCapacity
	}
	candidate := cloneGrants(s.grants)
	candidate[key] = grant
	if err := s.saveLocked(candidate); err != nil {
		return model.DelegatedAccessGrant{}, err
	}
	s.grants = candidate
	s.generation++
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

// Revoke is a compatibility entry point; ambiguous IDs refuse mutation.
func (s *Store) Revoke(id, reason string, now time.Time) (model.DelegatedAccessGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := ""
	for k, grant := range s.grants {
		if grant.ID == id {
			if key != "" {
				return model.DelegatedAccessGrant{}, fmt.Errorf("delegated grant ID is ambiguous")
			}
			key = k
		}
	}
	return s.revokeLocked(key, id, reason, now)
}
func (s *Store) RevokeForTenant(tenant, id, reason string, now time.Time) (model.DelegatedAccessGrant, error) {
	if err := validKey(tenant, id); err != nil {
		return model.DelegatedAccessGrant{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revokeLocked(grantKey(tenant, id), id, reason, now)
}
func (s *Store) revokeLocked(key, id, reason string, now time.Time) (model.DelegatedAccessGrant, error) {
	grant, ok := s.grants[key]
	if !ok {
		return model.DelegatedAccessGrant{}, fmt.Errorf("delegated access grant %s is absent", id)
	}
	if grant.Status == "revoked" {
		return grant, nil
	}
	revokedAt := now.UTC().Format(time.RFC3339)
	grant.Status, grant.RevokedAt, grant.RevocationReason = "revoked", &revokedAt, stringPtr(reason)
	candidate := cloneGrants(s.grants)
	candidate[key] = grant
	if err := s.saveLocked(candidate); err != nil {
		return model.DelegatedAccessGrant{}, err
	}
	s.grants = candidate
	s.generation++
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
func (s *Store) RemoveTenantChecked(tenantID string) (int, error) {
	if s == nil || strings.TrimSpace(tenantID) == "" {
		return 0, nil
	}
	tenantID = strings.TrimSpace(tenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	candidate := cloneGrants(s.grants)
	n := 0
	for id, v := range candidate {
		if strings.EqualFold(strings.TrimSpace(v.TenantID), tenantID) {
			delete(candidate, id)
			n++
		}
	}
	if n == 0 {
		return 0, nil
	}
	if err := s.saveLocked(candidate); err != nil {
		return 0, err
	}
	s.grants = candidate
	s.generation++

	return n, nil
}
