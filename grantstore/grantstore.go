// Package grantstore holds the short-lived, continuously-revocable GRANTS minted after a successful
// federated authentication: a grant binds a verified user (and optionally a device + scope) to a tenant for
// a bounded TTL. A flow is permitted only while a live, non-revoked, unexpired grant exists — so revoking a
// grant (or its expiry) denies the next flow. See docs/idp.md.
package grantstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
)

// Grant is one minted authorization. Times are RFC3339 UTC.
type Grant struct {
	GrantID  string `json:"grant_id"`
	TenantID string `json:"tenant_id"`
	UserID   string `json:"user_id"`
	// Human-readable identity, captured from the verified ID token at mint time so the grant is
	// self-describing (the admin surface must not depend on a directory sync to say WHO was approved).
	UserEmail       string   `json:"user_email,omitempty"`
	Username        string   `json:"username,omitempty"`
	UserDisplayName string   `json:"user_display_name,omitempty"`
	DeviceID        string   `json:"device_id,omitempty"`
	IdPID           string   `json:"idp_id"`
	ACR             string   `json:"acr,omitempty"`
	AMR             []string `json:"amr,omitempty"`
	Scope           string   `json:"scope,omitempty"` // app / destination / service the grant covers ("" = tenant-wide)
	IssuedAt        string   `json:"issued_at"`
	ExpiresAt       string   `json:"expires_at"`
	Revoked         bool     `json:"revoked,omitempty"`
}

// Store holds tenant-attributed grants with globally unique bearer IDs, safe for concurrent use.
type Store struct {
	mu        sync.RWMutex
	grants    map[string]Grant // grant_id -> grant
	persister blobstore.Persister
	dirty     bool // a locally applied denial still needs persistence
	// generation advances on every change. The config bundle SUMS it, and an Edge applies a bundle only when
	// that sum is newer — see ConfigGeneration.
	generation uint64
}

// ★★★ THE BUNDLE CARRIES THESE GRANTS, SO THE BUNDLE'S VERSION HAS TO MOVE WITH THEM (2026-09-02).
//
// An Edge applies a bundle only when its version is newer. A store the version does not count changes the
// bundle's CONTENTS without changing its VERSION, and no Edge re-pulls — so a grant minted at one node would
// reach the authority and stop there, and a REVOCATION would never reach the nodes still honouring it. That
// is the whole point of carrying grants at all, and it was measured failing exactly this way: the authority
// held the grant and every Edge listed none, indefinitely.
func (s *Store) ConfigGeneration() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.generation
}

// NewStore returns an empty grant store.
func NewStore() *Store { return &Store{grants: map[string]Grant{}} }

// Mint stores a grant. grant_id and tenant_id are required (the caller supplies a high-entropy id). ttl sets
// ExpiresAt = now + ttl.
func (s *Store) Mint(g Grant, ttl time.Duration, now time.Time) (Grant, error) {
	g.GrantID = strings.TrimSpace(g.GrantID)
	g.TenantID = strings.TrimSpace(g.TenantID)
	if g.GrantID == "" {
		return Grant{}, fmt.Errorf("grant_id is required")
	}
	if g.TenantID == "" {
		return Grant{}, fmt.Errorf("tenant_id is required")
	}
	if ttl <= 0 {
		ttl = 8 * time.Hour
	}
	now = now.UTC()
	g.IssuedAt = now.Format(time.RFC3339)
	g.ExpiresAt = now.Add(ttl).Format(time.RFC3339)
	g.Revoked = false
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.grants[g.GrantID]; exists {
		return Grant{}, ErrConflict
	}
	if err := validateGrant(g); err != nil {
		return Grant{}, err
	}
	candidate := cloneGrants(s.grants)
	candidate[g.GrantID] = cloneGrant(g)
	if err := s.saveLocked(candidate); err != nil && !savedNonAtomically(err) {
		return Grant{}, err
	}
	s.grants, s.dirty = candidate, false
	s.generation++
	return cloneGrant(g), nil
}

// Get returns a grant by id.
func (s *Store) Get(grantID string) (Grant, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	g, ok := s.grants[strings.TrimSpace(grantID)]
	return cloneGrant(g), ok
}

// Valid reports whether the grant exists, is not revoked, and has not expired at now.
func (s *Store) Valid(grantID string, now time.Time) bool {
	g, ok := s.Get(grantID)
	if !ok || g.Revoked {
		return false
	}
	exp, err := time.Parse(time.RFC3339, g.ExpiresAt)
	if err != nil {
		return false
	}
	return now.UTC().Before(exp)
}

// Revoke is the compatibility entry point: the boolean reports existence, not durability.
// Tenant-authenticated callers must use RevokeForTenant and handle its persistence error.
func (s *Store) Revoke(grantID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, found, _ := s.revokeLocked(strings.TrimSpace(grantID))
	return found
}

// RevokeForTenant checks exact attribution and revokes under the same lock.
// Denial is retained locally on save failure; repeating the call retries persistence.
// ErrSavedWithoutAtomicity is a completed-save warning, while ErrPersistence
// means confirmation is missing and the pending denial still needs a retry.
func (s *Store) RevokeForTenant(tenantID, grantID string) (Grant, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	grantID = strings.TrimSpace(grantID)
	if tenantID == "" {
		return Grant{}, false, fmt.Errorf("tenant_id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[grantID]
	if !ok || g.TenantID != tenantID {
		return Grant{}, false, nil
	}
	return s.revokeLocked(grantID)
}
func (s *Store) revokeLocked(grantID string) (Grant, bool, error) {
	g, ok := s.grants[grantID]
	if !ok {
		return Grant{}, false, nil
	}
	if !g.Revoked {
		g.Revoked = true
		s.grants[grantID] = g
		s.generation++
		s.dirty = true
	}
	if err := s.persistLocked(); err != nil {
		return cloneGrant(g), true, err
	}
	return cloneGrant(g), true, nil
}

// List returns the tenant's grants, newest first.
func (s *Store) List(tenantID string) []Grant {
	tenantID = strings.TrimSpace(tenantID)
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Grant, 0)
	for _, g := range s.grants {
		if g.TenantID == tenantID {
			out = append(out, cloneGrant(g))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IssuedAt > out[j].IssuedAt })
	return out
}

// SetStatePath enables durable persistence (grants survive a restart; a revoked grant stays revoked).
func (s *Store) SetStatePath(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return s.SetPersister(nil)
	}
	return s.SetPersister(blobstore.FilePersister{Path: path})
}

// SetPersister adopts a validated snapshot and its writer together. A failed load preserves both.
// Successful saves can be reloaded; coordination between independent writers is external to this store.
func (s *Store) SetPersister(p blobstore.Persister) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Loading even a valid older snapshot must not discard an unsaved denial.
	// Repair and retry the existing writer before replacing or detaching it.
	if s.dirty {
		return ErrPendingPersistence
	}
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
			return ErrInvalidGrant
		}
		s.persister = p
		s.dirty = len(s.grants) > 0
		return nil
	}
	var fresh map[string]Grant
	if err := json.Unmarshal(data, &fresh); err != nil {
		return ErrInvalidGrant
	}
	if fresh == nil {
		return ErrInvalidGrant
	}
	for key, g := range fresh {
		if key != g.GrantID {
			return ErrInvalidGrant
		}
		if err := validateGrant(g); err != nil {
			return err
		}
		fresh[key] = cloneGrant(g)
	}
	if !reflect.DeepEqual(s.grants, fresh) {
		s.generation++
	}
	s.grants, s.persister, s.dirty = fresh, p, false
	return nil
}

var ErrPersistence = errors.New("access-grant persistence is unconfirmed")
var ErrPendingPersistence = errors.New("save pending access-grant changes before replacing the persistence store")

func savedNonAtomically(err error) bool {
	return errors.Is(err, blobstore.ErrSavedWithoutAtomicity) && !errors.Is(err, blobstore.ErrDurabilityUnconfirmed)
}

// saveLocked writes a candidate without exposing new authorization in memory.
func (s *Store) saveLocked(candidate map[string]Grant) error {
	if s.persister == nil {
		return nil
	}
	data, err := json.MarshalIndent(candidate, "", "  ")
	if err == nil {
		err = s.persister.Save(data)
	}
	if err != nil {
		log.Printf("access grants save: %v", err)
		if errors.Is(err, blobstore.ErrDurabilityUnconfirmed) {
			return errors.Join(ErrPersistence, blobstore.ErrDurabilityUnconfirmed)
		}
		if savedNonAtomically(err) {
			return blobstore.ErrSavedWithoutAtomicity
		}
		return ErrPersistence
	}
	return nil
}
func (s *Store) persistLocked() error {
	err := s.saveLocked(s.grants)
	if err != nil && !savedNonAtomically(err) {
		s.dirty = true
		return err
	}
	s.dirty = false
	return err
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
	if err := s.saveLocked(candidate); err != nil && !savedNonAtomically(err) {
		return 0, err
	}
	s.grants = candidate
	s.generation++
	s.dirty = false
	return n, nil
}

// ★★★ THE DEPLOYMENT'S GRANTS, NOT THIS NODE'S (2026-09-02).
//
// A grant is minted by whichever Edge ran the step-up ceremony and lived only in that process. Two things
// followed, and both are silent. An Edge restart — a roll, a config change — dropped every grant, so users
// who had authenticated were held again with nothing said. And a region with more than one Edge behind its
// door, which is the shape this product scales into, could run the ceremony on one node and hold the flow on
// another: the user authenticates successfully and is held again, forever.
//
// The revocation surface says as much in its own comment — "a revocation is a security act that must be
// available wherever an administrator lands, and the store is shared" — and the store was not shared, so
// revoking on one node left the grant live on every other.

// ListAll is every organization's grants, ordered so two calls produce the same bytes.
func (s *Store) ListAll() []Grant {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Grant, 0, len(s.grants))
	for _, g := range s.grants {
		out = append(out, cloneGrant(g))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GrantID < out[j].GrantID })
	return out
}

// Merge is the compatibility entry point. Counts describe live changes, not durability.
// Production ingestion must use MergeChecked and handle its error.
func (s *Store) Merge(incoming []Grant, now time.Time) (added, updated int) {
	added, updated, err := s.MergeChecked(incoming, now)
	if err != nil {
		log.Printf("access grants merge rejected: %v", err)
	}
	return added, updated
}
