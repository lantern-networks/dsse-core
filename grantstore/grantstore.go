// Package grantstore holds the short-lived, continuously-revocable GRANTS minted after a successful
// federated authentication: a grant binds a verified user (and optionally a device + scope) to a tenant for
// a bounded TTL. A flow is permitted only while a live, non-revoked, unexpired grant exists — so revoking a
// grant (or its expiry) denies the next flow. See docs/idp_federated_authentication_design.md.
package grantstore

import (
	"encoding/json"
	"fmt"
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

// Store is a per-tenant set of grants, safe for concurrent use, optionally persisted (SetStatePath).
type Store struct {
	mu        sync.RWMutex
	grants    map[string]Grant // grant_id -> grant
	persister blobstore.Persister
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
	s.grants[g.GrantID] = g
	s.generation++
	s.persistLocked()
	return g, nil
}

// Get returns a grant by id.
func (s *Store) Get(grantID string) (Grant, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	g, ok := s.grants[strings.TrimSpace(grantID)]
	return g, ok
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

// Revoke marks a grant revoked (continuous revocation). Reports whether it existed.
func (s *Store) Revoke(grantID string) bool {
	grantID = strings.TrimSpace(grantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[grantID]
	if !ok {
		return false
	}
	g.Revoked = true
	s.grants[grantID] = g
	s.generation++
	s.persistLocked()
	return true
}

// List returns the tenant's grants, newest first.
func (s *Store) List(tenantID string) []Grant {
	tenantID = strings.TrimSpace(tenantID)
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Grant, 0)
	for _, g := range s.grants {
		if g.TenantID == tenantID {
			out = append(out, g)
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

// SetPersister enables durable persistence via any Persister (file or shared Postgres): grants (and their
// revoked state) survive a restart — and, on a shared persister, a CP failover.
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
	var snap map[string]Grant
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	if snap != nil {
		s.grants = snap
	}
	return nil
}

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
		s.generation++
		s.persistLocked()
	}
	return n
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
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GrantID < out[j].GrantID })
	return out
}

// Merge folds another node's view into this one. Incoming wins for a grant both hold — the control plane is
// where a revocation is recorded, and a stale local copy must never un-revoke it.
//
// ★ A UNION, NOT A REPLACEMENT, AND THAT IS THE WHOLE DESIGN. Revocation MARKS a grant rather than removing
// it, so "the other side does not have this one" never means "it was withdrawn" — it means the other side has
// not heard yet. That is exactly the case for a grant minted here a second ago, and replacing would delete it
// before the ceremony that earned it had finished.
//
// Grants already expired are dropped rather than merged: they satisfy nothing and would accumulate forever.
func (s *Store) Merge(incoming []Grant, now time.Time) (added, updated int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, g := range incoming {
		id := strings.TrimSpace(g.GrantID)
		if id == "" || strings.TrimSpace(g.TenantID) == "" {
			continue
		}
		if exp, err := time.Parse(time.RFC3339, g.ExpiresAt); err == nil && !now.Before(exp) {
			continue
		}
		if _, ok := s.grants[id]; ok {
			updated++
		} else {
			added++
		}
		s.grants[id] = g
	}
	if added > 0 || updated > 0 {
		s.generation++
		s.persistLocked()
	}
	return added, updated
}
