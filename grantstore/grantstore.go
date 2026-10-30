// Package grantstore holds the short-lived, continuously-revocable GRANTS minted after a successful
// federated authentication: a grant binds a verified user (and optionally a device + scope) to a tenant for
// a bounded TTL. A flow is permitted only while a live, non-revoked, unexpired grant exists — so revoking a
// grant (or its expiry) denies the next flow. See docs/idp.md.
package grantstore

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
)

// Grant is one minted authorization. Times are RFC3339 UTC.
type Grant struct {
	OSPrincipal      string                     `json:"os_principal,omitempty"`
	OSSession        string                     `json:"os_session,omitempty"`
	RequiredFeatures []string                   `json:"required_features,omitempty"`
	UnknownFields    map[string]json.RawMessage `json:"-"`
	// ReauthenticationStartedAt records a server-side max_age=0 attempt whose
	// signed auth_time passed freshness validation. It is not the flow start or
	// the grant mint time. AuthenticationRequestID binds its single permitted use;
	// revocation records consumption and also survives restart.
	ReauthenticationStartedAt string `json:"reauthentication_started_at,omitempty"`
	AuthenticationRequestID   string `json:"authentication_request_id,omitempty"`
	GrantID                   string `json:"grant_id"`
	TenantID                  string `json:"tenant_id"`
	UserID                    string `json:"user_id"`
	// Human-readable identity, captured from the verified ID token at mint time so the grant is
	// self-describing (the admin surface must not depend on a directory sync to say WHO was approved).
	UserEmail            string   `json:"user_email,omitempty"`
	Username             string   `json:"username,omitempty"`
	UserDisplayName      string   `json:"user_display_name,omitempty"`
	DeviceID             string   `json:"device_id,omitempty"`
	IdPID                string   `json:"idp_id"`
	Issuer               string   `json:"issuer,omitempty"`
	ProviderConfigSHA256 string   `json:"provider_config_sha256,omitempty"`
	ACR                  string   `json:"acr,omitempty"`
	AMR                  []string `json:"amr,omitempty"`
	AuthTime             string   `json:"auth_time,omitempty"` // verified IdP authentication time, never mint time
	Scope                string   `json:"scope,omitempty"`     // app / destination / service the grant covers ("" = tenant-wide)
	IssuedAt             string   `json:"issued_at"`
	ExpiresAt            string   `json:"expires_at"`
	Revoked              bool     `json:"revoked,omitempty"`
	// ConsumedAt distinguishes a released single request from an administrator
	// revocation. Revoked remains the authorization tombstone for old readers.
	ConsumedAt string `json:"consumed_at,omitempty"`
	// ReauthenticateAfter is a persistent administrator revocation boundary, not
	// expiry or single-request consumption. It also constrains replacement IDs.
	ReauthenticateAfter string `json:"reauthenticate_after,omitempty"`
}

// Store holds tenant-attributed grants with globally unique bearer IDs, safe for concurrent use.
type Store struct {
	// Writers remain serialized across persistence, but authorization readers
	// must not wait for a filesystem/database save of every tenant's snapshot.
	writeMu            sync.Mutex
	readRefreshMu      sync.Mutex
	readRefreshAt      time.Time
	readRefreshErr     error
	readRefreshRunning bool
	readRefreshAttempt time.Time
	authorityDigest    [32]byte
	persistenceEpoch   uint64
	mu                 sync.RWMutex
	grants             map[string]Grant // grant_id -> grant
	fences             reauthenticationReadIndex
	persister          blobstore.Persister
	authorityKnown     bool
	pending            map[string]Grant
	dirty              bool // a locally applied denial still needs persistence
	// generation advances on every change. Signed grant snapshots track it
	// independently of policy configuration, so login activity cannot invalidate
	// a policy transfer and grant-only changes still reach the enforcing Edge.
	generation uint64
}

// ConfigGeneration identifies the local grant authority incarnation's current
// state. The signed grant reference carries it separately from configuration.
func (s *Store) ConfigGeneration() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.generation
}

// NewStore returns an empty grant store.
func NewStore() *Store {
	return &Store{grants: map[string]Grant{}, fences: make(reauthenticationReadIndex)}
}

// Mint stores a grant. grant_id and tenant_id are required (the caller supplies a high-entropy id). ttl sets
// ExpiresAt = now + ttl.
func (s *Store) mintLocal(g Grant, ttl time.Duration, now time.Time) (Grant, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
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
	g.ConsumedAt = ""
	g.ReauthenticateAfter = ""
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.grants[g.GrantID]; exists {
		return Grant{}, ErrConflict
	}
	if err := validateGrant(g); err != nil {
		return Grant{}, err
	}
	if !s.authorizationFreshLocked(g, g.Scope, now) {
		return Grant{}, ErrReauthenticationRequired
	}
	if !s.reauthenticationAfterLocked(g, g.Scope).IsZero() && !slices.Contains(g.RequiredFeatures, FeatureRevocationReauthentication) {
		g.RequiredFeatures = append(append([]string(nil), g.RequiredFeatures...), FeatureRevocationReauthentication)
	}
	var candidate map[string]Grant
	_ = s.withAuthorizationReaders(func() error { candidate = maps.Clone(s.grants); return nil })
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
	if err := s.RefreshShared(); err != nil {
		return Grant{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	g, ok := s.grants[strings.TrimSpace(grantID)]
	return cloneGrant(g), ok
}

// Valid reports whether the grant exists, is not revoked, and has not expired at now.
func (s *Store) Valid(grantID string, now time.Time) bool {
	g, ok := s.Get(grantID)
	if !ok || g.Revoked || !g.Supported() {
		return false
	}
	exp, err := time.Parse(time.RFC3339, g.ExpiresAt)
	if err != nil {
		return false
	}
	return now.UTC().Before(exp) && s.authorizationFreshAt(g, g.Scope, now.UTC())
}

// Revoke is the compatibility entry point: the boolean reports existence, not durability.
// Tenant-authenticated callers must use RevokeForTenant and handle its persistence error.
func (s *Store) Revoke(grantID string) bool {
	g, ok := s.Get(grantID)
	if !ok {
		return false
	}
	_, found, _ := s.RevokeForTenant(g.TenantID, grantID)
	return found
}

// RevokeForTenant checks exact attribution and revokes under the same lock.
// Denial is retained locally on save failure; repeating the call retries persistence.
// ErrSavedWithoutAtomicity is a completed-save warning, while ErrPersistence
// means confirmation is missing and the pending denial still needs a retry.
func (s *Store) revokeForTenantLocal(tenantID, grantID string) (Grant, bool, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
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
func (s *Store) listLocal(tenantID string) []Grant {
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
// Shared writers coordinate edits through the persistence transaction.
func (s *Store) SetPersister(p blobstore.Persister) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	// Loading even a valid older snapshot must not discard an unsaved denial.
	// Repair and retry the existing writer before replacing or detaching it.
	if s.dirty {
		return ErrPendingPersistence
	}
	if p == nil {
		s.persister = nil
		s.persistenceEpoch++
		return nil
	}
	readStarted := time.Now()
	var data []byte
	err := s.withAuthorizationReaders(func() (err error) { data, err = p.Load(); return err })
	if err != nil {
		return err
	}
	if len(data) == 0 {
		if data != nil {
			return ErrInvalidGrant
		}
		s.persister = p
		s.persistenceEpoch++
		s.readRefreshAt, s.readRefreshErr = readStarted, nil
		s.authorityDigest = sha256.Sum256(nil)
		s.dirty = len(s.grants) > 0
		return nil
	}
	fresh, err := decodeShared(data)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(s.grants, fresh) {
		s.generation++
	}
	s.grants, s.persister, s.dirty = fresh, p, false
	s.rebuildReauthenticationIndexLocked()
	s.authorityKnown = true
	s.persistenceEpoch++
	s.authorityDigest = sha256.Sum256(data)
	s.readRefreshAt, s.readRefreshErr = readStarted, nil
	s.pending = nil
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
	p := s.persister
	err := s.withAuthorizationReaders(func() error {
		data, err := encodeGrantSnapshot(candidate)
		if err != nil {
			return err
		}
		return p.Save(data)
	})
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

// Caller holds writeMu and mu. The immutable candidate and current writer are
// protected by writeMu while readers keep using the last published state.
func (s *Store) withAuthorizationReaders(work func() error) error {
	s.mu.Unlock()
	defer s.mu.Lock()
	return work()
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
func (s *Store) removeTenantLocal(tenantID string) (int, error) {
	if s == nil || strings.TrimSpace(tenantID) == "" {
		return 0, nil
	}
	tenantID = strings.TrimSpace(tenantID)
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	candidate := cloneGrants(s.grants)
	n := 0
	for id, v := range candidate {
		if v.TenantID == tenantID {
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
	s.rebuildReauthenticationIndexLocked()
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
func (s *Store) listAllLocal() []Grant {
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

func (s *Store) Mint(g Grant, ttl time.Duration, now time.Time) (Grant, error) {
	return s.MintContext(context.Background(), g, ttl, now)
}
func (s *Store) RevokeForTenant(tenant, id string) (Grant, bool, error) {
	return s.RevokeForTenantContext(context.Background(), tenant, id)
}
func (s *Store) RemoveTenantChecked(tenant string) (int, error) {
	return s.RemoveTenantContext(context.Background(), tenant)
}

func (s *Store) List(tenant string) []Grant { rows, _ := s.ListChecked(tenant); return rows }
func (s *Store) ListAll() []Grant           { rows, _ := s.ListAllChecked(); return rows }
