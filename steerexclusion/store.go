package steerexclusion

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Admin-managed steer exclusions (slice 1).
//
// An SSE admin chooses which apps (by code-signing identifier) are excluded from steering on a given scope —
// the whole tenant, a device group, or a single device. The control plane is the authority and owns the
// durable store; the resolved set is later signed and delivered to the agent so the endpoint user cannot
// change it. This file is the model + store + resolution; delivery/signing are later slices.

const (
	scopeTenant      = "tenant"
	scopeDeviceGroup = "device_group"
	scopeDevice      = "device"
	statusActive     = "active"
)

var validScope = map[string]bool{
	scopeTenant:      true,
	scopeDeviceGroup: true,
	scopeDevice:      true,
}

// Policy assigns a set of excluded app signing identifiers to a scope.
type Policy struct {
	ID                    string    `json:"id"`
	TenantID              string    `json:"tenant_id"`
	ScopeType             string    `json:"scope_type"` // tenant | device_group | device
	ScopeID               string    `json:"scope_id"`   // device-group id or device identity ("" for tenant)
	ExcludedAppSigningIDs []string  `json:"excluded_app_signing_ids"`
	Note                  string    `json:"note"`
	Status                string    `json:"status"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

// Persistence is the optional durable backing (Postgres on the control plane).
type Persistence interface {
	LoadAll(ctx context.Context) ([]*Policy, error)
	Upsert(ctx context.Context, p *Policy) error
	Delete(ctx context.Context, id, tenantID string) error
}

type Store struct {
	mu          sync.Mutex
	byID        map[string]*Policy
	persistence Persistence
	// refreshedAt is when this node last re-read the durable store.
	//
	// ★★★ EVERY NODE LOADED ONCE AND NEVER LOOKED AGAIN (2026-08-29, measured on a two-region deployment).
	// An operator authored an exclusion in the Console; the control plane that served the write had it and the
	// other three did not, and would not until they restarted. The Console reads whichever node answers, so
	// the policy was present on one refresh and absent on the next — and the install profile issued to a
	// device carried four identifiers or none depending on which node signed it. Steering exclusions are the
	// list that decides whether the session doing the installing keeps its own route back, so "sometimes" is
	// not a state this may be in.
	//
	// Same shape as the release catalogue and the rollout plan, which were made shared the day before: making
	// the STORE shared is only half of it, because a process that read it once is still answering from a
	// snapshot.
	refreshedAt time.Time
}

// refreshWindow is how stale a node's copy may be. Short enough that an operator who authors a policy and
// refreshes the screen sees it, long enough that reads do not become a database query each.
const refreshWindow = 5 * time.Second

// refreshLocked re-reads the durable store when this node's copy is older than refreshWindow.
//
// ★ A FAILURE TO RE-READ KEEPS WHAT IS HELD. The alternative — emptying the map when the database blinks —
// would remove every exclusion on a transient error, and these are the identifiers that keep the tools
// managing this deployment off the steered path.
func (s *Store) refreshLocked(now time.Time) {
	if s.persistence == nil || now.Sub(s.refreshedAt) < refreshWindow {
		return
	}
	s.refreshedAt = now
	policies, err := s.persistence.LoadAll(context.Background())
	if err != nil {
		log.Printf("steer exclusions: could not re-read the durable store (%v) — this node keeps the %d "+
			"policy(ies) it holds rather than reporting none", err, len(s.byID))
		return
	}
	fresh := make(map[string]*Policy, len(policies))
	for _, p := range policies {
		fresh[p.ID] = p
	}
	s.byID = fresh
}

func NewStore() *Store {
	return &Store{byID: map[string]*Policy{}}
}

// NewStoreWithPersistence loads any persisted policies so admin-set exclusions survive a control-plane
// restart. persistence may be nil (in-memory only).
func NewStoreWithPersistence(persistence Persistence) (*Store, error) {
	s := NewStore()
	s.persistence = persistence
	if persistence != nil {
		policies, err := persistence.LoadAll(context.Background())
		if err != nil {
			return nil, fmt.Errorf("load persisted steer exclusions: %w", err)
		}
		for _, p := range policies {
			s.byID[p.ID] = p
		}
		s.refreshedAt = time.Now()
		log.Printf("steer exclusions: loaded %d policy(ies) from the durable store", len(policies))
	}
	return s, nil
}

var idFallbackCounter atomic.Uint64

// newPolicyID mints a unique policy id ("sx_" + 128 bits of entropy), falling back to process-local entropy
// only if the system CSPRNG is unavailable.
func newPolicyID(fallback time.Time) string {
	var random [16]byte
	if _, err := rand.Read(random[:]); err == nil {
		return "sx_" + hex.EncodeToString(random[:])
	} else {
		log.Printf("WARN: crypto/rand failed for sx id, falling back to process-local entropy: %v", err)
	}
	return fmt.Sprintf("sx_%d_%d_%d", fallback.UTC().UnixNano(), os.Getpid(), idFallbackCounter.Add(1))
}

func normalizeSigningIDs(ids []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Upsert validates and stores a policy (creating its id if absent), write-through to the durable store.
func (s *Store) Upsert(p Policy, now time.Time) (Policy, error) {
	p.ScopeType = strings.TrimSpace(strings.ToLower(p.ScopeType))
	if !validScope[p.ScopeType] {
		return Policy{}, fmt.Errorf("scope_type must be one of tenant, device_group, device")
	}
	p.ScopeID = strings.TrimSpace(p.ScopeID)
	if p.ScopeType != scopeTenant && p.ScopeID == "" {
		return Policy{}, fmt.Errorf("scope_id is required for scope_type %q", p.ScopeType)
	}
	if p.ScopeType == scopeTenant {
		p.ScopeID = ""
	}
	p.ExcludedAppSigningIDs = normalizeSigningIDs(p.ExcludedAppSigningIDs)
	if len(p.ExcludedAppSigningIDs) == 0 {
		return Policy{}, fmt.Errorf("at least one excluded_app_signing_ids entry is required")
	}
	if strings.TrimSpace(p.TenantID) == "" {
		return Policy{}, fmt.Errorf("tenant_id is required")
	}
	p.Status = statusActive

	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.TrimSpace(p.ID) == "" {
		p.ID = newPolicyID(now)
	}
	existing := s.byID[p.ID]
	if existing != nil {
		p.CreatedAt = existing.CreatedAt
	} else {
		p.CreatedAt = now.UTC()
	}
	p.UpdatedAt = now.UTC()
	stored := p
	s.byID[p.ID] = &stored
	if s.persistence != nil {
		if err := s.persistence.Upsert(context.Background(), &stored); err != nil {
			log.Printf("WARNING: persist steer exclusion %s failed (durability at risk): %v", stored.ID, err)
		}
	}
	return stored, nil
}

// List returns the tenant's policies (stable order).
func (s *Store) List(tenantID string) []Policy {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked(time.Now())
	out := []Policy{}
	for _, p := range s.byID {
		if p.TenantID == tenantID {
			out = append(out, *p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Get returns a tenant's policy by id (ok=false when absent). Used to snapshot a policy before deletion.
func (s *Store) Get(id, tenantID string) (Policy, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked(time.Now())
	if p := s.byID[id]; p != nil && p.TenantID == tenantID {
		return *p, true
	}
	return Policy{}, false
}

// Delete removes a tenant's policy by id. Returns false if absent.
func (s *Store) Delete(id, tenantID string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.byID[id]
	if p == nil || p.TenantID != tenantID {
		return false
	}
	delete(s.byID, id)
	if s.persistence != nil {
		if err := s.persistence.Delete(context.Background(), id, tenantID); err != nil {
			log.Printf("WARNING: delete steer exclusion %s failed: %v", id, err)
		}
	}
	return true
}

// ReplaceTenant atomically replaces ALL of a tenant's cached policies with the supplied set. Used by the
// enforcing Edge's CP→Edge sync: the Edge keeps NO durable DB (zero-DB), so it pulls the authoritative set
// from the control plane and caches it here. A fetch failure must NOT call this (keep the last good set).
// Cache-only: this never write-throughs to persistence (the control plane is the source of truth).
func (s *Store) ReplaceTenant(tenantID string, policies []Policy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Persist the replace too, or the durable cache drifts from the store: this is the CP→Edge sync path, and
	// before it also went through persistence, a synced-away policy stayed in the on-disk file and reappeared
	// for a moment on the next restart (until the next sync corrected it). Mirror Upsert/Delete: Delete the
	// removed ids, Upsert the incoming set. Best-effort — a persist failure must not drop the in-memory sync.
	removed := []string{}
	for id, p := range s.byID {
		if p.TenantID == tenantID {
			delete(s.byID, id)
			removed = append(removed, id)
		}
	}
	for i := range policies {
		stored := policies[i]
		if strings.TrimSpace(stored.ID) == "" || stored.TenantID != tenantID {
			continue
		}
		s.byID[stored.ID] = &stored
	}
	if s.persistence != nil {
		for _, id := range removed {
			if err := s.persistence.Delete(context.Background(), id, tenantID); err != nil {
				log.Printf("WARNING: persist steer-exclusion sync delete %s failed (durability at risk): %v", id, err)
			}
		}
		for i := range policies {
			stored := policies[i]
			if strings.TrimSpace(stored.ID) == "" || stored.TenantID != tenantID {
				continue
			}
			if err := s.persistence.Upsert(context.Background(), &stored); err != nil {
				log.Printf("WARNING: persist steer-exclusion sync upsert %s failed (durability at risk): %v", stored.ID, err)
			}
		}
	}
}

// ResolveForDevice returns the effective excluded signing identifiers for a device: the union of the tenant-,
// its-group-, and its-device-scoped active policies. Pure read; used by the delivery slice.
func (s *Store) ResolveForDevice(tenantID, deviceIdentity, deviceGroup string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	// The enforcing read. If any path must not answer from a snapshot it is this one.
	s.refreshLocked(time.Now())
	merged := []string{}
	for _, p := range s.byID {
		if p.TenantID != tenantID || p.Status != statusActive {
			continue
		}
		match := false
		switch p.ScopeType {
		case scopeTenant:
			match = true
		case scopeDeviceGroup:
			match = deviceGroup != "" && p.ScopeID == deviceGroup
		case scopeDevice:
			match = deviceIdentity != "" && p.ScopeID == deviceIdentity
		}
		if match {
			merged = append(merged, p.ExcludedAppSigningIDs...)
		}
	}
	return normalizeSigningIDs(merged)
}
