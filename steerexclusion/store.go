package steerexclusion

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
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

// ErrTenantConflict rejects reuse of an ID owned by another tenant, including
// conflicts discovered by persistence after this node loaded its cache.
var ErrTenantConflict = errors.New("steer exclusion ID is unavailable for this tenant")

// ErrPersistence means the write could not be confirmed. A backend may already
// have written the candidate; callers must not describe this as a disk rollback.
var ErrPersistence = errors.New("steer exclusion persistence could not be confirmed")

func clonePolicy(p Policy) Policy {
	p.ExcludedAppSigningIDs = append([]string(nil), p.ExcludedAppSigningIDs...)
	return p
}

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
	loadErr     error
	// generation moves every time the set this node holds changes, whoever changed it.
	//
	// ★★★ THE CONTROL PLANE HELD THE EXCLUSION AND NO DEVICE EVER GOT IT (2026-11-08, acceptance C, third
	// walk). An administrator excluded ssh.exe in the Console; the control plane saved it ("loaded 1 policy"
	// on its next restart), every Edge held none, and the device logged "refreshed 0 signed exclusion(s)" once
	// a minute while the list read "active". The Edges an installer produces pull ONE channel from the control
	// plane — the config bundle — and the bundle did not carry this store; the separate pull that did was never
	// configured by the installer and only ever asked for one organization. The set now rides the bundle, and
	// an Edge applies a bundle only when its version is newer, so this store has to say when it changed.
	//
	// It counts changes SEEN, not writes made: a policy written through another control plane arrives here
	// on the next re-read of the durable store, and that has to move the version as surely as a write here
	// does. The number is this process's own; the bundle's epoch is per process too, so an Edge re-baselines
	// when the answering control plane changes and never compares two processes' counts.
	generation uint64
	// receiver marks a node that RECEIVES its set (an Edge pulling the config bundle). Its persistence is a cache
	// for the next start, not an authority: re-reading it on a timer would put back what the authority just
	// removed whenever a write to the cache failed (review C3-R3). See SetReceiver.
	receiver bool
	// unconfirmed is set when a replacement's durable copy could not be confirmed, and cleared only by a pass
	// that confirms it — a write of the whole durable state, not a read that happens to show the new rows
	// (review C3-RRR1).
	unconfirmed bool
}

// Syncer is a Persistence that can write its current state again and confirm the write. See
// FilePersistence.Sync.
type Syncer interface {
	Sync(ctx context.Context) error
}

// SetReceiver makes this store a receiver: its durable copy is read once at start and written through, never
// re-read while running. Call it before the store is shared.
func (s *Store) SetReceiver() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.receiver = true
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
	if s.persistence == nil || s.receiver || now.Sub(s.refreshedAt) < refreshWindow {
		return
	}
	s.refreshedAt = now
	policies, err := s.persistence.LoadAll(context.Background())
	var fresh map[string]*Policy
	if err == nil {
		fresh, err = policySnapshot(policies)
	}
	s.loadErr = err
	if err != nil {
		log.Printf("steer exclusions: could not re-read the durable store (%v) — this node keeps the %d "+
			"policy(ies) it holds rather than reporting none", err, len(s.byID))
		return
	}
	if !samePolicies(s.byID, fresh) {
		s.generation++
	}
	s.byID = fresh
}

// samePolicies reports whether two held sets say the same thing. Times compare by instant: the copy read back
// from the database carries no monotonic reading and may carry another location, and neither is a change.
func samePolicies(a, b map[string]*Policy) bool {
	if len(a) != len(b) {
		return false
	}
	for id, x := range a {
		y := b[id]
		if y == nil || x.TenantID != y.TenantID || x.ScopeType != y.ScopeType || x.ScopeID != y.ScopeID ||
			x.Note != y.Note || x.Status != y.Status || !x.CreatedAt.Equal(y.CreatedAt) || !x.UpdatedAt.Equal(y.UpdatedAt) ||
			len(x.ExcludedAppSigningIDs) != len(y.ExcludedAppSigningIDs) {
			return false
		}
		for i := range x.ExcludedAppSigningIDs {
			if x.ExcludedAppSigningIDs[i] != y.ExcludedAppSigningIDs[i] {
				return false
			}
		}
	}
	return true
}

// ConfigGeneration is the version of the set this node holds, for the config bundle's aggregate. It re-reads
// the durable store first (within the refresh window), so a change made through another control plane moves
// it here too.
func (s *Store) ConfigGeneration() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked(time.Now())
	return s.generation
}

// SnapshotAllChecked is every organization's policies, for the config bundle. Like ListChecked it refuses to
// present a retained set as the authority's answer: a bundle that carried a stale set would be applied by
// every Edge as the whole truth.
func (s *Store) SnapshotAllChecked() ([]Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked(time.Now())
	if s.loadErr != nil {
		return nil, s.loadErr
	}
	out := make([]Policy, 0, len(s.byID))
	for _, p := range s.byID {
		out = append(out, clonePolicy(*p))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
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
		fresh, err := policySnapshot(policies)
		if err != nil {
			return nil, fmt.Errorf("load persisted steer exclusions: %w", err)
		}
		s.byID = fresh
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
// On ErrPersistence, the returned candidate identifies the attempted write, not a
// published policy. The previous local state remains in use.
func (s *Store) Upsert(p Policy, now time.Time) (Policy, error) {
	// Authored records must satisfy the canonical identity contract used by readers.
	if strings.TrimSpace(p.ID) != "" && strings.TrimSpace(p.ID) != p.ID {
		return Policy{}, fmt.Errorf("id must not contain surrounding whitespace")
	}
	if strings.TrimSpace(p.TenantID) != p.TenantID {
		return Policy{}, fmt.Errorf("tenant_id must not contain surrounding whitespace")
	}
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
	s.refreshLocked(time.Now())
	if s.loadErr != nil {
		return p, fmt.Errorf("%w: stored state unavailable: %w", ErrPersistence, s.loadErr)
	}
	if strings.TrimSpace(p.ID) == "" {
		p.ID = newPolicyID(now)
	}
	existing := s.byID[p.ID]
	if existing != nil {
		if existing.TenantID != p.TenantID {
			return Policy{}, ErrTenantConflict
		}
		p.CreatedAt = existing.CreatedAt
	} else {
		p.CreatedAt = now.UTC()
	}
	p.UpdatedAt = now.UTC()
	stored := clonePolicy(p)
	if s.persistence != nil {
		if err := s.persistence.Upsert(context.Background(), &stored); err != nil {
			if errors.Is(err, ErrTenantConflict) {
				return Policy{}, ErrTenantConflict
			}
			return clonePolicy(stored), fmt.Errorf("%w: %w", ErrPersistence, err)
		}
	}
	s.byID[p.ID] = &stored
	s.generation++
	return clonePolicy(stored), nil
}

// List returns the tenant's policies (stable order).
func (s *Store) List(tenantID string) []Policy {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked(time.Now())
	return s.listLocked(tenantID)
}

// ListChecked never advertises a retained, stale set as a successful authority
// read. Enforcement can still use List/ResolveForDevice to retain the last set.
func (s *Store) ListChecked(tenantID string) ([]Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked(time.Now())
	if s.loadErr != nil {
		return nil, s.loadErr
	}
	return s.listLocked(tenantID), nil
}

func (s *Store) listLocked(tenantID string) []Policy {
	out := []Policy{}
	for _, p := range s.byID {
		if p.TenantID == tenantID {
			out = append(out, clonePolicy(*p))
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
		return clonePolicy(*p), true
	}
	return Policy{}, false
}

// Delete is the compatibility wrapper. Administrative callers use DeleteChecked
// to distinguish a missing policy from an unconfirmed save.
func (s *Store) Delete(id, tenantID string, now time.Time) bool {
	deleted, err := s.DeleteChecked(id, tenantID, now)
	return deleted && err == nil
}

// DeleteChecked publishes the removal only after persistence confirms it.
func (s *Store) DeleteChecked(id, tenantID string, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked(time.Now())
	if s.loadErr != nil {
		return false, fmt.Errorf("%w: stored state unavailable: %w", ErrPersistence, s.loadErr)
	}
	p := s.byID[id]
	if p == nil || p.TenantID != tenantID {
		return false, nil
	}
	if s.persistence != nil {
		if err := s.persistence.Delete(context.Background(), id, tenantID); err != nil {
			return false, fmt.Errorf("%w: %w", ErrPersistence, err)
		}
	}
	delete(s.byID, id)
	s.generation++
	return true, nil
}

// ReplaceTenant atomically replaces ALL of a tenant's cached policies with the supplied set. Used by the
// enforcing Edge's CP→Edge sync: the Edge keeps NO durable DB (zero-DB), so it pulls the authoritative set
// from the control plane and caches it here. A fetch failure must NOT call this (keep the last good set).
// A configured cache persistence is updated best-effort; this sync contract is
// distinct from administrative write confirmation in Upsert/DeleteChecked.
func (s *Store) ReplaceTenant(tenantID string, policies []Policy) {
	if err := s.ReplaceTenantChecked(tenantID, policies); err != nil {
		log.Printf("steer exclusions: tenant replacement rejected: %v", err)
	}
}

// ReplaceTenantChecked replaces one organization's set; see ReplaceTenantsChecked.
func (s *Store) ReplaceTenantChecked(tenantID string, policies []Policy) error {
	return s.ReplaceTenantsChecked(map[string][]Policy{tenantID: policies})
}

// ReplaceTenantsChecked replaces the sets of every organization it is given, together.
//
// ★ EVERYTHING IS CHECKED BEFORE ANYTHING CHANGES (review C3-R3 and the note under it). Validation, and the
// ownership of every policy ID against what is held for the organizations NOT being replaced, happen first; one
// refusal leaves every organization as it was. Before, a conflict in the second organization was found after the
// first had been replaced.
//
// ★ A FAILED SAVE IS AN ERROR. The new set is what this node now holds — the authority sent it — so it stays in
// memory; the error tells the caller the durable copy did not follow, so a config bundle is not recorded as
// applied and is offered again. Before, a failed save was logged and reported as success, and five seconds later
// the timer re-read the stale cache: a removed exclusion came back and nothing ever removed it again.
func (s *Store) ReplaceTenantsChecked(sets map[string][]Policy) error {
	incomingOwner := map[string]string{}
	for tenantID, policies := range sets {
		if err := ValidateTenantPolicies(tenantID, policies); err != nil {
			return err
		}
		for _, p := range policies {
			if other, seen := incomingOwner[p.ID]; seen && other != tenantID {
				return ErrTenantConflict
			}
			incomingOwner[p.ID] = tenantID
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, tenant := range incomingOwner {
		if current := s.byID[id]; current != nil && current.TenantID != tenant {
			if _, replaced := sets[current.TenantID]; !replaced {
				return ErrTenantConflict
			}
		}
	}
	// What the durable copy must lose is read from the durable copy (review C3-RR1). Taken from memory, a
	// removal whose save failed was forgotten: memory had already dropped it, so the retry found nothing to
	// remove, reported success, and the stale row came back at the next start.
	removed := map[string]string{} // id -> tenant
	var persisted []*Policy
	var readErr error
	if s.persistence != nil {
		persisted, readErr = s.persistence.LoadAll(context.Background())
	}
	for _, p := range persisted {
		if p == nil {
			continue
		}
		if _, replaced := sets[p.TenantID]; replaced && incomingOwner[p.ID] != p.TenantID {
			removed[p.ID] = p.TenantID
		}
	}
	for id, p := range s.byID {
		if _, replaced := sets[p.TenantID]; replaced {
			delete(s.byID, id)
		}
	}
	for tenantID, policies := range sets {
		for i := range policies {
			stored := clonePolicy(policies[i])
			stored.TenantID = tenantID
			s.byID[stored.ID] = &stored
		}
	}
	s.generation++
	if s.persistence == nil {
		return nil
	}
	if readErr != nil {
		// The received set is in force; the durable copy is left for the retry this error asks for.
		s.unconfirmed = true
		return fmt.Errorf("%w: the durable copy could not be read to replace it: %w", ErrPersistence, readErr)
	}
	var failed []error
	for id, tenantID := range removed {
		if err := s.persistence.Delete(context.Background(), id, tenantID); err != nil {
			failed = append(failed, fmt.Errorf("remove %s: %w", id, err))
		}
	}
	for tenantID, policies := range sets {
		for i := range policies {
			stored := clonePolicy(policies[i])
			stored.TenantID = tenantID
			if err := s.persistence.Upsert(context.Background(), &stored); err != nil {
				failed = append(failed, fmt.Errorf("save %s: %w", stored.ID, err))
			}
		}
	}
	if len(failed) > 0 {
		s.unconfirmed = true
		return fmt.Errorf("%w: the received set is in force here, and its durable copy was not written: %w", ErrPersistence, errors.Join(failed...))
	}
	// A previous pass reported its durable copy unconfirmed. Reading the new rows back does not confirm them —
	// a save can put its bytes in place and still fail to confirm them — so the whole state is written again
	// and confirmed before this pass may say it is durable.
	if s.unconfirmed {
		if syncer, ok := s.persistence.(Syncer); ok {
			if err := syncer.Sync(context.Background()); err != nil {
				return fmt.Errorf("%w: the durable copy of an earlier replacement is still unconfirmed: %w", ErrPersistence, err)
			}
		}
		s.unconfirmed = false
	}
	return nil
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
			// The Console scopes a policy from one list and shows whether it applies by comparing lower-cased
			// (deviceKey in ui.js), because the lists spell the same machine differently — a Windows host name
			// in capitals in one, lower case in another.
			//
			// ★ THE SAME RELATION ENROLMENT USES, AND NO WIDER (review C3-R2). strings.EqualFold also folds
			// Unicode equivalents — "desktop-s" and "desktop-ſ" (U+017F) are one under it and two enrolled
			// devices under enrolledinventory.NormalizeIdentity (trim, then ToLower). An exclusion meant for one
			// of them was signed for the other. Two identities are the same device here exactly when enrolment
			// says they are.
			match = deviceIdentity != "" && sameEnrolledIdentity(p.ScopeID, deviceIdentity)
		}
		if match {
			merged = append(merged, p.ExcludedAppSigningIDs...)
		}
	}
	return normalizeSigningIDs(merged)
}

// sameEnrolledIdentity is enrolledinventory.NormalizeIdentity's relation (trim, then lower case), kept here
// rather than imported so this package stays free of the ledger. TestTheDeviceRelationIsEnrolments holds the
// two together.
func sameEnrolledIdentity(a, b string) bool {
	return strings.ToLower(strings.TrimSpace(a)) == strings.ToLower(strings.TrimSpace(b))
}
