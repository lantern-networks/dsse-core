package policyrule

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/lantern-networks/dsse-core/blobstore"
)

// Store is an in-memory, per-tenant store of authored rules. Like the asset catalog it is intentionally
// simple (the edge holds the live, hot-applied state); durability and distribution are layered on by the
// product edge. Safe for concurrent use.
type Store struct {
	mu        sync.Mutex
	seq       int
	rules     map[string]map[string]Rule // tenant -> rule id -> rule
	persister blobstore.Persister        // when set, authored rules are persisted here (survive restart)
	// generation is bumped on every mutation so a control plane can advertise "the rules changed" in one
	// monotonic number. See distribution.go for why the fleet needs it.
	generation uint64
}

// NewStore returns an empty Store.
func NewStore() *Store {
	return &Store{rules: map[string]map[string]Rule{}}
}

func (s *Store) nextIDLocked() string {
	s.seq++
	return "rule-" + strconv.Itoa(s.seq)
}

// Upsert validates and stores a rule (creating an id when absent), returning the stored rule.
func (s *Store) Upsert(r Rule) (Rule, error) {
	if err := r.normalizeAndValidate(); err != nil {
		return Rule{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.TrimSpace(r.ID) == "" {
		r.ID = s.nextIDLocked()
	}
	if s.rules[r.TenantID] == nil {
		s.rules[r.TenantID] = map[string]Rule{}
	}
	s.rules[r.TenantID][r.ID] = r
	s.generation++
	if err := s.persistLocked(); err != nil {
		// The rule IS live in memory (hot-applied); the caller must surface that durability failed so the
		// admin knows it will not survive a restart.
		return r, fmt.Errorf("rule %s applied in memory but not persisted (will not survive a restart): %w", r.ID, err)
	}
	return r, nil
}

// Get returns a rule by id.
func (s *Store) Get(tenantID, id string) (Rule, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rules[tenantID][id]
	return r, ok
}

// Delete removes a rule; it reports whether the rule existed. A non-nil error means the delete IS live in
// memory but the snapshot failed to persist — the rule would resurrect on restart, so callers must surface it.
func (s *Store) Delete(tenantID, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.rules[tenantID][id]; !ok {
		return false, nil
	}
	delete(s.rules[tenantID], id)
	s.generation++
	if err := s.persistLocked(); err != nil {
		return true, fmt.Errorf("rule %s deleted in memory but not persisted (would resurrect on restart): %w", id, err)
	}
	return true, nil
}

// List returns the tenant's rules for a plane, ordered by ascending priority then id (stable). An empty
// plane returns every plane's rules. East-west rules of both directions are included; callers that care
// about direction filter on Rule.Direction (the Console separates Outbound/Inbound tabs).
// RemoveTenant erases every authored rule belonging to one organization, and reports how many there were.
//
// ★★ TENANT DELETION DID NOT REACH THIS STORE (2026-08-17, measured: an organization deleted through the
// Console left its access rule on both planes, still attributed to it). The purge covers the Postgres tables,
// the credential store, the enrolled ledger and the log files; the authored-rule store is file-backed and was
// not among them, so the one thing the organization had authored outlived the organization.
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
	removed := len(s.rules[tenantID])
	if removed == 0 {
		return 0
	}
	delete(s.rules, tenantID)
	s.generation++
	s.persistLocked()
	return removed
}

// Tenants names every organization that has authored rules here.
//
// ★★ THE RECOMPILE NEEDED THIS AND DID NOT HAVE IT (2026-08-17). The Edge compiles authored rules into
// policies, and it did so for ONE organization — the node's own — so a rule authored for any other never
// became a policy and never decided anything, while the Console showed it as active and enforcing.
func (s *Store) Tenants() []string {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.rules))
	for tenant := range s.rules {
		out = append(out, tenant)
	}
	sort.Strings(out)
	return out
}

func (s *Store) List(tenantID, plane string) []Rule {
	plane = strings.ToLower(strings.TrimSpace(plane))
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Rule, 0, len(s.rules[tenantID]))
	for _, r := range s.rules[tenantID] {
		if plane != "" && r.Plane != plane {
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority < out[j].Priority
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// InboundReceiversNeedingPlatform reports the destination ids of an east-west INBOUND rule — the receivers
// whose platform the edge must resolve before saving, because inbound enforces on Windows WFP only (macOS
// receivers cannot be enforced). For any other rule it returns nil. This keeps the platform-aware check at
// the edge (which has the asset catalog) while the rule shape that triggers it is defined here.
func InboundReceiversNeedingPlatform(r Rule) []string {
	if r.Plane != PlaneEastWest || r.Direction != DirectionInbound {
		return nil
	}
	return append([]string(nil), r.Destination...)
}

// ErrMacOSInboundUnsupported is returned by ValidateInboundReceiverPlatforms when an inbound rule's
// receivers are macOS-only (a hard error — the rule cannot be enforced anywhere).
var ErrMacOSInboundUnsupported = fmt.Errorf("east-west inbound is unsupported on macOS receivers (enforce on the source's outbound rule, or target Windows receivers)")

// ValidateInboundReceiverPlatforms checks an inbound east-west rule against its receivers' resolved
// platforms. `platforms` is the set of distinct platform strings ("macos"/"windows"/"") across the rule's
// destination endpoints, as resolved by the edge from the asset catalog. It returns:
//   - a hard error when every receiver is macOS (nothing can enforce the rule), and
//   - a warning string naming the unenforceable macOS receivers when the set is mixed (Windows receivers
//     are enforced; macOS ones are silently uncovered without this notice).
//
// For non-inbound rules it is a no-op. The edge surfaces the hard error as a save-blocking 4xx and the
// warning alongside a successful save.
func ValidateInboundReceiverPlatforms(r Rule, platforms []string, macReceivers []string) (warning string, err error) {
	if r.Plane != PlaneEastWest || r.Direction != DirectionInbound {
		return "", nil
	}
	hasWindows, hasMac := false, false
	for _, p := range platforms {
		switch strings.ToLower(strings.TrimSpace(p)) {
		case "windows":
			hasWindows = true
		case "macos":
			hasMac = true
		}
	}
	if hasMac && !hasWindows {
		return "", ErrMacOSInboundUnsupported
	}
	if hasMac && hasWindows && len(macReceivers) > 0 {
		return fmt.Sprintf("inbound enforces on Windows only; these macOS receivers are not covered: %s", strings.Join(macReceivers, ", ")), nil
	}
	return "", nil
}
