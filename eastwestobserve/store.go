// Package eastwestobserve is the S1 (Observe) foundation of the East-West policy-learning lifecycle
// (Observe → Candidate → Warn → Partial Enforce → Full Enforce, see docs/east_west_policy_learning_lifecycle_gap.md).
//
// It records the LATERAL flows the tenant sees while East-West enforcement is still off (WATCHING / pre-enforce)
// as a structured, browsable inventory keyed by (source, destination, service). Unlike the egress
// policycandidate store (destination host/sni/port only), an east-west observation carries a SOURCE axis. It
// changes NOTHING about enforcement — it only records, so an operator can review the flows, adopt them into rules
// (S2), and watch the inventory CONVERGE (uncovered-flow rate → ~0) which is the readiness signal that disabling
// Allow-all (Full Enforce, S5) is safe.
//
// Note on source identity: in Observe there is no step-up ceremony, so the USER is unknown. The source recorded
// here is the device identity when the transport carries one, else "Any" — matching the S2 decision that adopted
// rules default to who=Any (a destination allow-list), narrowed manually later.
package eastwestobserve

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
)

// SourceAny is the recorded source when the observed flow carries no device identity (no ceremony runs in
// Observe, so no user identity is ever known). It mirrors the S2 adopted-rule default who=Any.
const SourceAny = "Any"

// FlowObservation is one aggregated lateral flow (source → destination : service) the tenant has seen while
// pre-enforce. Repeated sightings of the same (source, destination, service, port) upsert one record and
// increment Count.
type FlowObservation struct {
	ObservationID string `json:"observation_id"`
	TenantID      string `json:"tenant_id"`
	Source        string `json:"source"` // device id, or SourceAny
	// User is the logged-in user behind the flow (the corporate/OS user resolved at observe time), or empty when
	// NO user is logged in — i.e. machine / service / unattended traffic. It lets an operator tell HUMAN traffic
	// from SYSTEM traffic in the inventory (see Human()). Latest sighting wins (a flow is re-attributed to whoever
	// last made it). NOT part of the flow key — the key is device→dest:service; the user is per-flow metadata.
	User          string `json:"user,omitempty"`
	Destination   string `json:"destination"`    // dest IP / host / published-app identifier
	ServiceFamily string `json:"service_family"` // ssh / smb / rdp / winrm / ...
	Port          int    `json:"port"`
	Count         int    `json:"count"`      // number of times this flow was observed
	FirstSeen     string `json:"first_seen"` // RFC3339
	LastSeen      string `json:"last_seen"`  // RFC3339
	// Covered is whether an authored East-West rule already matches this flow. It is NOT stored — it is computed
	// at QUERY time against the CURRENT rule set (so it never goes stale) and set on the returned view. It drives
	// CONVERGENCE: the ramp is "complete" when uncovered flows stop appearing; covered flows need no adoption.
	Covered bool `json:"covered"`
}

// Human reports whether this flow was made by a logged-in user (human traffic) rather than an unattended
// machine/service (system traffic). Used by the Console to badge each observed flow human vs system.
func (o FlowObservation) Human() bool { return strings.TrimSpace(o.User) != "" }

// ObservationKey identifies a flow for dedup/upsert. Source is included so the same destination seen from
// different devices is distinguishable (an east-west observation is a FLOW, not just a destination).
func ObservationKey(source, destination, serviceFamily string, port int) string {
	key := strings.Join([]string{
		normalize(source), normalize(destination), normalize(serviceFamily), strconv.Itoa(port),
	}, "|")
	sum := sha256.Sum256([]byte(key))
	return "ewobs-" + hex.EncodeToString(sum[:10])
}

func normalize(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// Store is an east-west flow-observation inventory, per tenant. Safe for concurrent use. In-memory by default;
// attach a Persister (SetPersister) to make the inventory SURVIVE an Edge restart — otherwise every restart resets
// the learning inventory to empty, which resets the "uncovered → 0" convergence readiness signal.
type Store struct {
	mu        sync.RWMutex
	flows     map[string]map[string]FlowObservation // tenantID -> observationID -> observation
	persister blobstore.Persister
	retention time.Duration // drop observations whose LastSeen is older than this (0 = keep forever)
	dirty     bool          // there are un-persisted changes since the last flush
}

// NewStore returns an empty observation store.
func NewStore() *Store { return &Store{flows: map[string]map[string]FlowObservation{}} }

// SetPersister attaches durable storage and REHYDRATES the inventory from it (so observations survive a restart),
// dropping any whose LastSeen is older than retention (0 = keep forever). Call once at startup before serving.
// A load error is returned but is non-fatal — a fresh store still works. Pair with periodic PersistIfDirty().
func (s *Store) SetPersister(p blobstore.Persister, retention time.Duration) error {
	s.mu.Lock()
	s.persister = p
	s.retention = retention
	s.mu.Unlock()
	if p == nil {
		return nil
	}
	data, err := p.Load()
	if err != nil || len(data) == 0 {
		return err
	}
	var snap map[string]map[string]FlowObservation
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if snap != nil {
		s.flows = snap
	}
	s.pruneLocked(time.Now())
	return nil
}

// pruneLocked drops observations older than the retention window. Caller holds the write lock.
func (s *Store) pruneLocked(now time.Time) {
	if s.retention <= 0 {
		return
	}
	cutoff := now.Add(-s.retention)
	for tenant, byID := range s.flows {
		for id, obs := range byID {
			if t, err := time.Parse(time.RFC3339, obs.LastSeen); err == nil && t.Before(cutoff) {
				delete(byID, id)
			}
		}
		if len(byID) == 0 {
			delete(s.flows, tenant)
		}
	}
}

// PersistIfDirty writes a snapshot to durable storage when there are unsaved changes (prunes expired flows first).
// Cheap no-op when clean or when no persister is attached. Call periodically (e.g. every 30s) — Observe() only
// marks the store dirty, so the hot path never does I/O.
func (s *Store) PersistIfDirty() error {
	s.mu.Lock()
	if !s.dirty || s.persister == nil {
		s.mu.Unlock()
		return nil
	}
	s.pruneLocked(time.Now())
	data, err := json.Marshal(s.flows)
	p := s.persister
	if err == nil {
		s.dirty = false
	}
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if err := p.Save(data); err != nil {
		// The dirty flag was cleared optimistically before Save (Save runs outside the lock). On a failed
		// Save, re-mark dirty so the NEXT periodic flush retries — otherwise a transient failure silently
		// dropped this snapshot until some future Observe happened to dirty the store again.
		s.mu.Lock()
		s.dirty = true
		s.mu.Unlock()
		return err
	}
	return nil
}

// Observe records one sighting of a lateral flow. First sighting creates the record (Count=1, FirstSeen=now);
// subsequent sightings increment Count and refresh LastSeen. Destination is required; an empty source is recorded
// as SourceAny. Coverage is NOT recorded here (it is computed at query time). Returns the upserted observation.
// It never enforces anything.
func (s *Store) Observe(tenantID, source, user, destination, serviceFamily string, port int, now time.Time) FlowObservation {
	tenantID = strings.TrimSpace(tenantID)
	destination = strings.TrimSpace(destination)
	if tenantID == "" || destination == "" {
		return FlowObservation{}
	}
	source = strings.TrimSpace(source)
	if source == "" {
		source = SourceAny
	}
	user = strings.TrimSpace(user)
	serviceFamily = normalize(serviceFamily)
	if now.IsZero() {
		now = time.Now().UTC()
	}
	ts := now.UTC().Format(time.RFC3339)
	id := ObservationKey(source, destination, serviceFamily, port)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.flows[tenantID] == nil {
		s.flows[tenantID] = map[string]FlowObservation{}
	}
	obs, ok := s.flows[tenantID][id]
	if !ok {
		obs = FlowObservation{
			ObservationID: id, TenantID: tenantID, Source: source, Destination: destination,
			ServiceFamily: serviceFamily, Port: port, Count: 0, FirstSeen: ts,
		}
	}
	// Latest sighting wins for the user (re-attribute to whoever last made the flow). Recording an empty user is
	// meaningful — it flips the flow to "system" (unattended/machine), which is exactly the human-vs-system signal.
	obs.User = user
	obs.Count++
	obs.LastSeen = ts
	s.flows[tenantID][id] = obs
	s.dirty = true // a periodic PersistIfDirty() will snapshot this; the hot path stays I/O-free
	return obs
}

// Get returns one observation by id (for adoption). ok=false if absent.
func (s *Store) Get(tenantID, observationID string) (FlowObservation, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	obs, ok := s.flows[strings.TrimSpace(tenantID)][strings.TrimSpace(observationID)]
	return obs, ok
}

// List returns the tenant's observations, newest-last-seen first.
func (s *Store) List(tenantID string) []FlowObservation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]FlowObservation, 0, len(s.flows[tenantID]))
	for _, obs := range s.flows[tenantID] {
		out = append(out, obs)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].LastSeen != out[j].LastSeen {
			return out[i].LastSeen > out[j].LastSeen
		}
		return out[i].ObservationID < out[j].ObservationID
	})
	return out
}

// Convergence summarizes how close the tenant is to being safe to disable Allow-all (Full Enforce): the count of
// distinct flows, how many are already covered by an authored rule, and how recently a NEW uncovered flow first
// appeared. When uncovered flows stop appearing (NewestUncoveredFirstSeen stays old), the ramp has converged.
type Convergence struct {
	TotalFlows               int     `json:"total_flows"`
	CoveredFlows             int     `json:"covered_flows"`
	UncoveredFlows           int     `json:"uncovered_flows"`
	CoveragePercent          float64 `json:"coverage_percent"`
	NewestUncoveredFirstSeen string  `json:"newest_uncovered_first_seen,omitempty"` // RFC3339; the most recent time a still-uncovered flow was FIRST seen ("" if none uncovered)
}

// ConvergenceOf computes the readiness stats over a set of observations, using `covered` to decide whether each
// flow is already matched by an authored rule. Coverage is evaluated against the CURRENT rule set at call time
// (the caller supplies the predicate), so it never goes stale. Pass the result of List(tenant) as obs.
func ConvergenceOf(obs []FlowObservation, covered func(FlowObservation) bool) Convergence {
	c := Convergence{}
	for _, o := range obs {
		c.TotalFlows++
		if covered != nil && covered(o) {
			c.CoveredFlows++
			continue
		}
		c.UncoveredFlows++
		if o.FirstSeen > c.NewestUncoveredFirstSeen {
			c.NewestUncoveredFirstSeen = o.FirstSeen
		}
	}
	if c.TotalFlows > 0 {
		c.CoveragePercent = float64(c.CoveredFlows) / float64(c.TotalFlows) * 100
	}
	return c
}
