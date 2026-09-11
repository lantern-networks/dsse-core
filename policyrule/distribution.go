package policyrule

// distribution.go — what a control plane needs to make this store's contents authoritative for a FLEET.
//
// ★ Why this exists (2026-08-10). The store's header says durability and distribution "are layered on by the
// product edge". Durability was; distribution never was. Two Edges serving one tenant each kept their own
// rule file, so an authored rule reached whichever Edge the Console happened to be proxied to — and the device
// was served by the other one. Every admin-visible surface reported success, because each Edge answers
// truthfully about itself. See docs/authored_policy_reaches_one_edge_not_the_serving_one.md.
//
// The three pieces a config-bundle distributor needs are all missing from the CRUD surface above, and their
// absence is why nobody wrote the sync:
//
//   ConfigGeneration  — so a rule change advances the bundle generation and every Edge re-pulls. Without it a
//                       rule edit is invisible to the sync loop even once the section exists.
//   Snapshot          — ALL tenants, not one. Distribution is fleet-wide; List() is tenant-scoped and would
//                       have quietly shipped a single tenant's rules as if they were the whole set.
//   ReplaceAll        — because DELETE has to propagate. Every other bundle section is an additive upsert,
//                       which is right for registries where a stale extra entry is harmless. A rule is not
//                       that: an authored `allow` or `bypass` left behind after the admin deleted it is the
//                       permissive direction, and "I deleted the rule and traffic is still allowed" is the
//                       same silent-divergence bug in a worse costume.

import (
	"fmt"
	"sort"
)

// ConfigGeneration returns the monotonic authored-rule config version, bumped on every mutation. A
// config-bundle distributor folds it into the aggregate generation so a rule change triggers a fleet-wide
// re-pull.
func (s *Store) ConfigGeneration() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.generation
}

// Snapshot returns every rule this store holds, across ALL tenants, ordered deterministically (tenant, then
// priority, then id) so an unchanged set serialises identically and does not churn the bundle.
func (s *Store) Snapshot() []Rule {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Rule{}
	for _, byID := range s.rules {
		for _, r := range byID {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TenantID != out[j].TenantID {
			return out[i].TenantID < out[j].TenantID
		}
		if out[i].Priority != out[j].Priority {
			return out[i].Priority < out[j].Priority
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// ReplaceAll makes the given set the entire contents of the store, across every tenant.
//
// ★ REPLACE, not upsert, and the difference is the point — see the header. An invalid rule is REFUSED and the
// whole call fails without touching the store: a partially-applied rule set is a policy nobody authored, and
// choosing it over "keep the last good set" would mean a malformed CP response could invent an access posture.
//
// The caller is responsible for the lockout guard (an empty incoming set means "the CP is not the authority
// here", not "delete every rule"); that judgement belongs with the distributor, which can see whether the
// section was absent or merely empty, and this function cannot.
func (s *Store) ReplaceAll(rules []Rule) error {
	next := map[string]map[string]Rule{}
	for _, r := range rules {
		if err := r.normalizeAndValidate(); err != nil {
			return fmt.Errorf("rule %s (tenant %s): %w", r.ID, r.TenantID, err)
		}
		if r.ID == "" {
			return fmt.Errorf("a distributed rule set may not contain a rule without an id (tenant %s)", r.TenantID)
		}
		if next[r.TenantID] == nil {
			next[r.TenantID] = map[string]Rule{}
		}
		next[r.TenantID][r.ID] = r
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules = next
	s.generation++
	if err := s.persistLocked(); err != nil {
		return fmt.Errorf("distributed rule set applied in memory but not persisted (would revert on restart): %w", err)
	}
	return nil
}
