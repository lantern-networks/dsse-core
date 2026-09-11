package main

import (
	"fmt"
	"sort"
	"sync/atomic"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/dlp"
	"github.com/lantern-networks/dsse-core/model"
)

// overlayRuntimeDLPRules appends a tenant's runtime-authored DLP rules to a COPY of the evaluator's bundle
// DLPRules, so they surface as dlp_inspect directives on the decision alongside the bundle's own rules. The
// evaluator is passed by value; only the copy's slice field is rebound, never the base bundle's slice.
func overlayRuntimeDLPRules(eval decision.Evaluator, store dlpRuleRuntimeReader) decision.Evaluator {
	if store == nil {
		return eval
	}
	runtime := store.RulesForTenant(eval.PolicyBundle.TenantID)
	if len(runtime) == 0 {
		return eval
	}
	merged := make([]model.DLPRule, 0, len(eval.PolicyBundle.DLPRules)+len(runtime))
	merged = append(merged, eval.PolicyBundle.DLPRules...)
	merged = append(merged, runtime...)
	eval.PolicyBundle.DLPRules = merged
	return eval
}

// dlpRuleRuntimeReader supplies the runtime-authored DLP rules for a tenant (overlaid onto the bundle's
// DLPRules so they surface as dlp_inspect directives, per-destination — the unified DLP-as-egress-rule path).
type dlpRuleRuntimeReader interface {
	RulesForTenant(tenantID string) []model.DLPRule
}

// dlpRuleRuntimeStore holds per-tenant DLP rules with atomic hot-swap (the dnsresolver.livePolicy idiom): the
// /admin/dlp-rules API publishes a new immutable map so the egress data path reads live rules without a lock
// or restart. These are model.DLPRules WITH a selector (the removed tenant-wide store had none), so
// runtime authoring gets the same per-destination scoping the bundle rules have.
type dlpRuleRuntimeStore struct {
	rules atomic.Pointer[map[string][]model.DLPRule]
}

func newDLPRuleRuntimeStore() *dlpRuleRuntimeStore {
	s := &dlpRuleRuntimeStore{}
	empty := map[string][]model.DLPRule{}
	s.rules.Store(&empty)
	return s
}

// RulesForTenant returns the live DLP rules for a tenant (nil if none).
func (s *dlpRuleRuntimeStore) RulesForTenant(tenantID string) []model.DLPRule {
	if s == nil {
		return nil
	}
	if m := s.rules.Load(); m != nil {
		return (*m)[tenantID]
	}
	return nil
}

// SetRules atomically replaces one tenant's DLP rules (copy-on-write swap of the whole map).
func (s *dlpRuleRuntimeStore) SetRules(tenantID string, rules []model.DLPRule) {
	next := map[string][]model.DLPRule{}
	if old := s.rules.Load(); old != nil {
		for k, v := range *old {
			next[k] = v
		}
	}
	next[tenantID] = rules
	s.rules.Store(&next)
}

// Tenants returns the tenant ids that have rules, ordered (for admin listing).
func (s *dlpRuleRuntimeStore) Tenants() []string {
	m := s.rules.Load()
	if m == nil {
		return nil
	}
	out := make([]string, 0, len(*m))
	for t := range *m {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// validateDLPRules checks admin-supplied rules: each needs a known action and at least one known identifier. A
// tenant's operator-defined custom classifiers (custom, may be nil) are accepted as identifiers too, so a rule
// can govern a custom identifier alongside the built-ins.
func validateDLPRules(rules []model.DLPRule, custom *dlp.ClassifierSet) error {
	for i, r := range rules {
		if !dlp.KnownAction(dlp.Action(r.OnMatch)) {
			return fmt.Errorf("rule %d: invalid on_match %q (want observe|warn|block|authenticate)", i, r.OnMatch)
		}
		if len(r.Identifiers) == 0 {
			return fmt.Errorf("rule %d: at least one identifier is required", i)
		}
		if !dlpKnownInstanceScope(r.InstanceScope) {
			return fmt.Errorf("rule %d: invalid instance_scope %q (want any|corporate|personal)", i, r.InstanceScope)
		}
		for _, id := range r.Identifiers {
			if !dlpKnownIdentifier(id, custom) {
				return fmt.Errorf("rule %d: unknown identifier %q", i, id)
			}
		}
	}
	return nil
}

// dlpKnownIdentifier delegates to the engine's catalog (single source of truth) so the two validation paths never
// drift — a new built-in identifier in oss/dlp is accepted here automatically — plus the tenant's custom
// classifiers (custom, may be nil).
func dlpKnownIdentifier(id string, custom *dlp.ClassifierSet) bool {
	return dlp.KnownIdentifier(dlp.IdentifierType(id)) || custom.Has(id)
}
