package policy

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tenantrestriction"
)

type RuntimeStore interface {
	List(context.Context, string, ListOptions) (ListResponse, error)
	Get(context.Context, string, string) (model.Policy, bool, error)
	Upsert(context.Context, model.Policy, string, time.Time) (model.Policy, error)
	// Delete removes an admin-authored policy (the only kind the Admin API may remove — bundle policies
	// error). (policy, existed-as-authored, error).
	Delete(context.Context, string, string) (model.Policy, bool, error)
	// ConfigGeneration + Snapshot + SnapshotTenantConfig back the Phase 1 config-bundle feed
	// (GET /admin/config-bundle): the monotonic generation, the tenant's policies, and its distributed
	// config toggles (east-west / server-initiated / SWG status).
	ConfigGeneration() uint64
	Snapshot(string) []model.Policy
	SnapshotTenantConfig(string) TenantConfigBundle
}

type RuntimeEvaluatorStore interface {
	RuntimeEvaluator(decision.Evaluator) decision.Evaluator
}

type ListOptions struct {
	Status string
	Limit  int
}

type ListResponse struct {
	Policies []model.Policy `json:"policies"`
	Count    int            `json:"count"`
	Limit    int            `json:"limit"`
}

type Store struct {
	mu       sync.RWMutex
	policies map[string]map[string]model.Policy
	// cachedPolicies / cachedPolicyIDs are an immutable, pre-sorted, pre-deep-copied snapshot of all
	// policies across tenants, rebuilt only when policies change. RuntimeEvaluator assigns them
	// on the per-flow hot path instead of deep-copying + sorting every policy on every decision. The
	// snapshot is never mutated in place (a mutation builds a fresh slice and replaces the field), so the
	// evaluator can safely share it read-only; orderedPolicies copies before its own ordering sort.
	cachedPolicies  []model.Policy
	cachedPolicyIDs []string
	// adminAuthoredPolicies tracks policies CREATED via the Admin API (Upsert / adopt-observed-flow), keyed
	// tenant -> id, kept SEPARATE from bundle-seeded policies. Persisted + restored on boot as an overlay ON TOP
	// of the committed-bundle seed, so an admin-authored policy survives a restart. Without this, POST
	// /admin/policies added a policy to `policies` in memory only and it silently vanished on the next restart
	// (the bundle re-seed covers only committed policies). The bundle stays the source-of-truth for its own set.
	adminAuthoredPolicies map[string]map[string]model.Policy
	// tenantRestrictionRuleStatus maps a SWG tenant-restriction rule id to a runtime status override
	// ("active"/"inactive"). Applied in RuntimeEvaluator so Admin API SaaS enable/disable toggles take
	// effect on the live decision path without a restart.
	tenantRestrictionRuleStatus map[string]string
	tenantRestrictions          map[string]map[string]tenantrestriction.Setting
	// policyStatusOverride maps tenant id -> policy id -> status ("active"/"disabled"): a runtime enable/disable
	// of an individual policy (incl. a built-in seeded one). Persisted, so a disable survives a restart even
	// though the policy re-seeds from the config source. Applied onto the policies on set + on load.
	policyStatusOverride map[string]map[string]string
	// eastWestEnabled / eastWestRules hold the east-west per-hop authorization config per tenant
	// (allow/authenticate/deny, default-deny). Applied in RuntimeEvaluator so admin changes hot-apply to
	// the live decision path with no restart (E1.5).
	eastWestEnabled map[string]bool
	// eastWestAllowUnmatched decouples rule-enforcement from default-deny (S4 Partial Enforce): when true, enabled
	// rules bite but a flow matching NO rule is allowed (allow-all default) instead of denied. false (default) =
	// Full Enforce (unmatched denied). The learning-lifecycle posture is (enabled, allowUnmatched): (false,*)=
	// Observe, (true,true)=Partial, (true,false)=Full.
	eastWestAllowUnmatched map[string]bool
	// eastWestInternalNetworks is what the operator DECLARED internal for this tenant, on top of private
	// address space. It is a plane-membership input, not a rule: a destination outside it, on a public
	// address, is internet access whatever protocol reaches it, and belongs on the north-bound plane.
	eastWestInternalNetworks map[string]decision.InternalNetworks
	eastWestRules            map[string][]decision.EastWestRule
	// compiledEastWestRules holds east-west rules compiled from the unified authored-rule model (the Console
	// rule editor), kept SEPARATE from eastWestRules (the legacy /admin/east-west set) so neither clobbers the
	// other. RuntimeEvaluator unions the two; both apply only when east-west enforcement is enabled.
	compiledEastWestRules map[string][]decision.EastWestRule
	// compiledPolicies holds egress policies compiled from the authored egress access rules, kept SEPARATE
	// from the operator/adopted policies so neither clobbers the other. RuntimeEvaluator unions them.
	compiledPolicies map[string][]model.Policy
	// eastWestGrants holds the active ephemeral grants per tenant that release authenticate-mode holds
	// (E3). Injected into the live evaluator by RuntimeEvaluator; the evaluator drops expired ones.
	eastWestGrants map[string][]decision.EastWestGrant
	// eastWestMaxGrantTTL is the per-tenant admin-configurable ceiling (seconds) on east-west grant
	// lifetime (E6). 0 = no tenant cap. Per-rule MaxTTLSeconds (sensitivity tiering) caps further.
	eastWestMaxGrantTTL map[string]int
	// serverInitiatedEnabled / legacyExceptions hold the server-initiated (server->client) access
	// control config per tenant. Applied in RuntimeEvaluator so admin changes hot-apply to the live path.
	serverInitiatedEnabled map[string]bool
	legacyExceptions       map[string][]model.LegacyException
	// runtimeStatePersister, when set, is a durable store of the Admin-API runtime TOGGLES (tenant-restriction
	// status, east-west enabled/rules/maxTTL) that survive a restart. It is an overlay restored on boot ON
	// TOP OF the committed bundle seed — the bundle stays the policy source-of-truth. Ephemeral state
	// (east-west grants) is NOT persisted. nil = no persistence. A shared (Postgres) persister survives a CP failover.
	runtimeStatePersister blobstore.Persister
	// generation is a monotonic counter bumped on every policy mutation (Upsert / ReplaceTenant). Phase 1
	// config distribution uses it as the policy "config
	// version": the control plane serves {generation, policies} via GET /admin/config-bundle and each Edge
	// applies a bundle only when its generation is newer than the one it last applied.
	generation uint64
}

func NewStore(seed []model.Policy) *Store {
	store := &Store{
		policies:                    map[string]map[string]model.Policy{},
		tenantRestrictions:          map[string]map[string]tenantrestriction.Setting{},
		tenantRestrictionRuleStatus: map[string]string{},
		policyStatusOverride:        map[string]map[string]string{},
		eastWestEnabled:             map[string]bool{},
		eastWestAllowUnmatched:      map[string]bool{},
		eastWestInternalNetworks:    map[string]decision.InternalNetworks{},
		eastWestRules:               map[string][]decision.EastWestRule{},
		compiledEastWestRules:       map[string][]decision.EastWestRule{},
		compiledPolicies:            map[string][]model.Policy{},
		eastWestGrants:              map[string][]decision.EastWestGrant{},
		eastWestMaxGrantTTL:         map[string]int{},
		serverInitiatedEnabled:      map[string]bool{},
		legacyExceptions:            map[string][]model.LegacyException{},
	}
	now := time.Now().UTC()
	for _, policy := range seed {
		tenantID := strings.TrimSpace(policy.TenantID)
		if tenantID == "" {
			continue
		}
		normalized, err := normalizeAdminPolicy(policy, tenantID, now)
		if err != nil {
			continue
		}
		store.putLocked(normalized)
	}
	store.rebuildPolicyCacheLocked()
	return store
}

func (store *Store) List(_ context.Context, tenantID string, options ListOptions) (ListResponse, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return ListResponse{}, fmt.Errorf("tenant_id is required")
	}
	status := strings.TrimSpace(options.Status)
	if status != "" && !validAdminPolicyStatus(status) {
		return ListResponse{}, fmt.Errorf("policy status %s is invalid", status)
	}
	limit := options.Limit
	if limit <= 0 {
		limit = 100
	}

	store.mu.RLock()
	defer store.mu.RUnlock()

	rows := []model.Policy{}
	for _, policy := range store.policies[tenantID] {
		if status != "" && policy.Status != status {
			continue
		}
		rows = append(rows, copyAdminPolicy(policy))
	}
	SortPolicies(rows)
	count := len(rows)
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return ListResponse{
		Policies: rows,
		Count:    count,
		Limit:    limit,
	}, nil
}

func (store *Store) Get(_ context.Context, tenantID, policyID string) (model.Policy, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	policyID = strings.TrimSpace(policyID)
	if tenantID == "" {
		return model.Policy{}, false, fmt.Errorf("tenant_id is required")
	}
	if policyID == "" {
		return model.Policy{}, false, fmt.Errorf("policy_id is required")
	}

	store.mu.RLock()
	defer store.mu.RUnlock()

	policy, ok := store.policies[tenantID][policyID]
	if !ok {
		return model.Policy{}, false, nil
	}
	return copyAdminPolicy(policy), true, nil
}

func (store *Store) Upsert(_ context.Context, policy model.Policy, tenantID string, now time.Time) (model.Policy, error) {
	normalized, err := normalizeAdminPolicy(policy, tenantID, now)
	if err != nil {
		return model.Policy{}, err
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	if err := store.saveAuthoredPolicyLocked(normalized); err != nil {
		return model.Policy{}, err
	}
	store.putLocked(normalized)
	store.generation++
	store.rebuildPolicyCacheLocked()
	return copyAdminPolicy(normalized), nil
}

// Delete removes an ADMIN-AUTHORED policy, its authored record, and any status override for it. Only
// authored policies can be deleted: everything else in the store arrived from the policy bundle or the
// -policy flag, is configuration rather than runtime state, and would be resurrected by the next bundle
// apply anyway — refusing is more honest than a deletion that silently un-deletes. Returns whether the
// policy existed as authored, so the handler can 404 a bundle policy with the reason.
//
// This closes a one-way door: POST /admin/policies could create a policy and nothing could remove it, so
// a mistaken one could only ever be disabled and sat in every listing from then on.
func (store *Store) Delete(_ context.Context, tenantID, policyID string) (model.Policy, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	policyID = strings.TrimSpace(policyID)
	if tenantID == "" {
		return model.Policy{}, false, fmt.Errorf("tenant_id is required")
	}
	if policyID == "" {
		return model.Policy{}, false, fmt.Errorf("policy_id is required")
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	authored, isAuthored := store.adminAuthoredPolicies[tenantID][policyID]
	if !isAuthored {
		if _, exists := store.policies[tenantID][policyID]; exists {
			return model.Policy{}, false, fmt.Errorf("policy %s comes from the policy bundle, not the Admin API — remove it from the bundle configuration instead", policyID)
		}
		return model.Policy{}, false, nil
	}
	delete(store.adminAuthoredPolicies[tenantID], policyID)
	delete(store.policies[tenantID], policyID)
	if overrides := store.policyStatusOverride[tenantID]; overrides != nil {
		delete(overrides, policyID)
	}
	store.generation++
	store.rebuildPolicyCacheLocked()
	store.persistLocked()
	return copyAdminPolicy(authored), true, nil
}

// ConfigGeneration returns the monotonic policy config version (see the generation field). The control
// plane exposes it in the config bundle; an Edge compares it to decide whether to apply (Phase 1).
func (store *Store) ConfigGeneration() uint64 {
	if store == nil {
		return 0
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	return store.generation
}

// Snapshot returns every policy for a tenant (all statuses), deep-copied and ordered — the payload the
// control plane ships in the config bundle so an Edge can ReplaceTenant atomically.
func (store *Store) Snapshot(tenantID string) []model.Policy {
	tenantID = strings.TrimSpace(tenantID)
	rows := []model.Policy{}
	if store == nil || tenantID == "" {
		return rows
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	for _, policy := range store.policies[tenantID] {
		rows = append(rows, copyAdminPolicy(policy))
	}
	// ★ THE ONES COMPILED FROM AUTHORED RULES COUNT TOO (2026-08-17). An organization whose only access rules
	// were written in the Console's rule editor read as having none: this returned the operator/adopted
	// policies alone, so its setup checklist said "no rules — nothing is enforced for them" while the decision
	// path was denying by one of them. Two answers about the same organization, and the screen had the wrong
	// one. They are the same kind of thing to anybody asking "what is enforced here".
	for _, policy := range store.compiledPolicies[tenantID] {
		rows = append(rows, copyAdminPolicy(policy))
	}
	SortPolicies(rows)
	return rows
}

// ReplaceTenant atomically replaces ALL of a tenant's policies with the given set under one write lock, so
// the live evaluator never sees a half-applied bundle (Phase 1 config distribution: the Edge pulls the
// authoritative set from the control plane and swaps it in). Invalid policies are skipped; the tenant is
// re-bound. Returns the count applied.
func (store *Store) ReplaceTenant(tenantID string, policies []model.Policy, now time.Time) int {
	tenantID = strings.TrimSpace(tenantID)
	if store == nil || tenantID == "" {
		return 0
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	n := store.replacePoliciesLocked(tenantID, policies, now)
	store.generation++
	store.rebuildPolicyCacheLocked()
	return n
}

// ApplyBundle atomically replaces a tenant's policies AND its distributed config toggles (east-west,
// server-initiated + legacy exceptions, SWG tenant-restriction status) under ONE write lock with a
// single generation bump, so the live evaluator never sees a half-applied bundle across resources (Phase 1
// config distribution: the Edge pulls the whole tenant bundle from the control plane and swaps it in). Returns
// the policy count applied.
func (store *Store) ApplyBundle(tenantID string, policies []model.Policy, cfg TenantConfigBundle, now time.Time) int {
	tenantID = strings.TrimSpace(tenantID)
	if store == nil || tenantID == "" {
		return 0
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	n := store.replacePoliciesLocked(tenantID, policies, now)
	store.applyTenantConfigLocked(tenantID, cfg)
	store.generation++
	store.rebuildPolicyCacheLocked()
	return n
}

// replacePoliciesLocked rebuilds a tenant's policy map from the given set (invalid skipped, tenant re-bound),
// then re-applies the runtime overlays the incoming bundle does NOT carry: admin-authored policies (created
// via POST /admin/policies) and persisted enable/disable status overrides. Without this re-application a
// config pull (ApplyBundle / ReplaceTenant) silently RESURRECTED a runtime-disabled policy as active and
// DROPPED every admin-authored policy — the boot path already re-applies both, so the two diverged
// (review #20). Caller holds store.mu (write) and is responsible for the generation bump + cache rebuild.
// Returns the count of policies from the incoming bundle (admin-authored overlays are counted separately).
func (store *Store) replacePoliciesLocked(tenantID string, policies []model.Policy, now time.Time) int {
	fresh := map[string]model.Policy{}
	for _, policy := range policies {
		policy.TenantID = tenantID
		normalized, err := normalizeAdminPolicy(policy, tenantID, now)
		if err != nil {
			continue
		}
		fresh[normalized.ID] = normalized
	}
	store.policies[tenantID] = fresh
	n := len(fresh)
	store.reapplyRuntimeOverlaysLocked(tenantID)
	return n
}

// reapplyRuntimeOverlaysLocked re-overlays a tenant's admin-authored policies onto the (freshly re-seeded)
// bundle map and re-applies its persisted status overrides. It mirrors the boot path (store_persistence.go):
// admin-authored FIRST so a status override can also disable one of them. Caller holds store.mu (write).
func (store *Store) reapplyRuntimeOverlaysLocked(tenantID string) {
	for _, policy := range store.adminAuthoredPolicies[tenantID] {
		store.putLocked(policy)
	}
	if overrides := store.policyStatusOverride[tenantID]; len(overrides) > 0 {
		tenantPolicies := store.policies[tenantID]
		for policyID, status := range overrides {
			if policy, ok := tenantPolicies[policyID]; ok {
				policy.Status = status
				tenantPolicies[policyID] = policy
			}
		}
	}
}

// applyTenantConfigLocked swaps in the distributed per-tenant config toggles. Caller holds store.mu (write).
// East-west / server-initiated are tenant-scoped; SWG tenant-restriction status is a global rule-id map that
// the bundle ships wholesale (only replaced when the CP included it). Risk activation/scopes are NOT
// here (node-local auto-activation must survive a pull — see configBundlePayload.TenantConfig).
func (store *Store) applyTenantConfigLocked(tenantID string, cfg TenantConfigBundle) {
	if cfg.SaaSTenantRestrictions != nil {
		store.tenantRestrictions[tenantID] = tenantrestriction.Copy(cfg.SaaSTenantRestrictions)
	}
	if store.eastWestEnabled == nil {
		store.eastWestEnabled = map[string]bool{}
	}
	if store.eastWestAllowUnmatched == nil {
		store.eastWestAllowUnmatched = map[string]bool{}
	}
	if store.eastWestRules == nil {
		store.eastWestRules = map[string][]decision.EastWestRule{}
	}
	if store.eastWestMaxGrantTTL == nil {
		store.eastWestMaxGrantTTL = map[string]int{}
	}
	if store.serverInitiatedEnabled == nil {
		store.serverInitiatedEnabled = map[string]bool{}
	}
	if store.legacyExceptions == nil {
		store.legacyExceptions = map[string][]model.LegacyException{}
	}
	store.eastWestEnabled[tenantID] = cfg.EastWestEnabled
	store.eastWestAllowUnmatched[tenantID] = cfg.EastWestAllowUnmatched
	store.eastWestRules[tenantID] = append([]decision.EastWestRule(nil), cfg.EastWestRules...)
	store.eastWestMaxGrantTTL[tenantID] = cfg.EastWestMaxGrantTTL
	store.serverInitiatedEnabled[tenantID] = cfg.ServerInitiatedEnabled
	store.legacyExceptions[tenantID] = append([]model.LegacyException(nil), cfg.LegacyExceptions...)
	if cfg.TenantRestrictionRuleStatus != nil {
		fresh := map[string]string{}
		for k, v := range cfg.TenantRestrictionRuleStatus {
			fresh[k] = v
		}
		store.tenantRestrictionRuleStatus = fresh
	}
}

// SnapshotTenantConfig returns the distributed config toggles for a tenant (the control plane ships this in
// the config bundle). Mirror of applyTenantConfigLocked; deep-copied so the caller cannot mutate store state.
func (store *Store) SnapshotTenantConfig(tenantID string) TenantConfigBundle {
	cfg := TenantConfigBundle{}
	tenantID = strings.TrimSpace(tenantID)
	if store == nil || tenantID == "" {
		return cfg
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	cfg.SaaSTenantRestrictions = tenantrestriction.Copy(store.tenantRestrictions[tenantID])
	cfg.EastWestEnabled = store.eastWestEnabled[tenantID]
	cfg.EastWestAllowUnmatched = store.eastWestAllowUnmatched[tenantID]
	cfg.EastWestRules = append([]decision.EastWestRule(nil), store.eastWestRules[tenantID]...)
	cfg.EastWestMaxGrantTTL = store.eastWestMaxGrantTTL[tenantID]
	cfg.ServerInitiatedEnabled = store.serverInitiatedEnabled[tenantID]
	cfg.LegacyExceptions = append([]model.LegacyException(nil), store.legacyExceptions[tenantID]...)
	if len(store.tenantRestrictionRuleStatus) > 0 {
		fresh := map[string]string{}
		for k, v := range store.tenantRestrictionRuleStatus {
			fresh[k] = v
		}
		cfg.TenantRestrictionRuleStatus = fresh
	}
	return cfg
}

// rebuildPolicyCacheLocked rebuilds the immutable sorted policy snapshot from store.policies.
// Caller holds store.mu (write). Produces exactly what RuntimeEvaluator used to compute per flow:
// a deep-copied, SortPolicies-ordered slice plus the active policy IDs.
func (store *Store) rebuildPolicyCacheLocked() {
	policies := []model.Policy{}
	for _, tenantPolicies := range store.policies {
		for _, policy := range tenantPolicies {
			policies = append(policies, copyAdminPolicy(policy))
		}
	}
	SortPolicies(policies)
	store.cachedPolicies = policies
	store.cachedPolicyIDs = activeAdminPolicyIDs(policies)
}

// SetPolicyStatus enable/disables a single policy at runtime (status "active"|"disabled"), persisting the
// override so it survives a restart even though the policy re-seeds from config. Returns false if the policy is
// not present. A disabled policy is skipped at decision time (matchPolicy requires status active).
func (store *Store) SetPolicyStatus(tenantID, policyID, status string) bool {
	if store == nil {
		return false
	}
	tenantID = strings.TrimSpace(tenantID)
	policyID = strings.TrimSpace(policyID)
	status = strings.ToLower(strings.TrimSpace(status))
	if status != "active" && status != "disabled" {
		return false
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	tenantPolicies, ok := store.policies[tenantID]
	if !ok {
		return false
	}
	policy, ok := tenantPolicies[policyID]
	if !ok {
		return false
	}
	policy.Status = status
	tenantPolicies[policyID] = policy
	if store.policyStatusOverride[tenantID] == nil {
		store.policyStatusOverride[tenantID] = map[string]string{}
	}
	store.policyStatusOverride[tenantID][policyID] = status
	store.rebuildPolicyCacheLocked()
	store.persistLocked()
	return true
}

// applyPolicyStatusOverridesLocked re-applies persisted enable/disable overrides onto the (re-seeded) policies.
// Caller holds store.mu. Called after load so a disable survives a restart.
func (store *Store) applyPolicyStatusOverridesLocked() {
	for tenantID, overrides := range store.policyStatusOverride {
		tenantPolicies, ok := store.policies[tenantID]
		if !ok {
			continue
		}
		for policyID, status := range overrides {
			if policy, ok := tenantPolicies[policyID]; ok {
				policy.Status = status
				tenantPolicies[policyID] = policy
			}
		}
	}
}

func (store *Store) RuntimeEvaluator(base decision.Evaluator) decision.Evaluator {
	if store == nil {
		return base
	}
	store.mu.RLock()
	defer store.mu.RUnlock()

	// Assign the precomputed immutable snapshot instead of deep-copying + sorting every policy per flow
	//. The snapshot is rebuilt only on mutation; the evaluator treats Policies read-only and
	// orderedPolicies copies before applying its own ordering, so sharing the slice is safe.
	base.Policies = store.cachedPolicies
	base.PolicyBundle.PolicyIDs = store.cachedPolicyIDs

	store.compileTenantRestrictionsLocked(&base)

	// Apply SWG tenant-restriction rule status overrides (SaaS enable/disable hot-apply).
	// Only when overrides exist: shallow-copy the rules slice and replace the per-rule Status so the
	// shared base bundle is never mutated. Status is a value field; the rule Metadata map is not touched.
	if len(store.tenantRestrictionRuleStatus) > 0 && len(base.PolicyBundle.SWGTenantRestrictionRules) > 0 {
		rules := make([]model.SWGTenantRestrictionRule, len(base.PolicyBundle.SWGTenantRestrictionRules))
		copy(rules, base.PolicyBundle.SWGTenantRestrictionRules)
		for i := range rules {
			if status, ok := store.tenantRestrictionRuleStatus[rules[i].ID]; ok {
				rules[i].Status = status
			}
		}
		base.PolicyBundle.SWGTenantRestrictionRules = rules
	}

	tenantID := strings.TrimSpace(base.PolicyBundle.TenantID)

	// Union in the policies compiled from the authored egress rules (the Console rule editor), kept SEPARATE
	// from the operator/adopted policies so neither clobbers the other. They participate in normal
	// priority-ordered matching.
	//
	// ★★★ EVERY ORGANIZATION'S, NOT THIS NODE'S (2026-08-17, found by authoring a rule for a newly created
	// organization through the Console). The tenant was read from the BASE evaluator's bundle — the node's own —
	// so a rule authored for any other organization compiled into a set nothing ever merged. The rule was
	// stored, listed, and shown as "active · enforce", and no decision was ever taken by it: the preview for
	// the destination it denied came back with an empty trace.
	//
	// Merging every organization's compiled policies is safe because matching already gates on tenant equality
	// (decision/evaluator.go, "Tenant isolation (review finding #1)"): a compiled policy carries the tenant it
	// was compiled for, so it can only ever match that tenant's request.
	//
	// ★★ AND EACH ONE ONCE (2026-08-17, measured on the lab: the control plane listed 5 policies for an
	// organization and the Edge listed 7, with the same two ids twice). Both planes compile the same authored
	// rule: the control plane compiles it and distributes the result in the config bundle, where it lands in
	// this store's ordinary policy set; the Edge then compiles the rule itself into compiledPolicies. Unioning
	// them gave every authored rule a twin.
	//
	// Visible as noise — the customer's policy list and every decision trace showed each rule twice — and a
	// hazard underneath it: two policies sharing an ID can only stay identical while both compilers see the
	// same asset catalog. The moment they do not, this node evaluates two different versions of one rule and
	// which one wins is a sort tie-break. Keeping the copy already in the base set is the conservative half:
	// that is the one the config authority published.
	if len(store.compiledPolicies) > 0 {
		total := 0
		for _, compiled := range store.compiledPolicies {
			total += len(compiled)
		}
		if total > 0 {
			present := make(map[string]bool, len(base.Policies))
			for _, policy := range base.Policies {
				present[policy.ID] = true
			}
			merged := make([]model.Policy, 0, len(base.Policies)+total)
			merged = append(merged, base.Policies...)
			for _, owner := range sortedCompiledTenants(store.compiledPolicies) {
				for _, policy := range store.compiledPolicies[owner] {
					if present[policy.ID] {
						continue
					}
					present[policy.ID] = true
					merged = append(merged, policy)
				}
			}
			base.Policies = merged
		}
	}

	// Apply east-west per-hop authorization config (E1.5). Hot-applies admin changes to the live path.
	if store.eastWestEnabled[tenantID] {
		base.EastWestEnabled = true
	}
	// What this tenant has DECLARED to be inside its estate, on top of private address space (which is always
	// internal and cannot be declared away). It decides plane membership together with the protocol: without
	// it the service family alone decided, so every ssh was lateral movement by construction and ssh to a
	// public code host was held for an IdP ceremony. Empty is valid — a flat private estate needs no
	// declaration; see decision/locality.go.
	base.EastWestInternalNetworks = store.eastWestInternalNetworks[tenantID]
	// Partial Enforce (S4): enabled rules bite but unmatched flows are allowed (not default-denied).
	base.EastWestAllowUnmatched = store.eastWestAllowUnmatched[tenantID]
	// Union the legacy admin rules with the rules compiled from the authored-rule model. Enablement is NOT
	// implied by having rules — it stays under the existing posture toggle (observe → enforce), so authoring
	// a rule never silently turns on east-west default-deny.
	legacy := store.eastWestRules[tenantID]
	compiled := store.compiledEastWestRules[tenantID]
	if len(legacy) > 0 || len(compiled) > 0 {
		merged := make([]decision.EastWestRule, 0, len(legacy)+len(compiled))
		merged = append(merged, legacy...)
		merged = append(merged, compiled...)
		base.EastWestRules = merged
	}
	if grants := store.eastWestGrants[tenantID]; len(grants) > 0 {
		base.EastWestGrants = append([]decision.EastWestGrant(nil), grants...)
	}

	// Apply server-initiated access control for this evaluator's tenant.
	if store.serverInitiatedEnabled[tenantID] {
		base.ServerInitiatedEnabled = true
	}
	if exs := store.legacyExceptions[tenantID]; len(exs) > 0 {
		base.LegacyExceptions = decision.LegacyExceptionsFromModel(exs)
	}
	return base
}

// IssueEastWestGrant appends an ephemeral east-west grant for a tenant (E3). Applied live: the next
// matching authenticate-mode request is released to allow until the grant expires.
func (store *Store) IssueEastWestGrant(tenantID string, grant decision.EastWestGrant) {
	if store == nil {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.eastWestGrants == nil {
		store.eastWestGrants = map[string][]decision.EastWestGrant{}
	}
	tenantID = strings.TrimSpace(tenantID)
	store.eastWestGrants[tenantID] = append(store.eastWestGrants[tenantID], grant)
}

// revokeEastWestGrantsForScopeLocked deletes the east-west grants bound to a device/user scope (E5
// continuous revocation). Caller holds store.mu. Returns the number revoked.
func (store *Store) revokeEastWestGrantsForScopeLocked(tenantID, scopeType, scopeID string) int {
	if scopeID == "" {
		return 0
	}
	grants := store.eastWestGrants[tenantID]
	if len(grants) == 0 {
		return 0
	}
	kept := grants[:0]
	removed := 0
	for _, g := range grants {
		match := (scopeType == "device" && g.DeviceID == scopeID) ||
			(scopeType == "user" && g.SubjectUserID == scopeID)
		if match {
			removed++
			continue
		}
		kept = append(kept, g)
	}
	store.eastWestGrants[tenantID] = kept
	return removed
}

// revokeEastWestGrantsForTenantLocked deletes all east-west grants for a tenant. Caller holds store.mu.
func (store *Store) revokeEastWestGrantsForTenantLocked(tenantID string) int {
	n := len(store.eastWestGrants[tenantID])
	delete(store.eastWestGrants, tenantID)
	return n
}

// RevokeEastWestGrants revokes east-west grants for a tenant (scopeType ""/"tenant") or a device/user
// scope (E5 / admin). Returns the number revoked.
func (store *Store) RevokeEastWestGrants(tenantID, scopeType, scopeID string) int {
	if store == nil {
		return 0
	}
	tenantID = strings.TrimSpace(tenantID)
	scopeType = strings.TrimSpace(scopeType)
	scopeID = strings.TrimSpace(scopeID)
	store.mu.Lock()
	defer store.mu.Unlock()
	if scopeType == "" || scopeType == "tenant" {
		return store.revokeEastWestGrantsForTenantLocked(tenantID)
	}
	return store.revokeEastWestGrantsForScopeLocked(tenantID, scopeType, scopeID)
}

// SetEastWestMaxGrantTTL sets the per-tenant ceiling (seconds) on east-west grant lifetime (E6). 0 = no
// cap. The maximum is admin-configurable and intentionally not hard-capped.
func (store *Store) SetEastWestMaxGrantTTL(tenantID string, seconds int) {
	if store == nil {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.eastWestMaxGrantTTL == nil {
		store.eastWestMaxGrantTTL = map[string]int{}
	}
	if seconds < 0 {
		seconds = 0
	}
	store.eastWestMaxGrantTTL[strings.TrimSpace(tenantID)] = seconds
	store.generation++ // distributed via the config bundle (Phase 1): advance so Edges re-pull
	store.persistLocked()
}

// EastWestMaxGrantTTL returns the per-tenant grant TTL ceiling in seconds (0 = none).
func (store *Store) EastWestMaxGrantTTL(tenantID string) int {
	if store == nil {
		return 0
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	return store.eastWestMaxGrantTTL[strings.TrimSpace(tenantID)]
}

// TouchEastWestGrant bumps LastUsedAt on the grants matching a request so an actively-used grant does not
// idle-expire (E6). Called after an east-west grant releases a flow.
func (store *Store) TouchEastWestGrant(tenantID string, req model.DecisionRequest, now time.Time) {
	if store == nil {
		return
	}
	tenantID = strings.TrimSpace(tenantID)
	store.mu.Lock()
	defer store.mu.Unlock()
	grants := store.eastWestGrants[tenantID]
	for i := range grants {
		g := grants[i]
		if g.IdleTTLSeconds <= 0 {
			continue
		}
		if g.Protocol != "" && !strings.EqualFold(g.Protocol, strings.TrimSpace(req.ServiceFamily)) {
			continue
		}
		if g.SubjectUserID != "" && g.SubjectUserID != req.SubjectUserID && g.SubjectUserID != req.UserID {
			continue
		}
		if g.DeviceID != "" && g.DeviceID != req.DeviceID {
			continue
		}
		if g.Destination != "" && g.Destination != req.Destination && g.Destination != req.ApplicationID {
			continue
		}
		grants[i].LastUsedAt = now
	}
}

// EastWestGrantsFor returns a copy of the active (non-expired) east-west grants for a tenant.
func (store *Store) EastWestGrantsFor(tenantID string, now time.Time) []decision.EastWestGrant {
	if store == nil {
		return nil
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	out := []decision.EastWestGrant{}
	for _, g := range store.eastWestGrants[strings.TrimSpace(tenantID)] {
		if now.Before(g.ExpiresAt) {
			out = append(out, g)
		}
	}
	return out
}

// SetEastWestEnabled toggles east-west per-hop authorization for a tenant (E1.5). Applied live.
// SetEastWestInternalNetworks records what a tenant has DECLARED to be inside its estate — the CIDRs and DNS
// suffixes that make a destination lateral even when its address is globally routable.
//
// Deliberately NOT persisted and NOT generation-advancing, unlike the settings around it. This is DERIVED
// state: it is recomputed from the connectors' advertised reachable routes, which have their own durable
// store and their own route-governance approval. Persisting a second copy here would create a ledger that can
// disagree with the one that owns the answer, and the failure would be silent — an Edge deciding plane
// membership from a stale idea of the estate. It is refreshed on boot and whenever routes change.
func (store *Store) SetEastWestInternalNetworks(tenantID string, networks decision.InternalNetworks) {
	if store == nil {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.eastWestInternalNetworks == nil {
		store.eastWestInternalNetworks = map[string]decision.InternalNetworks{}
	}
	store.eastWestInternalNetworks[strings.TrimSpace(tenantID)] = networks
}

func (store *Store) SetEastWestEnabled(tenantID string, enabled bool) {
	if store == nil {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.eastWestEnabled == nil {
		store.eastWestEnabled = map[string]bool{}
	}
	store.eastWestEnabled[strings.TrimSpace(tenantID)] = enabled
	store.generation++ // distributed via the config bundle (Phase 1): advance so Edges re-pull
	store.persistLocked()
}

// EastWestIsEnabled reports whether east-west authorization is enabled for a tenant.
func (store *Store) EastWestIsEnabled(tenantID string) bool {
	if store == nil {
		return false
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	return store.eastWestEnabled[strings.TrimSpace(tenantID)]
}

// SetEastWestAllowUnmatched toggles Partial Enforce (S4) for a tenant: when true, enabled rules bite but a flow
// matching no rule is allowed (allow-all default) instead of default-denied. Applied live.
func (store *Store) SetEastWestAllowUnmatched(tenantID string, allow bool) {
	if store == nil {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.eastWestAllowUnmatched == nil {
		store.eastWestAllowUnmatched = map[string]bool{}
	}
	store.eastWestAllowUnmatched[strings.TrimSpace(tenantID)] = allow
	store.generation++ // distributed via the config bundle (Phase 1): advance so Edges re-pull
	store.persistLocked()
}

// EastWestAllowsUnmatched reports whether unmatched east-west flows are allowed (Partial Enforce) for a tenant.
func (store *Store) EastWestAllowsUnmatched(tenantID string) bool {
	if store == nil {
		return false
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	return store.eastWestAllowUnmatched[strings.TrimSpace(tenantID)]
}

// SetEastWestRules replaces the east-west rule set for a tenant (E1.5). Applied live.
func (store *Store) SetEastWestRules(tenantID string, rules []decision.EastWestRule) {
	if store == nil {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.eastWestRules == nil {
		store.eastWestRules = map[string][]decision.EastWestRule{}
	}
	store.eastWestRules[strings.TrimSpace(tenantID)] = append([]decision.EastWestRule(nil), rules...)
	store.generation++ // distributed via the config bundle (Phase 1): advance so Edges re-pull
	store.persistLocked()
}

// SetCompiledEastWestRules replaces the east-west rules compiled from the authored-rule model for a tenant.
// Kept separate from SetEastWestRules (the legacy admin set) so neither clobbers the other; RuntimeEvaluator
// unions them. Applied live.
func (store *Store) SetCompiledEastWestRules(tenantID string, rules []decision.EastWestRule) {
	if store == nil {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.compiledEastWestRules == nil {
		store.compiledEastWestRules = map[string][]decision.EastWestRule{}
	}
	// Deliberately kept as an explicit empty set rather than a deleted key when there are no rules: this map is
	// persisted and distributed, and an absent value reads as "keep what you have" downstream — which would
	// turn deleting the last east-west rule into a no-op. The egress compiled set is not distributed and does
	// drop its key; see SetCompiledPolicies.
	store.compiledEastWestRules[strings.TrimSpace(tenantID)] = append([]decision.EastWestRule(nil), rules...)
	store.generation++ // distributed via the config bundle (Phase 1): advance so Edges re-pull
	store.persistLocked()
}

// SetCompiledPolicies replaces the egress policies compiled from the authored-rule model for a tenant. Kept
// separate from the operator/adopted policies (Upsert/ApplyBundle) so neither clobbers the other;
// RuntimeEvaluator unions them. Applied live.
//
// The compiled set is DERIVED state (re-compiled from the durable authored-rule store on every boot — see
// rules_admin.go's startup compile), so it is deliberately NOT persisted here: it is absent from the runtime
// snapshot, so the old persistLocked() call wrote only the unchanged toggles while giving the false
// impression the compiled sets were durable (review #20). The generation bump remains — it is the "policy
// config changed, rebuild" signal.
func (store *Store) SetCompiledPolicies(tenantID string, policies []model.Policy) {
	if store == nil {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.compiledPolicies == nil {
		store.compiledPolicies = map[string][]model.Policy{}
	}
	key := strings.TrimSpace(tenantID)
	if len(policies) == 0 {
		// Nothing left to compile for this organization — drop the entry rather than keeping an empty one, so
		// the recompile loop stops walking it and CompiledPolicyTenants names only organizations with
		// something to clear. Setting an empty slice under the key would leave every organization that ever
		// had a rule in that list forever.
		delete(store.compiledPolicies, key)
		store.generation++
		return
	}
	store.compiledPolicies[key] = append([]model.Policy(nil), policies...)
	store.generation++
}

// CompiledRuleTenants names every organization this store currently holds anything COMPILED for — egress
// policies or east-west rules.
//
// ★★ WHY IT HAS TO BE ASKABLE (2026-08-17, measured on the lab). The recompile loop walked the organizations
// that HAVE authored rules. Delete an organization's last rule and it leaves that list — so its compiled set
// was never rebuilt to empty and kept enforcing. Measured: an administrator deleted a deny rule, the rules
// screen showed none, the control plane had dropped the policy, and the Edge went on answering DENY for that
// destination across two further config pulls, indefinitely.
//
// A recompile has to cover every organization that has something to clear, not only the ones that still have
// something to build.
func (store *Store) CompiledRuleTenants() []string {
	if store == nil {
		return nil
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	seen := map[string]bool{}
	out := []string{}
	for _, tenant := range sortedCompiledTenants(store.compiledPolicies) {
		if !seen[tenant] {
			seen[tenant] = true
			out = append(out, tenant)
		}
	}
	// ★ THE EAST-WEST HALF MATTERS FOR THE SAME REASON AND IS CLEARED DIFFERENTLY. An organization whose only
	// authored rules are east-west leaves the rule store's tenant list when its last one is deleted, exactly
	// like the egress case — so it has to be walked from here too. Its compiled set is kept as an EXPLICIT
	// empty rather than a deleted key (see SetCompiledEastWestRules): that set is persisted and distributed,
	// where an absent value reads as "keep what you have" and would turn a deletion into a no-op.
	for _, tenant := range sortedCompiledEastWestTenants(store.compiledEastWestRules) {
		if !seen[tenant] {
			seen[tenant] = true
			out = append(out, tenant)
		}
	}
	return out
}

func sortedCompiledEastWestTenants(m map[string][]decision.EastWestRule) []string {
	out := make([]string, 0, len(m))
	for tenant := range m {
		out = append(out, tenant)
	}
	sort.Strings(out)
	return out
}

// EastWestRulesFor returns a copy of the east-west rule set for a tenant.
func (store *Store) EastWestRulesFor(tenantID string) []decision.EastWestRule {
	if store == nil {
		return nil
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	return append([]decision.EastWestRule(nil), store.eastWestRules[strings.TrimSpace(tenantID)]...)
}

// EffectiveEastWestRules returns the UNION of the legacy admin rules and the rules compiled from the authored-rule
// model — the same set the evaluator matches against. Use this (not EastWestRulesFor, which is legacy-only) when
// you need the rules the decision path actually enforces, e.g. computing observation coverage.
func (store *Store) EffectiveEastWestRules(tenantID string) []decision.EastWestRule {
	if store == nil {
		return nil
	}
	tenantID = strings.TrimSpace(tenantID)
	store.mu.RLock()
	defer store.mu.RUnlock()
	legacy := store.eastWestRules[tenantID]
	compiled := store.compiledEastWestRules[tenantID]
	out := make([]decision.EastWestRule, 0, len(legacy)+len(compiled))
	out = append(out, legacy...)
	out = append(out, compiled...)
	return out
}

// SetTenantRestrictionRuleStatus records a runtime status override ("active"/"inactive") for a SWG
// tenant-restriction rule id (Admin API SaaS enable/disable). Applied live by RuntimeEvaluator.
func (store *Store) SetTenantRestrictionRuleStatus(ruleID, status string) {
	if store == nil {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.tenantRestrictionRuleStatus == nil {
		store.tenantRestrictionRuleStatus = map[string]string{}
	}
	store.tenantRestrictionRuleStatus[strings.TrimSpace(ruleID)] = strings.TrimSpace(status)
	store.generation++ // distributed via the config bundle (Phase 1): advance so Edges re-pull
	store.persistLocked()
}

// TenantRestrictionRuleStatusOverrides returns a copy of the current rule status overrides.
func (store *Store) TenantRestrictionRuleStatusOverrides() map[string]string {
	out := map[string]string{}
	if store == nil {
		return out
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	for k, v := range store.tenantRestrictionRuleStatus {
		out[k] = v
	}
	return out
}

func (store *Store) putLocked(policy model.Policy) {
	if store.policies[policy.TenantID] == nil {
		store.policies[policy.TenantID] = map[string]model.Policy{}
	}
	store.policies[policy.TenantID][policy.ID] = copyAdminPolicy(policy)
}

func normalizeAdminPolicy(policy model.Policy, tenantID string, now time.Time) (model.Policy, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return model.Policy{}, fmt.Errorf("tenant_id is required")
	}

	policy.ID = strings.TrimSpace(policy.ID)
	if policy.ID == "" {
		return model.Policy{}, fmt.Errorf("policy id is required")
	}
	if strings.Contains(policy.ID, "/") {
		return model.Policy{}, fmt.Errorf("policy id cannot contain slash")
	}

	policy.TenantID = strings.TrimSpace(policy.TenantID)
	if policy.TenantID == "" {
		policy.TenantID = tenantID
	}
	if policy.TenantID != tenantID {
		return model.Policy{}, fmt.Errorf("policy tenant_id %s does not match authenticated tenant_id %s", policy.TenantID, tenantID)
	}

	policy.Name = strings.TrimSpace(policy.Name)
	if policy.Name == "" {
		policy.Name = policy.ID
	}

	status := strings.TrimSpace(policy.Status)
	if status == "" {
		status = "draft"
	}
	if !validAdminPolicyStatus(status) {
		return model.Policy{}, fmt.Errorf("policy status %s is invalid", status)
	}
	policy.Status = status

	policy.Action.Decision = strings.TrimSpace(policy.Action.Decision)
	if policy.Action.Decision == "" {
		return model.Policy{}, fmt.Errorf("policy action.decision is required")
	}
	if !validAdminPolicyDecision(policy.Action.Decision) {
		return model.Policy{}, fmt.Errorf("policy action.decision %s is invalid", policy.Action.Decision)
	}

	if len(policy.Conditions) == 0 {
		return model.Policy{}, fmt.Errorf("policy conditions must contain at least one condition")
	}
	policy.Conditions = copyStringAnyMap(policy.Conditions)
	policy.AllowedTaskPurposes = normalizedStringList(policy.AllowedTaskPurposes)
	policy.AllowedToolIDs = normalizedStringList(policy.AllowedToolIDs)
	policy.AllowedToolActions = normalizedStringList(policy.AllowedToolActions)
	policy.AllowedContextScopeIDs = normalizedStringList(policy.AllowedContextScopeIDs)
	policy.AllowedMemoryScopeIDs = normalizedStringList(policy.AllowedMemoryScopeIDs)
	policy.AllowedDataClassifications = normalizedStringList(policy.AllowedDataClassifications)
	policy.Metadata = copyStringAnyMap(policy.Metadata)
	if policy.Metadata == nil {
		policy.Metadata = map[string]any{}
	}

	if now.IsZero() {
		now = time.Now().UTC()
	}
	updatedAt := now.UTC().Format(time.RFC3339)
	policy.UpdatedAt = &updatedAt
	return policy, nil
}

func validAdminPolicyStatus(status string) bool {
	switch status {
	case "active", "draft", "disabled":
		return true
	default:
		return false
	}
}

func validAdminPolicyDecision(decision string) bool {
	switch decision {
	case "allow", "deny", "require_reauthentication", "require_workload_attestation":
		return true
	default:
		return false
	}
}

func copyAdminPolicy(policy model.Policy) model.Policy {
	policy.Conditions = copyStringAnyMap(policy.Conditions)
	policy.AllowedTaskPurposes = append([]string(nil), policy.AllowedTaskPurposes...)
	policy.AllowedToolIDs = append([]string(nil), policy.AllowedToolIDs...)
	policy.AllowedToolActions = append([]string(nil), policy.AllowedToolActions...)
	policy.AllowedContextScopeIDs = append([]string(nil), policy.AllowedContextScopeIDs...)
	policy.AllowedMemoryScopeIDs = append([]string(nil), policy.AllowedMemoryScopeIDs...)
	policy.AllowedDataClassifications = append([]string(nil), policy.AllowedDataClassifications...)
	policy.Metadata = copyStringAnyMap(policy.Metadata)
	return policy
}

func copyStringAnyMap(values map[string]any) map[string]any {
	if values == nil {
		return nil
	}
	copied := make(map[string]any, len(values))
	for key, value := range values {
		copied[key] = value
	}
	return copied
}

func SortPolicies(policies []model.Policy) {
	sort.SliceStable(policies, func(i, j int) bool {
		if policies[i].Priority != policies[j].Priority {
			return policies[i].Priority < policies[j].Priority
		}
		return policies[i].ID < policies[j].ID
	})
}

func activeAdminPolicyIDs(policies []model.Policy) []string {
	ids := []string{}
	for _, policy := range policies {
		if policy.Status == "active" {
			ids = append(ids, policy.ID)
		}
	}
	return ids
}

// SetServerInitiatedEnabled toggles server-initiated enforcement for a tenant. Applied live by
// RuntimeEvaluator.
func (store *Store) SetServerInitiatedEnabled(tenantID string, enabled bool) {
	if store == nil {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.serverInitiatedEnabled == nil {
		store.serverInitiatedEnabled = map[string]bool{}
	}
	store.serverInitiatedEnabled[strings.TrimSpace(tenantID)] = enabled
	store.generation++
	store.persistLocked()
}

// ServerInitiatedEnabledFor reports whether server-initiated (server->client) default-deny enforcement is
// currently on for the tenant (default false = allow by default). Lets the Console show the live state.
func (store *Store) ServerInitiatedEnabledFor(tenantID string) bool {
	if store == nil {
		return false
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	return store.serverInitiatedEnabled[strings.TrimSpace(tenantID)]
}

// UpsertLegacyException stores/updates a Legacy Exception for a tenant (validated by the caller).
func (store *Store) UpsertLegacyException(tenantID string, ex model.LegacyException) {
	if store == nil {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.legacyExceptions == nil {
		store.legacyExceptions = map[string][]model.LegacyException{}
	}
	tenantID = strings.TrimSpace(tenantID)
	list := store.legacyExceptions[tenantID]
	replaced := false
	for i := range list {
		if list[i].ID == ex.ID {
			list[i] = ex
			replaced = true
			break
		}
	}
	if !replaced {
		list = append(list, ex)
	}
	store.legacyExceptions[tenantID] = list
	store.generation++
	store.persistLocked()
}

// RemoveLegacyException deletes a tenant's Legacy Exception by id, persisting the change so it does not
// re-appear on restart. Returns false if no exception with that id exists for the tenant.
func (store *Store) RemoveLegacyException(tenantID, id string) bool {
	if store == nil {
		return false
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	tenantID = strings.TrimSpace(tenantID)
	id = strings.TrimSpace(id)
	list := store.legacyExceptions[tenantID]
	for i := range list {
		if list[i].ID == id {
			store.legacyExceptions[tenantID] = append(list[:i:i], list[i+1:]...)
			store.generation++
			store.persistLocked()
			return true
		}
	}
	return false
}

// LegacyExceptionsFor returns a copy of a tenant's Legacy Exceptions.
func (store *Store) LegacyExceptionsFor(tenantID string) []model.LegacyException {
	if store == nil {
		return nil
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	out := append([]model.LegacyException(nil), store.legacyExceptions[strings.TrimSpace(tenantID)]...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// TenantConfigBundle is the distributed, CP-authoritative slice of the admin policy store's per-tenant
// config toggles. Applied atomically with the policies under one lock (ApplyBundle).
type TenantConfigBundle struct {
	SaaSTenantRestrictions      map[string]tenantrestriction.Setting `json:"saas_tenant_restrictions"`
	EastWestEnabled             bool                                 `json:"east_west_enabled"`
	EastWestAllowUnmatched      bool                                 `json:"east_west_allow_unmatched"`
	EastWestRules               []decision.EastWestRule              `json:"east_west_rules,omitempty"`
	EastWestMaxGrantTTL         int                                  `json:"east_west_max_grant_ttl_seconds"`
	ServerInitiatedEnabled      bool                                 `json:"server_initiated_enabled"`
	LegacyExceptions            []model.LegacyException              `json:"legacy_exceptions,omitempty"`
	TenantRestrictionRuleStatus map[string]string                    `json:"tenant_restriction_rule_status,omitempty"`
}

// normalizedStringList trims, de-dups, drops empties (order-preserving) — package-local copy of the shared
// admin helper so the package stays self-contained.
func normalizedStringList(values []string) []string {
	result := []string{}
	seen := map[string]bool{}
	for _, value := range values {
		normalized := strings.TrimSpace(value)
		if normalized == "" || seen[normalized] {
			continue
		}
		seen[normalized] = true
		result = append(result, normalized)
	}
	return result
}

// Tenants returns every tenant this store holds policies or tenant config for, ordered.
//
// ★ WHY IT EXISTS (2026-08-15). The config bundle carried ONE tenant's policies — the pulling Edge's own —
// so a second organization's policies reached no Edge at all. Measured on the lab: a policy created for a
// second tenant sat on the control plane while both Edges reported zero for it, which is "the tenant was
// created and nothing happens", the failure mode the whole tenant-provisioning review exists to end. The
// control plane cannot publish every tenant's policies without being able to name them.
func (store *Store) Tenants() []string {
	if store == nil {
		return nil
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	seen := map[string]bool{}
	for tenantID := range store.tenantRestrictions {
		seen[tenantID] = true
	}
	for tenantID := range store.policies {
		if t := strings.TrimSpace(tenantID); t != "" {
			seen[t] = true
		}
	}
	for tenantID := range store.eastWestEnabled {
		if t := strings.TrimSpace(tenantID); t != "" {
			seen[t] = true
		}
	}
	out := make([]string, 0, len(seen))
	for tenantID := range seen {
		out = append(out, tenantID)
	}
	sort.Strings(out)
	return out
}

// sortedCompiledTenants keeps the merge order deterministic, so two evaluations of the same state produce the
// same precedence and a trace does not reshuffle between reads.
func sortedCompiledTenants(byTenant map[string][]model.Policy) []string {
	out := make([]string, 0, len(byTenant))
	for tenant := range byTenant {
		out = append(out, tenant)
	}
	sort.Strings(out)
	return out
}
