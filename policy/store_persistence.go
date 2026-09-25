package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tenantrestriction"
)

// adminPolicyRuntimeStateFile is the durable overlay of Admin-API runtime TOGGLES that the
// Store restores on boot. It deliberately excludes:
//   - the committed policy bundle / admin policies (the bundle is the policy source-of-truth; a
//     restart re-seeds from it),
//   - ephemeral state (east-west grants, lateral-movement attempt windows) which is short-lived by
//     design and must not be resurrected by a restart.
//
// Contains policy configuration and non-secret SaaS allowlists; never credentials.
// Legacy startup-file restriction values remain in the operator value store.
type adminPolicyRuntimeStateFile struct {
	SaaSTenantRestrictions      map[string]map[string]tenantrestriction.Setting `json:"saas_tenant_restrictions,omitempty"`
	SchemaVersion               string                                          `json:"schema_version"`
	TenantRestrictionRuleStatus map[string]string                               `json:"tenant_restriction_rule_status,omitempty"`
	PolicyStatusOverride        map[string]map[string]string                    `json:"policy_status_override,omitempty"`
	EastWestEnabled             map[string]bool                                 `json:"east_west_enabled,omitempty"`
	EastWestAllowUnmatched      map[string]bool                                 `json:"east_west_allow_unmatched,omitempty"`
	EastWestRules               map[string][]decision.EastWestRule              `json:"east_west_rules,omitempty"`
	EastWestMaxGrantTTL         map[string]int                                  `json:"east_west_max_grant_ttl,omitempty"`
	// server-initiated config: the enable toggle + the Legacy Exceptions (governed allow-list).
	// These are admin-authored CONFIG (like east-west rules), not ephemeral — they MUST survive a restart
	// (they were previously in-memory only, lost on restart, needing a manual seed script).
	ServerInitiatedEnabled map[string]bool                    `json:"server_initiated_enabled,omitempty"`
	LegacyExceptions       map[string][]model.LegacyException `json:"legacy_exceptions,omitempty"`
	// AdminAuthoredPolicies persists policies CREATED via the Admin API (POST /admin/policies + adopt), keyed
	// tenant -> id. Unlike the committed bundle (re-seeded on boot), these have no other source, so they MUST be
	// persisted or they vanish on restart. Restored as an overlay on top of the bundle seed (see load).
	AdminAuthoredPolicies map[string]map[string]model.Policy `json:"admin_authored_policies,omitempty"`
}

const adminPolicyRuntimeStateSchemaVersion = "admin_policy_runtime_state.v1"

// SetRuntimeStatePath enables cross-restart persistence of Admin-API runtime toggles to path and immediately
// loads any existing state (overlaying the bundle seed). Call once at boot after construction.
//
// It returns an error when a store that EXISTS cannot be used — see SetRuntimeStatePersister for why that is
// fatal rather than a fresh start. A store that is merely absent (first boot) is not an error.
func (store *Store) SetRuntimeStatePath(path string) error {
	if store == nil {
		return nil
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	return store.SetRuntimeStatePersister(blobstore.FilePersister{Path: path})
}

// SetRuntimeStatePersister enables cross-restart persistence of Admin-API runtime toggles via any Persister (file
// or shared Postgres) and immediately loads existing state (overlaying the bundle seed) — and, on a shared
// persister, carries the toggles across a CP failover.
// It FAILS CLOSED on a store that exists but cannot be read or parsed. That is deliberate and it is the point
// of this function's error return.
//
// These toggles are security controls — east-west authorization, tenant-restriction rule status,
// server-initiated access. Their zero value is OFF. So a store that has been lost, truncated or corrupted used
// to mean: start with everything disabled, then persist that as if it were a decision, destroying the evidence
// of what the posture had been. On 2026-08-05 an east-west posture of mode=full was found inert with no record
// anywhere of it changing — this is the mechanism that can do that without leaving a trace, because "I could
// not read the state" and "the state says off" produced identical behaviour and identical logs.
//
// An ABSENT store is not this case and stays a normal first boot: blobstore.FilePersister.Load returns
// (nil, nil) for a file that does not exist, and an error only when one exists and cannot be read.
func (store *Store) SetRuntimeStatePersister(p blobstore.Persister) error {
	if store == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.runtimeStatePersister = p
	store.runtimeAuthorityKnown = false
	if p == nil {
		return nil
	}
	return store.loadRuntimeStateLocked()
}

// loadRuntimeStateLocked reads the durable store and overlays it onto the in-memory maps. Caller holds
// store.mu. A MISSING store is a fresh start; a store that exists but cannot be read or parsed is an error,
// because continuing would silently disable every control it holds. See SetRuntimeStatePersister.
func (store *Store) loadRuntimeStateLocked() error {
	if store.runtimeStatePersister == nil {
		return nil
	}
	data, err := store.runtimeStatePersister.Load()
	if err != nil {
		return fmt.Errorf("admin runtime state exists but cannot be read (%w) — refusing to continue with security toggles at their OFF defaults, which would overwrite the stored posture with silence", err)
	}
	if len(data) == 0 {
		return nil
	}
	var f adminPolicyRuntimeStateFile
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("admin runtime state is unparseable (%w) — refusing to continue with security toggles at their OFF defaults; restore or delete the store deliberately", err)
	}
	for _, settings := range f.SaaSTenantRestrictions {
		if err := ValidateTenantRestrictions(settings); err != nil {
			return fmt.Errorf("invalid stored SaaS restriction: %w", err)
		}
	}
	if f.SaaSTenantRestrictions != nil {
		store.tenantRestrictions = f.SaaSTenantRestrictions
	}
	// Restore admin-authored policies FIRST (before status-override application below), overlaying them on top of
	// the committed-bundle seed so a policy created via POST /admin/policies survives the restart. Doing it here
	// (not at the end) lets a persisted disable in PolicyStatusOverride apply to them too.
	if f.AdminAuthoredPolicies != nil {
		store.adminAuthoredPolicies = f.AdminAuthoredPolicies
		n := 0
		for _, byID := range f.AdminAuthoredPolicies {
			for _, p := range byID {
				store.putLocked(p)
				n++
			}
		}
		store.rebuildPolicyCacheLocked()
		log.Printf("admin_policy_runtime_state load: restored %d admin-authored policy(ies) as a bundle overlay", n)
	}
	if f.TenantRestrictionRuleStatus != nil {
		store.tenantRestrictionRuleStatus = f.TenantRestrictionRuleStatus
	}
	if f.PolicyStatusOverride != nil {
		store.policyStatusOverride = f.PolicyStatusOverride
		store.applyPolicyStatusOverridesLocked()
		store.rebuildPolicyCacheLocked()
	}
	if f.EastWestEnabled != nil {
		store.eastWestEnabled = f.EastWestEnabled
	}
	if f.EastWestAllowUnmatched != nil {
		store.eastWestAllowUnmatched = f.EastWestAllowUnmatched
	}
	if f.EastWestRules != nil {
		store.eastWestRules = f.EastWestRules
	}
	if f.EastWestMaxGrantTTL != nil {
		store.eastWestMaxGrantTTL = f.EastWestMaxGrantTTL
	}
	if f.ServerInitiatedEnabled != nil {
		store.serverInitiatedEnabled = f.ServerInitiatedEnabled
	}
	if f.LegacyExceptions != nil {
		store.legacyExceptions = f.LegacyExceptions
	}
	// Log the restored VALUES, not counts. The previous line printed the same text whether east-west came back
	// as `full` or as `false`, so a security control that had silently reverted was indistinguishable from one
	// that was correctly restored — which is exactly how an enforced east-west posture sat disabled for three
	// weeks with nothing in any log to notice. A restore line has to say WHAT was restored to be evidence.
	log.Printf("admin_policy_runtime_state load: restored runtime toggles (tenant_restriction_overrides=%d east_west_tenants=%d legacy_exception_tenants=%d)",
		len(store.tenantRestrictionRuleStatus), len(store.eastWestEnabled), len(store.legacyExceptions))
	for tenant, enabled := range store.eastWestEnabled {
		log.Printf("admin_policy_runtime_state load: east-west tenant=%s mode=%s rules=%d max_grant_ttl=%d",
			tenant, eastWestModeLabel(enabled, store.eastWestAllowUnmatched[tenant]), len(store.eastWestRules[tenant]), store.eastWestMaxGrantTTL[tenant])
	}
	for rule, status := range store.tenantRestrictionRuleStatus {
		log.Printf("admin_policy_runtime_state load: tenant-restriction rule=%s status=%s", rule, status)
	}
	for tenant, enabled := range store.serverInitiatedEnabled {
		log.Printf("admin_policy_runtime_state load: server-initiated tenant=%s enabled=%t", tenant, enabled)
	}
	store.runtimeAuthorityKnown = true
	return nil
}

// persistLocked atomically writes the current runtime toggles to the durable store. Caller holds
// store.mu. Best-effort: write errors are logged, never fail the admin operation. No-op when
// persistence is disabled (statePath == "").
func (store *Store) persistLocked() {
	if err := store.persistLockedChecked(); err != nil {
		log.Printf("admin_policy_runtime_state persist: %v", err)
	}
}

func (store *Store) persistLockedChecked() error {
	if store == nil || store.runtimeStatePersister == nil {
		return nil
	}
	f := adminPolicyRuntimeStateFile{
		SchemaVersion:               adminPolicyRuntimeStateSchemaVersion,
		SaaSTenantRestrictions:      store.tenantRestrictions,
		TenantRestrictionRuleStatus: store.tenantRestrictionRuleStatus,
		PolicyStatusOverride:        store.policyStatusOverride,
		EastWestEnabled:             store.eastWestEnabled,
		EastWestAllowUnmatched:      store.eastWestAllowUnmatched,
		EastWestRules:               store.eastWestRules,
		EastWestMaxGrantTTL:         store.eastWestMaxGrantTTL,
		ServerInitiatedEnabled:      store.serverInitiatedEnabled,
		LegacyExceptions:            store.legacyExceptions,
		AdminAuthoredPolicies:       store.adminAuthoredPolicies,
	}
	data, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("marshal failed: %w", err)
	}
	if err := store.runtimeStatePersister.Save(data); err != nil {
		// Saved-but-not-atomically is not a failure. Reporting it as one would tell an operator their change was
		// lost when it was written; saying nothing would hide that an interrupted write could truncate it.
		if errors.Is(err, blobstore.ErrSavedWithoutAtomicity) {
			log.Printf("admin_policy_runtime_state persist: saved, but NOT atomically — %v", err)
		} else {
			return fmt.Errorf("save failed: %w", err)
		}
	}
	store.runtimeAuthorityKnown = true
	return nil
}

// eastWestModeLabel renders the enabled/allow-unmatched pair as the posture name the admin API and the docs
// use, so a log line, an API response and an operator's mental model all say the same word.
func eastWestModeLabel(enabled, allowUnmatched bool) string {
	if !enabled {
		return "observe (INERT — east-west authorization is not enforced)"
	}
	if allowUnmatched {
		return "partial"
	}
	return "full"
}
