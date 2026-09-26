package policy

import (
	"errors"
	"fmt"
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
	previous := store.runtimeStatePersister
	previousKnown := store.runtimeAuthorityKnown
	store.runtimeStatePersister = p
	store.runtimeAuthorityKnown = false
	if p == nil {
		return nil
	}
	if err := store.loadRuntimeStateLocked(); err != nil {
		store.runtimeStatePersister = previous
		store.runtimeAuthorityKnown = previousKnown
		return err
	}
	return nil
}

// loadRuntimeStateLocked restores the authoritative overlay after a successful read.
func (store *Store) loadRuntimeStateLocked() error {
	raw, err := store.runtimeStatePersister.Load()
	if err != nil {
		return fmt.Errorf("admin runtime state cannot be read: %w", err)
	}
	if raw == nil {
		return nil
	}
	f, _, err := decodeRuntimeState(raw)
	if err != nil {
		return fmt.Errorf("admin runtime state is unparseable: %w", err)
	}
	store.adoptRuntimeLocked(f)
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

var ErrPolicyPersistence = errors.New("policy could not be saved")
