package main

import (
	"path/filepath"
	"testing"

	"github.com/lantern-networks/dsse-core/policy"

	"github.com/lantern-networks/dsse-core/decision"
)

// TestAdminPolicyRuntimeStatePersistsAcrossRestart verifies that Admin-API runtime toggles written
// to the durable store are restored by a fresh store on boot — the cross-restart fix for the
// /steer-403 class of incident where runtime state was lost on restart.
func TestAdminPolicyRuntimeStatePersistsAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin_runtime_state.json")

	// First "process": apply a spread of runtime toggles.
	s1 := policy.NewStore(nil)
	s1.SetRuntimeStatePath(path)
	s1.SetTenantRestrictionRuleStatus("swg_tr_google_workspace_lab", "inactive")
	s1.SetEastWestEnabled("tenant_a", true)
	s1.SetEastWestRules("tenant_a", []decision.EastWestRule{{ID: "ew1", Mode: "deny"}})
	s1.SetEastWestMaxGrantTTL("tenant_a", 3600)

	// Second "process": fresh store seeded from bundle (empty here) then overlay the durable store.
	s2 := policy.NewStore(nil)
	s2.SetRuntimeStatePath(path)

	if got := s2.TenantRestrictionRuleStatusOverrides()["swg_tr_google_workspace_lab"]; got != "inactive" {
		t.Fatalf("tenant restriction status not restored: %q", got)
	}
	if !s2.EastWestIsEnabled("tenant_a") {
		t.Fatalf("east-west enabled not restored")
	}
	if rules := s2.EastWestRulesFor("tenant_a"); len(rules) != 1 || rules[0].ID != "ew1" {
		t.Fatalf("east-west rules not restored: %v", rules)
	}
	if ttl := s2.EastWestMaxGrantTTL("tenant_a"); ttl != 3600 {
		t.Fatalf("east-west max grant ttl not restored: %d", ttl)
	}
}

// TestAdminPolicyRuntimeStateNoPathIsInMemoryOnly confirms that without a state path the store keeps
// the previous in-memory-only behavior (nothing persisted, no errors).
func TestAdminPolicyRuntimeStateNoPathIsInMemoryOnly(t *testing.T) {
	s := policy.NewStore(nil)
	s.SetTenantRestrictionRuleStatus("swg_tr_x", "inactive") // must not panic / must be a no-op for persistence
	if got := s.TenantRestrictionRuleStatusOverrides()["swg_tr_x"]; got != "inactive" {
		t.Fatalf("in-memory toggle should still apply: %q", got)
	}
}

// TestAdminPolicyRuntimeStateMissingFileStartsFresh confirms a missing store file is tolerated.
func TestAdminPolicyRuntimeStateMissingFileStartsFresh(t *testing.T) {
	s := policy.NewStore(nil)
	s.SetRuntimeStatePath(filepath.Join(t.TempDir(), "does_not_exist.json"))
	if len(s.TenantRestrictionRuleStatusOverrides()) != 0 {
		t.Fatalf("expected empty overrides on fresh start")
	}
}
