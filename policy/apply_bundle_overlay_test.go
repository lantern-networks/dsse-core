package policy

import (
	"context"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// Review #20: a config pull (ApplyBundle / ReplaceTenant) rebuilds the tenant's policy map from the incoming
// bundle. It must RE-APPLY the runtime overlays the bundle does not carry — a runtime-disabled policy must
// stay disabled (not resurrect as active), and an admin-authored policy must survive (not be dropped).
func TestApplyBundlePreservesStatusOverrideAndAdminAuthored(t *testing.T) {
	now := time.Date(2026, 7, 23, 0, 0, 0, 0, time.UTC)
	seed := []model.Policy{{ID: "pol_builtin_1", TenantID: "t1", Status: "active", Priority: 100,
		Conditions: map[string]any{"sni": "x.example.com"}, Action: model.PolicyAction{Decision: "allow"}}}
	store := NewStore(seed)

	// Runtime-disable the seeded policy...
	if !store.SetPolicyStatus("t1", "pol_builtin_1", "disabled") {
		t.Fatalf("SetPolicyStatus should succeed")
	}
	// ...and create an admin-authored policy.
	if _, err := store.Upsert(context.Background(), model.Policy{
		ID: "pol_admin_1", TenantID: "t1", Status: "active", Priority: 50,
		Conditions: map[string]any{"sni": "admin.example.com"}, Action: model.PolicyAction{Decision: "deny"},
	}, "t1", now); err != nil {
		t.Fatalf("Upsert admin policy: %v", err)
	}

	// A config pull ships ONLY the committed bundle (the seed, with pol_builtin_1 marked active again on the
	// CP side and no knowledge of the admin-authored policy).
	store.ApplyBundle("t1", []model.Policy{
		{ID: "pol_builtin_1", TenantID: "t1", Status: "active", Priority: 100,
			Conditions: map[string]any{"sni": "x.example.com"}, Action: model.PolicyAction{Decision: "allow"}},
	}, TenantConfigBundle{}, now)

	// The runtime disable must have been re-applied (not resurrected as active).
	if p, ok, _ := store.Get(context.Background(), "t1", "pol_builtin_1"); !ok || p.Status != "disabled" {
		t.Fatalf("config pull resurrected a runtime-disabled policy: %+v (ok=%v)", p, ok)
	}
	// The admin-authored policy must still be present.
	if p, ok, _ := store.Get(context.Background(), "t1", "pol_admin_1"); !ok || p.Action.Decision != "deny" {
		t.Fatalf("config pull dropped the admin-authored policy: %+v (ok=%v)", p, ok)
	}
}

// ReplaceTenant shares replacePoliciesLocked with ApplyBundle, so it gets the same overlay re-application.
func TestReplaceTenantPreservesOverlays(t *testing.T) {
	now := time.Date(2026, 7, 23, 0, 0, 0, 0, time.UTC)
	seed := []model.Policy{{ID: "pol_builtin_1", TenantID: "t1", Status: "active", Priority: 100,
		Conditions: map[string]any{"sni": "x.example.com"}, Action: model.PolicyAction{Decision: "allow"}}}
	store := NewStore(seed)
	store.SetPolicyStatus("t1", "pol_builtin_1", "disabled")
	if _, err := store.Upsert(context.Background(), model.Policy{
		ID: "pol_admin_1", TenantID: "t1", Status: "active", Priority: 50,
		Conditions: map[string]any{"sni": "admin.example.com"}, Action: model.PolicyAction{Decision: "deny"},
	}, "t1", now); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	store.ReplaceTenant("t1", []model.Policy{
		{ID: "pol_builtin_1", TenantID: "t1", Status: "active", Priority: 100,
			Conditions: map[string]any{"sni": "x.example.com"}, Action: model.PolicyAction{Decision: "allow"}},
	}, now)

	if p, ok, _ := store.Get(context.Background(), "t1", "pol_builtin_1"); !ok || p.Status != "disabled" {
		t.Fatalf("ReplaceTenant resurrected a disabled policy: %+v", p)
	}
	if _, ok, _ := store.Get(context.Background(), "t1", "pol_admin_1"); !ok {
		t.Fatalf("ReplaceTenant dropped the admin-authored policy")
	}
}
