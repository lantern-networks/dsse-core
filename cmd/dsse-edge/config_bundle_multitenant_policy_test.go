package main

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
)

// ★ THE MEASURED BLOCKER (2026-08-15). The config bundle carried ONE tenant's policies — whichever tenant the
// pulling Edge's own token named — so a second organization's policies reached no Edge at all. Measured on the
// lab while standing up a second tenant: the policy existed on the control plane and both Edges reported zero
// for it. The registry row arrived, the organization showed up in every list, and nothing it said was
// enforced anywhere. "Created it, and nothing happens" is the failure this review exists to end, and this was
// the largest instance of it.
func TestASecondTenantsPoliciesReachTheEdge(t *testing.T) {
	store := policy.NewStore(nil)
	now := time.Now()
	source := configBundleSource{tenantID: "tenant_edge"}
	targets := configApplyTargets{policyStore: store}

	payload := configBundlePayload{
		Policies: []model.Policy{policyForTest("pol_edge", "tenant_edge")},
		TenantPolicies: []tenantPolicySection{
			{TenantID: "tenant_edge", Policies: []model.Policy{policyForTest("pol_edge", "tenant_edge")}},
			{TenantID: "tenant_northwind", Policies: []model.Policy{policyForTest("pol_nw", "tenant_northwind")}},
		},
	}
	if _, err := source.apply(payload, targets); err != nil {
		t.Fatalf("apply: %v", err)
	}

	if got := len(store.Snapshot("tenant_northwind")); got != 1 {
		t.Fatalf("the second tenant has %d policy(ies) on this Edge, want 1 — its policies reached nothing", got)
	}
	if got := len(store.Snapshot("tenant_edge")); got != 1 {
		t.Fatalf("the Edge's own tenant lost its policies: %d", got)
	}
	_ = now
}

// A tenant the section does not name is left alone. Absence is not an instruction here any more than it is
// for a deletion — a truncated payload must not silently disarm a tenant nobody mentioned.
func TestATenantAbsentFromTheSectionKeepsItsPolicies(t *testing.T) {
	store := policy.NewStore(nil)
	store.ReplaceTenant("tenant_untouched", []model.Policy{policyForTest("pol_keep", "tenant_untouched")}, time.Now())
	source := configBundleSource{tenantID: "tenant_edge"}
	targets := configApplyTargets{policyStore: store}

	payload := configBundlePayload{
		TenantPolicies: []tenantPolicySection{
			{TenantID: "tenant_northwind", Policies: []model.Policy{policyForTest("pol_nw", "tenant_northwind")}},
		},
	}
	if _, err := source.apply(payload, targets); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got := len(store.Snapshot("tenant_untouched")); got != 1 {
		t.Fatalf("a tenant the bundle never mentioned lost its policies (%d) — absence disarmed it", got)
	}
}

// The Edge's own tenant keeps the zero-policies lockout guard, which the loop deliberately does not repeat:
// a control plane sending zero policies for the tenant this Edge ENFORCES must not disarm it.
func TestTheEdgesOwnTenantKeepsItsLockoutGuard(t *testing.T) {
	store := policy.NewStore(nil)
	store.ReplaceTenant("tenant_edge", []model.Policy{policyForTest("pol_edge", "tenant_edge")}, time.Now())
	source := configBundleSource{tenantID: "tenant_edge"}
	targets := configApplyTargets{policyStore: store}

	payload := configBundlePayload{
		Policies: []model.Policy{}, // the control plane sent none
		TenantPolicies: []tenantPolicySection{
			{TenantID: "tenant_edge", Policies: []model.Policy{}},
		},
	}
	if _, err := source.apply(payload, targets); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got := len(store.Snapshot("tenant_edge")); got != 1 {
		t.Fatalf("an empty bundle disarmed the tenant this Edge enforces (%d policies left)", got)
	}
}

func policyForTest(id, tenantID string) model.Policy {
	return model.Policy{
		ID:         id,
		TenantID:   tenantID,
		Name:       id,
		Status:     "active",
		Priority:   1000,
		Conditions: map[string]any{"destination_port": 443},
		Action:     model.PolicyAction{Decision: "allow"},
	}
}
