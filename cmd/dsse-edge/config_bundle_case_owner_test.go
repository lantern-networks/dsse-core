package main

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
)

func TestConfigBundleAppliesCaseDistinctTenantPolicy(t *testing.T) {
	store := policy.NewStore(nil)
	if n := store.ReplaceTenant("Tenant_A", []model.Policy{{ID: "old", TenantID: "Tenant_A", Status: "active", Conditions: map[string]any{"service_family": "https"}, Action: model.PolicyAction{Decision: "allow"}}}, time.Now()); n != 1 {
		t.Fatal("invalid fixture policy")
	}
	source := configBundleSource{tenantID: "tenant_a"}
	payload := configBundlePayload{TenantPolicies: []tenantPolicySection{{TenantID: "Tenant_A", Policies: []model.Policy{
		{ID: "new", TenantID: "Tenant_A", Status: "active", Conditions: map[string]any{"service_family": "https"}, Action: model.PolicyAction{Decision: "deny"}},
	}}}}
	if _, err := source.apply(payload, configApplyTargets{policyStore: store}); err != nil {
		t.Fatal(err)
	}
	got := store.Snapshot("Tenant_A")
	if len(got) != 1 || got[0].ID != "new" || got[0].Action.Decision != "deny" {
		t.Fatalf("case-distinct tenant kept stale policy: %+v", got)
	}
}
