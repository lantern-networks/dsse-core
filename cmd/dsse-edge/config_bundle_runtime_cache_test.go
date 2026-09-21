package main

import (
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/policy"
	"path/filepath"
	"reflect"
	"testing"
)

func TestReceivedRuntimeControlsSurviveRestartWithoutPull(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.json")
	s := policy.NewStore(nil)
	if err := s.SetRuntimeStatePath(path); err != nil {
		t.Fatal(err)
	}
	cfg := policy.TenantConfigBundle{EastWestEnabled: true, EastWestAllowUnmatched: false, EastWestMaxGrantTTL: 37, ServerInitiatedEnabled: true, EastWestRules: []decision.EastWestRule{{ID: "deny", Mode: "deny", Destinations: []string{"db.invalid"}}}, TenantRestrictionRuleStatus: map[string]string{"rule": "disabled"}}
	src := configBundleSource{tenantID: "own"}
	if _, err := src.apply(configBundlePayload{TenantConfig: &cfg, TenantPolicies: []tenantPolicySection{{TenantID: "peer", Config: &cfg}}}, configApplyTargets{policyStore: s}); err != nil {
		t.Fatal(err)
	}
	r := policy.NewStore(nil)
	if err := r.SetRuntimeStatePath(path); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"own", "peer"} {
		if !reflect.DeepEqual(r.SnapshotTenantConfig(tenant), s.SnapshotTenantConfig(tenant)) {
			t.Fatalf("cold restart weakened %s controls: %+v", tenant, r.SnapshotTenantConfig(tenant))
		}
	}
}
