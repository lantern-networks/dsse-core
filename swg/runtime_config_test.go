package swg

import (
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

func TestPolicyBundleHasActiveTenantRestrictionRules(t *testing.T) {
	if PolicyBundleHasActiveTenantRestrictionRules(model.PolicyBundle{}) {
		t.Error("empty bundle should have no active tenant restriction rules")
	}

	cases := []struct {
		status string
		want   bool
	}{
		{"", true},           // empty status is treated as active
		{"active", true},     // explicit active
		{"ACTIVE", true},     // case-insensitive
		{"  active  ", true}, // whitespace-tolerant
		{"inactive", false},  // anything else is inactive
		{"disabled", false},
	}
	for _, tc := range cases {
		b := model.PolicyBundle{SWGTenantRestrictionRules: []model.SWGTenantRestrictionRule{{Status: tc.status}}}
		if got := PolicyBundleHasActiveTenantRestrictionRules(b); got != tc.want {
			t.Errorf("status=%q: got %v want %v", tc.status, got, tc.want)
		}
	}
}

func TestLoadRuntimeConfigNoPathNoRules(t *testing.T) {
	cfg, err := LoadRuntimeConfig(RuntimeConfigInput{
		TenantRestrictionOperatorValueStorePath: "  /tmp/value-store.json  ",
		RuntimeTLSDecryptionObserved:            true,
		MacCATrustObserved:                      true,
	})
	if err != nil {
		t.Fatalf("no path + no active rules should not error: %v", err)
	}
	if cfg.TenantRestrictionResolverConfigured {
		t.Error("no operator config path → resolver must not be configured")
	}
	if cfg.TenantRestrictionOperatorValueStorePath != "/tmp/value-store.json" {
		t.Errorf("value store path should be trimmed, got %q", cfg.TenantRestrictionOperatorValueStorePath)
	}
	if !cfg.RuntimeTLSDecryptionObserved || !cfg.MacCATrustObserved {
		t.Error("observed flags should pass through to the runtime config")
	}
}

func TestLoadRuntimeConfigNoPathButActiveRulesErrors(t *testing.T) {
	in := RuntimeConfigInput{
		PolicyBundle: model.PolicyBundle{
			SWGTenantRestrictionRules: []model.SWGTenantRestrictionRule{{Status: "active"}},
		},
	}
	if _, err := LoadRuntimeConfig(in); err == nil {
		t.Fatal("active tenant restriction rules without an operator config path must error")
	}
}
