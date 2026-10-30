package decision

import (
	"github.com/lantern-networks/dsse-core/model"
	"testing"
)

func TestCaseDistinctTenantPolicyCannotAuthorizeOrDiagnose(t *testing.T) {
	policy := model.Policy{ID: "other-tenant-rule", TenantID: "Acme", Status: "active", Action: model.PolicyAction{Decision: "allow"}}
	req := model.DecisionRequest{TenantID: "acme", Destination: "example.com", Protocol: "tcp"}
	eval := Evaluator{Policies: []model.Policy{policy}}
	got := eval.Evaluate(req)
	if got.Decision != "deny" || got.PolicyID != "" {
		t.Fatalf("other tenant policy authorized request: decision=%q policy=%q", got.Decision, got.PolicyID)
	}
	if policyTenantAppliesTo(policy, req) {
		t.Fatal("other tenant policy exposed in diagnosis")
	}
	req.TenantID = "Acme"
	if got = eval.Evaluate(req); got.Decision != "allow" {
		t.Fatalf("owner's rule stopped matching: %q", got.Decision)
	}
}

func TestFlowTenantCannotBorrowStartupBundleBypassOrDLP(t *testing.T) {
	eval := Evaluator{PolicyBundle: model.PolicyBundle{TenantID: "startup-tenant",
		SWGTLSBypassRules: []model.SWGTLSBypassRule{{ID: "foreign-bypass", TenantID: "startup-tenant", Status: "active", MatchType: "domain", Pattern: "example.com"}},
		DLPRules:          []model.DLPRule{{ID: "foreign-dlp", TenantID: "startup-tenant", Status: "active"}},
	}}
	policy := model.Policy{TenantID: "flow-tenant"}
	req := model.DecisionRequest{TenantID: "flow-tenant", FQDN: "example.com"}
	if _, ok := eval.firstSWGTLSBypassRule(req, policy); ok {
		t.Error("startup tenant's bypass applied to another tenant")
	}
	if _, ok := eval.firstDLPRule(req, policy); ok {
		t.Error("startup tenant's DLP applied to another tenant")
	}
	req.TenantID = "startup-tenant"
	policy.TenantID = "startup-tenant"
	if _, ok := eval.firstSWGTLSBypassRule(req, policy); !ok {
		t.Error("owner's bypass missing")
	}
	if _, ok := eval.firstDLPRule(req, policy); !ok {
		t.Error("owner's DLP missing")
	}
}

func TestTenantResourceFallbackPrecedence(t *testing.T) {
	for _, tc := range []struct {
		candidate, bundle, policy, request string
		want                               bool
	}{
		{"", "bundle", "policy", "request", true},
		{"request", "bundle", "policy", "request", true},
		{"bundle", "bundle", "policy", "request", false},
		{"policy", "bundle", "policy", "request", false},
		{"policy", "bundle", "policy", "", true},
		{"bundle", "bundle", "", "", true},
		{"unrelated", "bundle", "", "", false},
	} {
		if got := tenantMatches(tc.candidate, tc.bundle, tc.policy, tc.request); got != tc.want {
			t.Errorf("scope %v: got %v", tc, got)
		}
	}
}
