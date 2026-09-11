package swg

import "testing"

func trStatus() TenantRestrictionStatusResponse {
	return TenantRestrictionStatusResponse{
		SchemaVersion:   "admin_swg_tenant_restriction_status.v1",
		TenantID:        "tenant_reference_lab",
		RuleCount:       3,
		ActiveRuleCount: 2,
		Rules: []adminSWGTenantRestrictionRuleStatus{
			{ID: "r_lab", TenantID: "tenant_reference_lab", SaaSApplicationID: "saas_google_workspace", HeaderValueRef: "operator_config_ref:google_allowed", Status: "active", Active: true},
			{ID: "r_nw", TenantID: "tenant_northwind", SaaSApplicationID: "saas_microsoft_365", HeaderValueRef: "operator_config_ref:ms_allowed", Status: "active", Active: true},
			{ID: "r_all", TenantID: "", SaaSApplicationID: "saas_anthropic_claude", HeaderValueRef: "operator_config_ref:claude_allowed", Status: "inactive"},
		},
	}
}

// ★★★ A CUSTOMER TURNED ANOTHER ORGANIZATION'S TENANT RESTRICTION ON, ON THE LIVE LAB, WITH A 200
// (2026-08-16). Signed in as Northwind's administrator the screen listed four rules belonging to another
// organization, and one POST made one of them active. Reverted in the same run.
func TestTenantRestrictionStatusIsScopedToTheOrganizationAsking(t *testing.T) {
	got := trStatus().ForTenant("tenant_northwind", false)

	if got.TenantID != "tenant_northwind" {
		t.Fatalf("the status must be about the caller, not about the node's own organization: %q", got.TenantID)
	}
	ids := map[string]bool{}
	for _, r := range got.Rules {
		ids[r.ID] = true
	}
	if ids["r_lab"] {
		t.Fatalf("another organization's rule is visible: %+v", got.Rules)
	}
	if !ids["r_nw"] {
		t.Fatalf("the caller's own rule must survive: %+v", got.Rules)
	}
	// An unattributed rule applies to every request this node serves — including the caller's. Hiding it would
	// say "your traffic is unrestricted" while it is being restricted, which is the worse failure.
	if !ids["r_all"] {
		t.Fatalf("a rule that applies to everybody must stay visible: %+v", got.Rules)
	}
	if got.RuleCount != 2 || got.ActiveRuleCount != 1 {
		t.Fatalf("the counts must be recomputed from what survives, got %d/%d", got.ActiveRuleCount, got.RuleCount)
	}

	// The control: an operator still sees the whole node.
	all := trStatus().ForTenant("", true)
	if len(all.Rules) != 3 || all.TenantID != "tenant_reference_lab" {
		t.Fatalf("the operator's view must be untouched, got %d rules for %q", len(all.Rules), all.TenantID)
	}
}

func TestTenantRestrictionUpdateRefusesAnotherOrganizationsRule(t *testing.T) {
	s := trStatus()

	// The exact act that succeeded on the lab.
	if refused := s.UpdateRefusal(TenantRestrictionUpdateRequest{
		SaaSEnablement: map[string]bool{"saas_google_workspace": true},
	}, "tenant_northwind", false); refused != "saas_google_workspace" {
		t.Fatalf("enabling another organization's rule must be refused, got %q", refused)
	}

	// Their own is theirs to change.
	if refused := s.UpdateRefusal(TenantRestrictionUpdateRequest{
		SaaSEnablement: map[string]bool{"saas_microsoft_365": false},
	}, "tenant_northwind", false); refused != "" {
		t.Fatalf("a caller must still change their own rule, refused %q", refused)
	}

	// A header value ref is shared by whatever rules cite it: replacing it changes what those rules inject.
	if refused := s.UpdateRefusal(TenantRestrictionUpdateRequest{
		HeaderValueUpdates: map[string]string{"operator_config_ref:google_allowed": "evil.example"},
	}, "tenant_northwind", false); refused != "operator_config_ref:google_allowed" {
		t.Fatalf("replacing a value only another organization's rules inject must be refused, got %q", refused)
	}

	// The control: the operator may do both.
	if refused := s.UpdateRefusal(TenantRestrictionUpdateRequest{
		SaaSEnablement:     map[string]bool{"saas_google_workspace": true},
		HeaderValueUpdates: map[string]string{"operator_config_ref:google_allowed": "example.com"},
	}, "", true); refused != "" {
		t.Fatalf("the operator must not be refused, got %q", refused)
	}
}
