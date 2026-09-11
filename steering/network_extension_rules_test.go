package steering

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadNetworkExtensionRulesAndEvaluateMatchedFlow(t *testing.T) {
	rules, err := LoadNetworkExtensionRules(sampleNetworkExtensionRulesPath(t))
	if err != nil {
		t.Fatalf("LoadNetworkExtensionRules returned error: %v", err)
	}
	decision := EvaluateNetworkExtensionFlow(rules, "DUMMY-SSH.LOCAL.", 22)
	if decision.Action != NetworkExtensionActionTunnel {
		t.Fatalf("action = %q, want tunnel: %+v", decision.Action, decision)
	}
	if decision.Reason != NetworkExtensionDecisionReasonMatched {
		t.Fatalf("reason = %q, want matched", decision.Reason)
	}
	if decision.ApplicationID != "app_dummy_ssh" {
		t.Fatalf("application_id = %q, want app_dummy_ssh", decision.ApplicationID)
	}
	if decision.ConnectorGroup != "cg_lab_001" {
		t.Fatalf("connector_group_id = %q, want cg_lab_001", decision.ConnectorGroup)
	}
}

func TestEvaluateNetworkExtensionFlowDeniesExplicitProxyDestination(t *testing.T) {
	rules, err := LoadNetworkExtensionRules(sampleNetworkExtensionRulesPath(t))
	if err != nil {
		t.Fatalf("LoadNetworkExtensionRules returned error: %v", err)
	}
	decision := EvaluateNetworkExtensionFlow(rules, "dummy-private-app.local", 443)
	if decision.Action != NetworkExtensionActionDeny {
		t.Fatalf("action = %q, want deny: %+v", decision.Action, decision)
	}
	if decision.Reason != NetworkExtensionDecisionReasonNoMatch {
		t.Fatalf("reason = %q, want no match", decision.Reason)
	}
}

func TestEvaluateNetworkExtensionFlowDeniesWrongPort(t *testing.T) {
	rules, err := LoadNetworkExtensionRules(sampleNetworkExtensionRulesPath(t))
	if err != nil {
		t.Fatalf("LoadNetworkExtensionRules returned error: %v", err)
	}
	decision := EvaluateNetworkExtensionFlow(rules, "dummy-ssh.local", 2222)
	if decision.Action != NetworkExtensionActionDeny {
		t.Fatalf("action = %q, want deny: %+v", decision.Action, decision)
	}
	if decision.Reason != NetworkExtensionDecisionReasonNoMatch {
		t.Fatalf("reason = %q, want no match", decision.Reason)
	}
}

func TestEvaluateNetworkExtensionFlowDeniesInvalidAuthority(t *testing.T) {
	rules, err := LoadNetworkExtensionRules(sampleNetworkExtensionRulesPath(t))
	if err != nil {
		t.Fatalf("LoadNetworkExtensionRules returned error: %v", err)
	}
	decision := EvaluateNetworkExtensionFlow(rules, "*.dummy-ssh.local", 22)
	if decision.Action != NetworkExtensionActionDeny {
		t.Fatalf("action = %q, want deny: %+v", decision.Action, decision)
	}
	if decision.Reason != NetworkExtensionDecisionReasonInvalidFlow {
		t.Fatalf("reason = %q, want invalid flow", decision.Reason)
	}
}

// Review #25: a raw IP-literal flow is a VALID flow that no FQDN rule can match, so it follows
// default_action — NOT an invalid flow denied up front. Under a non-tunnel default it is an unmatched flow
// (deny with reason NoMatch); under tunnel-all it tunnels.
func TestEvaluateNetworkExtensionFlowIPLiteralFollowsDefaultAction(t *testing.T) {
	// Default deny: an IP-literal flow is unmatched, not "invalid".
	denyRules := validNetworkExtensionRulesForTest() // DefaultAction = deny
	d := EvaluateNetworkExtensionFlow(denyRules, "127.0.0.1", 5432)
	if d.Action != NetworkExtensionActionDeny || d.Reason != NetworkExtensionDecisionReasonNoMatch {
		t.Fatalf("IP literal under default-deny: got %q/%q, want deny/no-match", d.Action, d.Reason)
	}

	// Tunnel-all: an IP-literal egress must be TUNNELED, honoring operator config.
	tunnelRules := validNetworkExtensionRulesForTest()
	tunnelRules.DefaultAction = NetworkExtensionActionTunnel
	tv4 := EvaluateNetworkExtensionFlow(tunnelRules, "203.0.113.7", 5432)
	if tv4.Action != NetworkExtensionActionTunnel || tv4.Reason != NetworkExtensionDecisionReasonDefault {
		t.Fatalf("IPv4 literal under tunnel-all: got %q/%q, want tunnel/default", tv4.Action, tv4.Reason)
	}
	if tv4.FQDN != "203.0.113.7" || tv4.DestinationPort != 5432 {
		t.Fatalf("tunnel decision must carry the IP + port: %+v", tv4)
	}
	// IPv6 literal too.
	tv6 := EvaluateNetworkExtensionFlow(tunnelRules, "2001:db8::1", 443)
	if tv6.Action != NetworkExtensionActionTunnel {
		t.Fatalf("IPv6 literal under tunnel-all must tunnel: %+v", tv6)
	}

	// A genuinely malformed host (neither FQDN nor IP) is still an invalid flow.
	bad := EvaluateNetworkExtensionFlow(tunnelRules, "not a host/path", 443)
	if bad.Action != NetworkExtensionActionDeny || bad.Reason != NetworkExtensionDecisionReasonInvalidFlow {
		t.Fatalf("malformed host must be an invalid flow: got %q/%q", bad.Action, bad.Reason)
	}
}

func TestValidateNetworkExtensionRulesRejectsDuplicateDestination(t *testing.T) {
	rules := validNetworkExtensionRulesForTest()
	rules.Rules = append(rules.Rules, rules.Rules[0])
	if err := ValidateNetworkExtensionRules(rules); err == nil {
		t.Fatal("ValidateNetworkExtensionRules returned nil error for duplicate destination")
	}
}

func TestValidateNetworkExtensionRulesRejectsIPLiteralRule(t *testing.T) {
	rules := validNetworkExtensionRulesForTest()
	rules.Rules[0].FQDN = "127.0.0.1"
	if err := ValidateNetworkExtensionRules(rules); err == nil {
		t.Fatal("ValidateNetworkExtensionRules returned nil error for IP literal fqdn")
	}
}

func TestValidateNetworkExtensionRulesAcceptsDefaultTunnelWithoutExactRules(t *testing.T) {
	rules := validNetworkExtensionRulesForTest()
	rules.DefaultAction = NetworkExtensionActionTunnel
	rules.Rules = nil
	if err := ValidateNetworkExtensionRules(rules); err != nil {
		t.Fatalf("ValidateNetworkExtensionRules returned error for default tunnel: %v", err)
	}
	decision := EvaluateNetworkExtensionFlow(rules, "mail.google.com", 443)
	if decision.Action != NetworkExtensionActionTunnel ||
		decision.Reason != NetworkExtensionDecisionReasonDefault ||
		decision.ApplicationID != "default_network_extension_tunnel" ||
		decision.FQDN != "mail.google.com" ||
		decision.DestinationPort != 443 ||
		decision.ServiceFamily != "https" {
		t.Fatalf("default tunnel decision = %+v", decision)
	}
}

func TestValidateNetworkExtensionRulesRejectsInvalidDefaultAction(t *testing.T) {
	rules := validNetworkExtensionRulesForTest()
	rules.DefaultAction = "observe"
	if err := ValidateNetworkExtensionRules(rules); err == nil {
		t.Fatal("ValidateNetworkExtensionRules returned nil error for invalid default_action")
	}
}

func TestValidateNetworkExtensionRulesRejectsNonTunnelRuleAction(t *testing.T) {
	rules := validNetworkExtensionRulesForTest()
	rules.Rules[0].Action = NetworkExtensionActionDeny
	if err := ValidateNetworkExtensionRules(rules); err == nil {
		t.Fatal("ValidateNetworkExtensionRules returned nil error for non-tunnel rule action")
	}
}

func validNetworkExtensionRulesForTest() NetworkExtensionRules {
	connectorGroup := "cg_lab_001"
	return NetworkExtensionRules{
		SchemaVersion:         NetworkExtensionRulesSchemaVersion,
		TenantID:              "tenant_lab_001",
		Version:               "2026.05.22.001",
		SourceProtectedAppMap: "protected_app_map_lab.json",
		GeneratedAt:           "2026-05-26T14:48:00Z",
		DefaultAction:         NetworkExtensionActionDeny,
		Rules: []NetworkExtensionRule{{
			ApplicationID:   "app_dummy_ssh",
			FQDN:            "dummy-ssh.local",
			DestinationPort: 22,
			ServiceFamily:   "ssh",
			SteeringMode:    "network_extension",
			Action:          NetworkExtensionActionTunnel,
			ConnectorGroup:  &connectorGroup,
		}},
	}
}

func sampleNetworkExtensionRulesPath(t *testing.T) string {
	t.Helper()
	candidates := []string{
		filepath.Join("..", "samples", "phase1", "network_extension_steering_rules_lab.json"),
		filepath.Join("..", "..", "oss", "samples", "phase1", "network_extension_steering_rules_lab.json"),
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	t.Skip("network extension steering rules fixture not shipped with the dsse-core module (monorepo-only)")
	return ""
}
