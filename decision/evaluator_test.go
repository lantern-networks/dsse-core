package decision

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

func TestDestinationAddressScopeClassification(t *testing.T) {
	cases := []struct {
		dest string
		ip   string
		want string
	}{
		{"example.com", "", "public"},
		{"93.184.216.34", "", "public"},
		{"192.168.100.50", "", "private"},
		{"10.0.0.5", "", "private"},
		{"172.16.4.1", "", "private"},
		{"127.0.0.1", "", "loopback"},
		{"169.254.1.1", "", "link_local"},
		{"fd00::1", "", "private"},
		{"[::1]", "", "loopback"},
		{"", "10.1.2.3", "private"},
		{"", "8.8.8.8", "public"},
	}
	for _, tc := range cases {
		got := destinationAddressScope(model.DecisionRequest{Destination: tc.dest, DestinationIP: tc.ip})
		if got != tc.want {
			t.Errorf("destinationAddressScope(dest=%q ip=%q) = %q, want %q", tc.dest, tc.ip, got, tc.want)
		}
	}
}

func TestPolicyDestinationAddressScopePublicOnlyMatch(t *testing.T) {
	// Product model: the public-internet catch-all allow is limited to destination_address_scope=public;
	// private-range destinations do not match and fall through to default-deny.
	policy := model.Policy{
		Status:     "active",
		Conditions: map[string]any{"destination_address_scope": "public"},
	}
	if ok, _ := matchPolicy(policy, model.DecisionRequest{Destination: "example.com"}, "human"); !ok {
		t.Error("public FQDN must match destination_address_scope=public (internet allow)")
	}
	if ok, _ := matchPolicy(policy, model.DecisionRequest{Destination: "8.8.8.8"}, "human"); !ok {
		t.Error("public IP must match destination_address_scope=public")
	}
	if ok, _ := matchPolicy(policy, model.DecisionRequest{Destination: "192.168.100.50"}, "human"); ok {
		t.Error("private RFC1918 destination must NOT match public catch-all (falls to default-deny)")
	}
	if ok, _ := matchPolicy(policy, model.DecisionRequest{Destination: "10.0.0.5"}, "human"); ok {
		t.Error("private 10/8 destination must NOT match public catch-all")
	}
}

func TestEvaluateAllowsMatchedApplicationPolicy(t *testing.T) {
	ev := testEvaluator()
	dec := ev.Evaluate(model.DecisionRequest{
		TenantID:               "tenant_lab_001",
		SessionID:              "sess_lab_001",
		UserID:                 "user_lab_001",
		SubjectUserID:          "user_lab_001",
		ActorType:              "human",
		DeviceID:               "dev_lab_001",
		ApplicationID:          "app_dummy_https",
		ApplicationSensitivity: "medium",
		SourceIP:               "127.0.0.1",
		SourcePort:             50100,
		Destination:            "dummy-private-app.local",
		DestinationIP:          "127.0.0.1",
		DestinationPort:        8443,
		Protocol:               "tcp",
		FQDN:                   "dummy-private-app.local",
		SNI:                    "dummy-private-app.local",
		ServiceFamily:          "https",
		ConnectionInitiator:    "client",
		SourceRole:             "managed_endpoint",
		DestinationRole:        "private_app",
	})

	if dec.Decision != "allow" {
		t.Fatalf("decision = %q, want allow", dec.Decision)
	}
	if dec.PolicyID != "pol_https_allow_001" {
		t.Fatalf("policy_id = %q, want pol_https_allow_001", dec.PolicyID)
	}
	if dec.PolicyBundleID != "pb_lab_20260522_001" {
		t.Fatalf("policy_bundle_id = %q, want pb_lab_20260522_001", dec.PolicyBundleID)
	}
	if !contains(dec.ReasonCodes, "policy_matched") {
		t.Fatalf("reason_codes = %v, want policy_matched", dec.ReasonCodes)
	}
	if !contains(dec.ReasonCodes, "application_allowed") {
		t.Fatalf("reason_codes = %v, want application_allowed", dec.ReasonCodes)
	}
	if len(dec.MatchedConditions) != 3 {
		t.Fatalf("matched_conditions length = %d, want 3", len(dec.MatchedConditions))
	}
}

// TestEvaluateTenantIsolatesPolicyMatch pins review finding #1: the shared RuntimeEvaluator flattens every
// tenant's policies into one set, so a request must NOT match another tenant's policy. A tenant-B request against
// a tenant-A-scoped allow policy must fall through to the unmatched default (deny), while a same-tenant request
// still matches, and a tenant-less (global) policy still matches any tenant.
func TestEvaluateTenantIsolatesPolicyMatch(t *testing.T) {
	base := func(tenant string) model.DecisionRequest {
		return model.DecisionRequest{
			TenantID: tenant, ActorType: "human", ApplicationID: "app_x", ServiceFamily: "https",
			SubjectUserID: "u1", ConnectionInitiator: "client",
		}
	}
	allowA := model.Policy{
		ID: "pol_a_allow", TenantID: "tenant-a", Priority: 100, Status: "active",
		Conditions: map[string]any{"actor_type": "human", "application_id": "app_x", "service_family": "https"},
		Action:     model.PolicyAction{Decision: "allow"},
	}
	ev := testEvaluatorWithPolicies([]model.Policy{allowA})

	// Same tenant → matches (control).
	if dec := ev.Evaluate(base("tenant-a")); dec.Decision != "allow" || dec.PolicyID != "pol_a_allow" {
		t.Fatalf("same-tenant: decision=%q policy=%q, want allow/pol_a_allow", dec.Decision, dec.PolicyID)
	}
	// A different tenant falls through to default deny, with no policy attribution.
	if dec := ev.Evaluate(base("tenant-b")); dec.Decision != "deny" || dec.PolicyID != "" {
		t.Fatalf("cross-tenant: want unattributed deny; decision=%q policy=%q reasons=%v", dec.Decision, dec.PolicyID, dec.ReasonCodes)
	}

	// A tenant-less (global) policy still matches any tenant (lockout-safe empty handling).
	globalAllow := allowA
	globalAllow.ID = "pol_global_allow"
	globalAllow.TenantID = ""
	evG := testEvaluatorWithPolicies([]model.Policy{globalAllow})
	if dec := evG.Evaluate(base("tenant-b")); dec.Decision != "allow" || dec.PolicyID != "pol_global_allow" {
		t.Fatalf("global policy must match any tenant: decision=%q policy=%q", dec.Decision, dec.PolicyID)
	}
}

func TestEvaluateMatchesSessionIDPresentCondition(t *testing.T) {
	ev := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:       "pol_auth_required_without_session_001",
			TenantID: "tenant_lab_001",
			Priority: 10,
			Conditions: map[string]any{
				"application_id":     "app_private_internal_web",
				"service_family":     "https",
				"session_id_present": "false",
			},
			Action: model.PolicyAction{Decision: "require_reauthentication"},
			Status: "active",
		},
		{
			ID:       "pol_allow_with_session_001",
			TenantID: "tenant_lab_001",
			Priority: 20,
			Conditions: map[string]any{
				"application_id":     "app_private_internal_web",
				"service_family":     "https",
				"session_id_present": "true",
			},
			Action: model.PolicyAction{Decision: "allow"},
			Status: "active",
		},
	})

	noSession := ev.Evaluate(model.DecisionRequest{
		TenantID:      "tenant_lab_001",
		ActorType:     "human",
		ApplicationID: "app_private_internal_web",
		ServiceFamily: "https",
	})
	if noSession.Decision != "require_reauthentication" || noSession.PolicyID != "pol_auth_required_without_session_001" {
		t.Fatalf("no-session decision=%s policy=%s, want require_reauthentication policy", noSession.Decision, noSession.PolicyID)
	}
	if !contains(noSession.MatchedConditions, "session_id_present") {
		t.Fatalf("no-session matched_conditions = %v, want session_id_present", noSession.MatchedConditions)
	}

	withSession := ev.Evaluate(model.DecisionRequest{
		TenantID:      "tenant_lab_001",
		SessionID:     "sess_lab_001",
		ActorType:     "human",
		ApplicationID: "app_private_internal_web",
		ServiceFamily: "https",
	})
	if withSession.Decision != "allow" || withSession.PolicyID != "pol_allow_with_session_001" {
		t.Fatalf("with-session decision=%s policy=%s, want allow policy", withSession.Decision, withSession.PolicyID)
	}
	if !contains(withSession.MatchedConditions, "session_id_present") {
		t.Fatalf("with-session matched_conditions = %v, want session_id_present", withSession.MatchedConditions)
	}
}

func TestProductizationP2PolicyDecisionFixturesReplayThroughEvaluator(t *testing.T) {
	type p2PolicyBindingsFile struct {
		TenantID string         `json:"tenant_id"`
		Policies []model.Policy `json:"policies"`
	}
	type p2DecisionFixture struct {
		FixtureID       string `json:"fixture_id"`
		ServiceCategory string `json:"service_category"`
		Request         struct {
			TenantID                string `json:"tenant_id"`
			ActorType               string `json:"actor_type"`
			ApplicationID           string `json:"application_id"`
			ServiceFamily           string `json:"service_family"`
			DestinationPort         int    `json:"destination_port"`
			Protocol                string `json:"protocol"`
			SteeringMode            string `json:"steering_mode"`
			NetworkExtensionRuleRef string `json:"network_extension_rule_ref"`
			DestinationValueSource  string `json:"destination_value_source"`
			DatabaseProtocol        string `json:"database_protocol"`
		} `json:"request"`
		ExpectedPolicyDecision struct {
			Decision               string   `json:"decision"`
			PolicyID               string   `json:"policy_id"`
			ReasonCodes            []string `json:"reason_codes"`
			NetworkExtensionAction string   `json:"network_extension_action"`
		} `json:"expected_policy_decision"`
	}
	type p2DecisionFixturesFile struct {
		TenantID string              `json:"tenant_id"`
		Fixtures []p2DecisionFixture `json:"fixtures"`
	}

	loadJSON := func(path string, target any) {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				t.Skipf("fixture not shipped with the dsse-core module (monorepo-only): %s", path)
			}
			t.Fatalf("read %s: %v", path, err)
		}
		if err := json.Unmarshal(data, target); err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
	}

	configDir := filepath.Join("..", "..", "config", "productization_p2")
	var bindings p2PolicyBindingsFile
	loadJSON(filepath.Join(configDir, "policy_bindings_operator_config.json"), &bindings)
	var fixtures p2DecisionFixturesFile
	loadJSON(filepath.Join(configDir, "policy_decision_fixtures_operator_config.json"), &fixtures)
	if len(fixtures.Fixtures) != 4 {
		t.Fatalf("fixtures = %d, want 4", len(fixtures.Fixtures))
	}

	ev := Evaluator{
		Policies: bindings.Policies,
		PolicyBundle: model.PolicyBundle{
			ID:       "pb_p2_operator_config_m1543_local_replay",
			TenantID: bindings.TenantID,
			Version:  "local-replay",
		},
		EdgeRegionID:  "local",
		EdgeClusterID: "local-edge-p2",
	}
	for _, fixture := range fixtures.Fixtures {
		req := model.DecisionRequest{
			TenantID:        fixture.Request.TenantID,
			ActorType:       fixture.Request.ActorType,
			ApplicationID:   fixture.Request.ApplicationID,
			ServiceFamily:   fixture.Request.ServiceFamily,
			DestinationPort: fixture.Request.DestinationPort,
			Protocol:        fixture.Request.Protocol,
			SteeringMode:    fixture.Request.SteeringMode,
		}
		dec := ev.Evaluate(req)
		if dec.Decision != fixture.ExpectedPolicyDecision.Decision {
			t.Fatalf("%s decision = %q, want %q", fixture.FixtureID, dec.Decision, fixture.ExpectedPolicyDecision.Decision)
		}
		if dec.PolicyID != fixture.ExpectedPolicyDecision.PolicyID {
			t.Fatalf("%s policy_id = %q, want %q", fixture.FixtureID, dec.PolicyID, fixture.ExpectedPolicyDecision.PolicyID)
		}
		for _, key := range []string{"actor_type", "application_id", "destination_port", "service_family", "steering_mode"} {
			if !contains(dec.MatchedConditions, key) {
				t.Fatalf("%s matched_conditions = %v, want %s", fixture.FixtureID, dec.MatchedConditions, key)
			}
		}
		if !contains(dec.ReasonCodes, "policy_matched") || !contains(dec.ReasonCodes, "application_allowed") {
			t.Fatalf("%s reason_codes = %v, want policy_matched and application_allowed", fixture.FixtureID, dec.ReasonCodes)
		}
		if dec.FQDN != nil && *dec.FQDN != "" {
			t.Fatalf("%s replay unexpectedly used fqdn %q", fixture.FixtureID, *dec.FQDN)
		}
		if dec.DestinationIP != nil && *dec.DestinationIP != "" {
			t.Fatalf("%s replay unexpectedly used destination_ip %q", fixture.FixtureID, *dec.DestinationIP)
		}
		if fixture.Request.DestinationValueSource != "source_operator_config_not_duplicated" {
			t.Fatalf("%s destination_value_source = %q", fixture.FixtureID, fixture.Request.DestinationValueSource)
		}
		if fixture.ExpectedPolicyDecision.NetworkExtensionAction != "tunnel" {
			t.Fatalf("%s network_extension_action = %q, want tunnel", fixture.FixtureID, fixture.ExpectedPolicyDecision.NetworkExtensionAction)
		}
	}
}

func TestProductizationP2PolicyEnforcementPreflightFixturesReplayThroughEvaluator(t *testing.T) {
	type p2PolicyBindingsFile struct {
		TenantID string         `json:"tenant_id"`
		Policies []model.Policy `json:"policies"`
	}
	type p2PolicyEnforcementFixture struct {
		FixtureID       string `json:"fixture_id"`
		FixtureClass    string `json:"fixture_class"`
		ServiceCategory string `json:"service_category"`
		Request         struct {
			TenantID                string `json:"tenant_id"`
			ActorType               string `json:"actor_type"`
			ApplicationID           string `json:"application_id"`
			ServiceFamily           string `json:"service_family"`
			DestinationPort         int    `json:"destination_port"`
			Protocol                string `json:"protocol"`
			SteeringMode            string `json:"steering_mode"`
			NetworkExtensionRuleRef string `json:"network_extension_rule_ref"`
			DestinationValueSource  string `json:"destination_value_source"`
			DatabaseProtocol        string `json:"database_protocol"`
		} `json:"request"`
		ExpectedPolicyDecision struct {
			Decision               string   `json:"decision"`
			PolicyID               string   `json:"policy_id"`
			ReasonCodes            []string `json:"reason_codes"`
			NetworkExtensionAction string   `json:"network_extension_action"`
		} `json:"expected_policy_decision"`
	}
	type p2PolicyEnforcementFixturesFile struct {
		TenantID      string                       `json:"tenant_id"`
		AllowFixtures []p2PolicyEnforcementFixture `json:"allow_fixtures"`
		DenyFixtures  []p2PolicyEnforcementFixture `json:"deny_fixtures"`
	}

	loadJSON := func(path string, target any) {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				t.Skipf("fixture not shipped with the dsse-core module (monorepo-only): %s", path)
			}
			t.Fatalf("read %s: %v", path, err)
		}
		if err := json.Unmarshal(data, target); err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
	}

	configDir := filepath.Join("..", "..", "config", "productization_p2")
	var bindings p2PolicyBindingsFile
	loadJSON(filepath.Join(configDir, "policy_bindings_operator_config.json"), &bindings)
	var fixtures p2PolicyEnforcementFixturesFile
	loadJSON(filepath.Join(configDir, "policy_enforcement_preflight_fixtures_operator_config.json"), &fixtures)
	if len(fixtures.AllowFixtures) != 4 {
		t.Fatalf("allow fixtures = %d, want 4", len(fixtures.AllowFixtures))
	}
	if len(fixtures.DenyFixtures) != 4 {
		t.Fatalf("deny fixtures = %d, want 4", len(fixtures.DenyFixtures))
	}

	ev := Evaluator{
		Policies: bindings.Policies,
		PolicyBundle: model.PolicyBundle{
			ID:       "pb_p2_operator_config_m1558_policy_enforcement_preflight",
			TenantID: bindings.TenantID,
			Version:  "policy-enforcement-preflight",
		},
		EdgeRegionID:  "local",
		EdgeClusterID: "local-edge-p2",
	}

	replay := func(fixture p2PolicyEnforcementFixture) {
		t.Helper()
		req := model.DecisionRequest{
			TenantID:        fixture.Request.TenantID,
			ActorType:       fixture.Request.ActorType,
			ApplicationID:   fixture.Request.ApplicationID,
			ServiceFamily:   fixture.Request.ServiceFamily,
			DestinationPort: fixture.Request.DestinationPort,
			Protocol:        fixture.Request.Protocol,
			SteeringMode:    fixture.Request.SteeringMode,
		}
		dec := ev.Evaluate(req)
		if dec.Decision != fixture.ExpectedPolicyDecision.Decision {
			t.Fatalf("%s decision = %q, want %q", fixture.FixtureID, dec.Decision, fixture.ExpectedPolicyDecision.Decision)
		}
		if fixture.ExpectedPolicyDecision.PolicyID != "" && dec.PolicyID != fixture.ExpectedPolicyDecision.PolicyID {
			t.Fatalf("%s policy_id = %q, want %q", fixture.FixtureID, dec.PolicyID, fixture.ExpectedPolicyDecision.PolicyID)
		}
		for _, code := range fixture.ExpectedPolicyDecision.ReasonCodes {
			if !contains(dec.ReasonCodes, code) {
				t.Fatalf("%s reason_codes = %v, want %s", fixture.FixtureID, dec.ReasonCodes, code)
			}
		}
		if dec.FQDN != nil && *dec.FQDN != "" {
			t.Fatalf("%s replay unexpectedly used fqdn %q", fixture.FixtureID, *dec.FQDN)
		}
		if dec.DestinationIP != nil && *dec.DestinationIP != "" {
			t.Fatalf("%s replay unexpectedly used destination_ip %q", fixture.FixtureID, *dec.DestinationIP)
		}
		if fixture.Request.DestinationValueSource == "" {
			t.Fatalf("%s destination_value_source is empty", fixture.FixtureID)
		}
		switch fixture.FixtureClass {
		case "allow_control":
			for _, key := range []string{"actor_type", "application_id", "destination_port", "service_family", "steering_mode"} {
				if !contains(dec.MatchedConditions, key) {
					t.Fatalf("%s matched_conditions = %v, want %s", fixture.FixtureID, dec.MatchedConditions, key)
				}
			}
			if fixture.ExpectedPolicyDecision.NetworkExtensionAction != "tunnel" {
				t.Fatalf("%s network_extension_action = %q, want tunnel", fixture.FixtureID, fixture.ExpectedPolicyDecision.NetworkExtensionAction)
			}
		case "deny_control":
			if len(dec.MatchedConditions) != 0 {
				t.Fatalf("%s matched_conditions = %v, want none", fixture.FixtureID, dec.MatchedConditions)
			}
			if fixture.ExpectedPolicyDecision.NetworkExtensionAction != "deny" {
				t.Fatalf("%s network_extension_action = %q, want deny", fixture.FixtureID, fixture.ExpectedPolicyDecision.NetworkExtensionAction)
			}
		default:
			t.Fatalf("%s fixture_class = %q", fixture.FixtureID, fixture.FixtureClass)
		}
	}

	for _, fixture := range fixtures.AllowFixtures {
		replay(fixture)
	}
	for _, fixture := range fixtures.DenyFixtures {
		replay(fixture)
	}
}

// TestEvaluateDoesNotAutoDenyOnRiskSignals pins the product requirement: a live risk signal must NEVER, on its
// own, deny access. Device risk is INGESTED (admin API / manual marking / DLP) and exposed to the policy
// matcher as conditions; whether it blocks anything is the operator's policy decision.
//
// This test previously asserted the OPPOSITE — a hardcoded "Ransomware Protection Mode" overlay denied here
// before any policy was consulted, with no toggle and a Go-literal protocol list. That overlay was removed as
// a requirement violation: risk must reach a decision only through operator-authored policy. Each case below is
// a signal that used to force a deny; all of them must now fall through to the matched policy (allow).
func TestEvaluateDoesNotAutoDenyOnRiskSignals(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*model.DecisionRequest)
		reasonCode string
	}{
		{
			name: "manual high risk",
			mutate: func(req *model.DecisionRequest) {
				req.AdminHighRisk = true
			},
			reasonCode: "risk_signal_manual_high_risk",
		},
		{
			name: "idp high risk",
			mutate: func(req *model.DecisionRequest) {
				req.IDPRiskLevel = "high"
			},
			reasonCode: "risk_signal_idp_high_risk",
		},
		{
			name: "agent tamper",
			mutate: func(req *model.DecisionRequest) {
				req.AgentTamperSignal = true
			},
			reasonCode: "risk_signal_agent_tamper",
		},
		{
			name: "authentication anomaly",
			mutate: func(req *model.DecisionRequest) {
				req.AuthenticationAnomaly = true
			},
			reasonCode: "risk_signal_authentication_anomaly",
		},
		{
			name: "risk state recommended action",
			mutate: func(req *model.DecisionRequest) {
				req.RiskStateID = "risk_state_lab_001"
				req.RiskRecommendedAction = "apply_ransomware_protection_mode"
			},
			reasonCode: "risk_state_recommended_emergency_block",
		},
		{
			name: "risk signal source",
			mutate: func(req *model.DecisionRequest) {
				req.RiskSignalSources = []string{"manual_high_risk"}
			},
			reasonCode: "risk_signal_manual_high_risk",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := testEvaluatorWithPolicies([]model.Policy{
				{
					ID:       "pol_database_allow_001",
					TenantID: "tenant_lab_001",
					Priority: 100,
					Conditions: map[string]any{
						"actor_type":     "human",
						"application_id": "app_dummy_postgres",
						"service_family": "database",
					},
					Action: model.PolicyAction{Decision: "allow"},
					Status: "active",
				},
			})
			req := model.DecisionRequest{
				TenantID:               "tenant_lab_001",
				UserID:                 "user_lab_001",
				ActorType:              "human",
				DeviceID:               "dev_lab_001",
				ApplicationID:          "app_dummy_postgres",
				ApplicationSensitivity: "high",
				ServiceFamily:          "database",
				DestinationPort:        5432,
			}
			tt.mutate(&req)

			dec := ev.Evaluate(req)
			// The matched operator policy governs — the risk signal alone must not override it.
			if dec.Decision != "allow" {
				t.Fatalf("decision = %q, want allow (a risk signal must not deny on its own)", dec.Decision)
			}
			if dec.PolicyID != "pol_database_allow_001" {
				t.Fatalf("policy_id = %q, want the matched operator policy", dec.PolicyID)
			}
			// The removed overlay's vocabulary must be gone from the wire entirely.
			for _, code := range []string{"ransomware_protection_mode_active", "high_sensitivity_application"} {
				if contains(dec.ReasonCodes, code) {
					t.Fatalf("reason_codes = %v, must not contain the removed overlay code %s", dec.ReasonCodes, code)
				}
			}
			// The risk state itself is still carried — it is INPUT for policy, just not an automatic deny.
			if req.RiskStateID != "" && (dec.RiskStateID == nil || *dec.RiskStateID != req.RiskStateID) {
				t.Fatalf("risk_state_id = %#v, want %s (risk must still be observable to policy)", dec.RiskStateID, req.RiskStateID)
			}
		})
	}
}

// TestEvaluateRiskGatedPolicyDenies is the replacement mechanism for the removed overlay: risk-based
// authorization is expressed as an operator-authored policy condition (what the Console's risk_at_least
// compiles to) and is honoured by the normal policy branch. Risk still blocks — but only because an operator
// said so.
func TestEvaluateRiskGatedPolicyDenies(t *testing.T) {
	ev := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:       "pol_deny_when_high_risk",
			TenantID: "tenant_lab_001",
			Priority: 50, // lower number wins
			Conditions: map[string]any{
				"actor_type":          "human",
				"service_family":      "database",
				"risk_state_severity": []any{"high", "critical"},
			},
			Action: model.PolicyAction{Decision: "deny"},
			Status: "active",
		},
		{
			ID:       "pol_database_allow_001",
			TenantID: "tenant_lab_001",
			Priority: 100,
			Conditions: map[string]any{
				"actor_type":     "human",
				"service_family": "database",
			},
			Action: model.PolicyAction{Decision: "allow"},
			Status: "active",
		},
	})
	base := model.DecisionRequest{
		TenantID: "tenant_lab_001", UserID: "user_lab_001", ActorType: "human",
		DeviceID: "dev_lab_001", ServiceFamily: "database", DestinationPort: 5432,
	}

	for _, tc := range []struct{ severity, want, wantPolicy string }{
		{"", "allow", "pol_database_allow_001"},
		{"medium", "allow", "pol_database_allow_001"},
		{"high", "deny", "pol_deny_when_high_risk"},
		{"critical", "deny", "pol_deny_when_high_risk"},
	} {
		req := base
		req.RiskStateSeverity = tc.severity
		dec := ev.Evaluate(req)
		if dec.Decision != tc.want || dec.PolicyID != tc.wantPolicy {
			t.Errorf("severity %q: decision = %q via %q, want %q via %q",
				tc.severity, dec.Decision, dec.PolicyID, tc.want, tc.wantPolicy)
		}
	}
}

func TestEvaluateDoesNotEmergencyBlockMediumSensitivityApplication(t *testing.T) {
	ev := testEvaluator()
	dec := ev.Evaluate(model.DecisionRequest{
		TenantID:               "tenant_lab_001",
		UserID:                 "user_lab_001",
		ActorType:              "human",
		DeviceID:               "dev_lab_001",
		ApplicationID:          "app_dummy_https",
		ApplicationSensitivity: "medium",
		ServiceFamily:          "https",
		AdminHighRisk:          true,
	})

	if dec.Decision != "allow" {
		t.Fatalf("decision = %q, want allow for medium sensitivity app", dec.Decision)
	}
	if contains(dec.ReasonCodes, "ransomware_protection_mode_active") {
		t.Fatalf("reason_codes = %v, did not expect ransomware_protection_mode_active", dec.ReasonCodes)
	}
	if dec.Metadata["admin_high_risk"] != true {
		t.Fatalf("metadata admin_high_risk = %v, want true", dec.Metadata["admin_high_risk"])
	}
}

func TestEvaluateEnrichesSaaSContextFromCatalog(t *testing.T) {
	ev := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:       "pol_saas_slack_allow_001",
			TenantID: "tenant_lab_001",
			Priority: 100,
			Conditions: map[string]any{
				"actor_type":          "human",
				"saas_application_id": "saas_slack",
				"service_family":      "https",
			},
			Action: model.PolicyAction{Decision: "allow"},
			Status: "active",
		},
	})
	ev.PolicyBundle.SaaSCatalog = []model.SaaSCatalogEntry{
		{
			TenantID:          "tenant_lab_001",
			SaaSApplicationID: "saas_slack",
			Name:              "Slack",
			Provider:          "slack",
			Category:          "collaboration",
			RiskTier:          "standard",
			DomainPatterns:    []string{"slack.com", "*.slack.com"},
		},
	}

	dec := ev.Evaluate(model.DecisionRequest{
		TenantID:               "tenant_lab_001",
		UserID:                 "user_lab_001",
		ActorType:              "human",
		ApplicationID:          "app_saas_egress",
		ApplicationSensitivity: "medium",
		FQDN:                   "Engineering.Slack.com.",
		SNI:                    "engineering.slack.com",
		ServiceFamily:          "https",
		DestinationPort:        443,
	})

	if dec.Decision != "allow" {
		t.Fatalf("decision = %q, want allow", dec.Decision)
	}
	if dec.PolicyID != "pol_saas_slack_allow_001" {
		t.Fatalf("policy_id = %q, want pol_saas_slack_allow_001", dec.PolicyID)
	}
	if dec.SaaSContext == nil {
		t.Fatal("saas_context = nil, want catalog context")
	}
	if dec.SaaSContext.SaaSApplicationID != "saas_slack" || dec.SaaSContext.Provider != "slack" || dec.SaaSContext.MatchedDomain != "engineering.slack.com" || dec.SaaSContext.MatchType != "fqdn_wildcard" {
		t.Fatalf("saas_context = %#v, want Slack fqdn wildcard context", dec.SaaSContext)
	}
	for _, key := range []string{"saas_application_id", "saas_provider", "saas_category", "saas_risk_tier", "saas_matched_domain", "saas_matched_pattern", "saas_match_type"} {
		if _, ok := dec.Metadata[key]; !ok {
			t.Fatalf("metadata missing %s: %#v", key, dec.Metadata)
		}
	}
	accessLog := AccessLogFromDecision(dec)
	if accessLog.Metadata["saas_application_id"] != "saas_slack" {
		t.Fatalf("access log metadata = %#v, want saas_application_id", accessLog.Metadata)
	}
	trace := DecisionTraceFromDecision(dec)
	if trace.Metadata["saas_provider"] != "slack" {
		t.Fatalf("trace metadata = %#v, want SaaS provider", trace.Metadata)
	}
}

func TestEvaluateDoesNotTrustRequestSuppliedSaaSContextWithoutCatalogMatch(t *testing.T) {
	ev := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:       "pol_saas_slack_allow_001",
			TenantID: "tenant_lab_001",
			Priority: 100,
			Conditions: map[string]any{
				"actor_type":          "human",
				"saas_application_id": "saas_slack",
				"service_family":      "https",
			},
			Action: model.PolicyAction{Decision: "allow"},
			Status: "active",
		},
	})
	ev.PolicyBundle.SaaSCatalog = []model.SaaSCatalogEntry{
		{
			TenantID:          "tenant_lab_001",
			SaaSApplicationID: "saas_slack",
			Provider:          "slack",
			DomainPatterns:    []string{"*.slack.com"},
		},
	}

	dec := ev.Evaluate(model.DecisionRequest{
		TenantID:          "tenant_lab_001",
		ActorType:         "human",
		ApplicationID:     "app_saas_egress",
		ServiceFamily:     "https",
		FQDN:              "untrusted.example",
		SaaSApplicationID: "saas_slack",
		SaaSProvider:      "slack",
	})

	if dec.Decision != "deny" {
		t.Fatalf("decision = %q, want deny", dec.Decision)
	}
	if dec.SaaSContext != nil {
		t.Fatalf("saas_context = %#v, want nil without catalog match", dec.SaaSContext)
	}
	if _, ok := dec.Metadata["saas_application_id"]; ok {
		t.Fatalf("metadata = %#v, did not expect request-supplied SaaS context", dec.Metadata)
	}
}

func TestEvaluatePropagatesTLSInspectionReadinessMetadata(t *testing.T) {
	profileID := "ip_tls_readiness_lab"
	ev := testTLSReadinessEvaluator(profileID)

	dec := ev.Evaluate(model.DecisionRequest{
		TenantID:            "tenant_lab_001",
		ActorType:           "human",
		ApplicationID:       "app_dummy_https",
		ServiceFamily:       "https",
		Protocol:            "tcp",
		InspectionProfileID: "client_supplied_profile_is_not_authoritative",
		TrustProfileID:      "client_supplied_trust_profile_is_not_authoritative",
		TenantRootCAID:      "client_supplied_root_ca_is_not_authoritative",
	})

	if dec.Decision != "allow" {
		t.Fatalf("decision = %q, want allow", dec.Decision)
	}
	if dec.InspectionProfileID == nil || *dec.InspectionProfileID != profileID {
		t.Fatalf("inspection_profile_id = %#v, want %s", dec.InspectionProfileID, profileID)
	}
	if dec.InspectionMode == nil || *dec.InspectionMode != "tls_readiness" {
		t.Fatalf("inspection_mode = %#v, want tls_readiness", dec.InspectionMode)
	}
	for key, want := range map[string]any{
		"tls_inspection_readiness":          "policy_layer",
		"tls_interception_enabled":          false,
		"certificate_issuance_mode":         "not_issued",
		"inspection_profile_id":             profileID,
		"trust_profile_id":                  "tp_lab_managed_browser_001",
		"trust_profile_status":              "active",
		"tenant_root_ca_id":                 "trca_lab_001",
		"tenant_root_ca_status":             "configured",
		"tenant_root_ca_private_key_status": "not_recorded",
		"quic_policy_mode":                  "prefer_tcp_tls",
		"quic_policy_action":                "tcp_tls_required",
		"network_extension_runtime_used":    false,
		"network_extension_dependency":      "none_policy_layer",
	} {
		if got := dec.Metadata[key]; got != want {
			t.Fatalf("metadata[%s] = %#v, want %#v; metadata=%#v", key, got, want, dec.Metadata)
		}
	}
	if dec.Metadata["requested_inspection_profile_id"] != "client_supplied_profile_is_not_authoritative" {
		t.Fatalf("metadata = %#v, want requested inspection profile preserved separately", dec.Metadata)
	}

	// The access record no longer restates the tenant's inspection/trust/CA config — it carries a
	// config_generation_id, and the config resolves through the generation snapshot. The property under test is
	// unchanged and is what matters: the AUTHORITATIVE config is recoverable from the record. Only the shape
	// moved, from ~20 keys per decision to one id plus a row per config change.
	accessLog := AccessLogFromDecision(dec)
	if accessLog.ConfigGenerationID == "" {
		t.Fatalf("access log = %#v, want a config_generation_id", accessLog)
	}
	if _, stillInline := accessLog.Metadata["tenant_root_ca_id"]; stillInline {
		t.Fatalf("access log metadata = %#v, want the config block normalised out of the record", accessLog.Metadata)
	}
	snapshot, ok := ConfigGenerationFromDecision(dec)
	if !ok {
		t.Fatalf("decision %#v produced no config generation", dec.Metadata)
	}
	if snapshot.ID != accessLog.ConfigGenerationID {
		t.Fatalf("generation id = %q, want the record's %q", snapshot.ID, accessLog.ConfigGenerationID)
	}
	if snapshot.Config["tenant_root_ca_id"] != "trca_lab_001" {
		t.Fatalf("generation config = %#v, want tenant root CA id recoverable", snapshot.Config)
	}
	if snapshot.Config["trust_profile_id"] != "tp_lab_managed_browser_001" {
		t.Fatalf("generation config = %#v, want trust profile id recoverable", snapshot.Config)
	}
	// Per-request facts must NOT be normalised away: they are not config, and freezing them into a generation
	// shared by every decision would make them lie (they were only "constant" in the 95-decision sample).
	if accessLog.Metadata["edge_tls_policy_decision"] != "metadata_inspection" {
		t.Fatalf("access log metadata = %#v, want the per-request edge_tls_policy_decision kept inline", accessLog.Metadata)
	}
	trace := DecisionTraceFromDecision(dec)
	if trace.Metadata["trust_profile_id"] != "tp_lab_managed_browser_001" || trace.Metadata["certificate_issuance_mode"] != "not_issued" {
		t.Fatalf("trace metadata = %#v, want TLS readiness metadata", trace.Metadata)
	}
}

func TestEvaluateRecordsQUICPolicyAsAuditMetadataWithoutRuntimeClaim(t *testing.T) {
	ev := testTLSReadinessEvaluator("ip_tls_readiness_lab")

	dec := ev.Evaluate(model.DecisionRequest{
		TenantID:      "tenant_lab_001",
		ActorType:     "human",
		ApplicationID: "app_dummy_https",
		ServiceFamily: "quic",
		Protocol:      "udp",
	})

	if dec.Decision != "allow" {
		t.Fatalf("decision = %q, want allow", dec.Decision)
	}
	for _, code := range []string{"tls_inspection_readiness_policy_layer", "quic_tcp_tls_required"} {
		if !contains(dec.ReasonCodes, code) {
			t.Fatalf("reason_codes = %v, want %s", dec.ReasonCodes, code)
		}
	}
	if dec.Metadata["quic_tcp_tls_redirect_required"] != true {
		t.Fatalf("metadata = %#v, want quic_tcp_tls_redirect_required", dec.Metadata)
	}
	if dec.Metadata["network_extension_runtime_used"] != false {
		t.Fatalf("metadata = %#v, want runtime-used false", dec.Metadata)
	}
	if len(dec.Actions) != 1 || dec.Actions[0].Type != "emit_audit_event" {
		t.Fatalf("actions = %#v, want one audit metadata action", dec.Actions)
	}
	if dec.Actions[0].Metadata["recommended_transport"] != "tcp_tls" || dec.Actions[0].Metadata["network_extension_runtime_used"] != false {
		t.Fatalf("action metadata = %#v, want TCP/TLS recommendation without runtime claim", dec.Actions[0].Metadata)
	}
}

func TestSaaSCatalogWildcardDoesNotMatchApexOrLookalikeDomain(t *testing.T) {
	bundle := model.PolicyBundle{
		ID:       "pb_lab_20260522_001",
		TenantID: "tenant_lab_001",
		SaaSCatalog: []model.SaaSCatalogEntry{
			{
				TenantID:          "tenant_lab_001",
				SaaSApplicationID: "saas_github",
				Provider:          "github",
				DomainPatterns:    []string{"*.github.com"},
			},
		},
	}
	for _, fqdn := range []string{"github.com", "evilgithub.com", "github.com.evil.example"} {
		if ctx, ok := SaaSContextForRequest(bundle, model.DecisionRequest{FQDN: fqdn}); ok {
			t.Fatalf("fqdn %q matched context %#v, want no match", fqdn, ctx)
		}
	}
	ctx, ok := SaaSContextForRequest(bundle, model.DecisionRequest{SNI: "api.github.com"})
	if !ok {
		t.Fatal("api.github.com did not match wildcard catalog")
	}
	if ctx.MatchType != "sni_wildcard" || ctx.MatchedPattern != "*.github.com" {
		t.Fatalf("context = %#v, want sni wildcard match", ctx)
	}
}

func TestEvaluateDeniesRequestWithoutPolicyMatch(t *testing.T) {
	ev := testEvaluator()
	dec := ev.Evaluate(model.DecisionRequest{
		TenantID:      "tenant_lab_001",
		ActorType:     "human",
		ApplicationID: "app_unknown",
		ServiceFamily: "https",
	})

	if dec.Decision != "deny" {
		t.Fatalf("decision = %q, want deny", dec.Decision)
	}
	if !contains(dec.ReasonCodes, "no_policy_match") {
		t.Fatalf("reason_codes = %v, want no_policy_match", dec.ReasonCodes)
	}
}

// Policy Learning was removed on 2026-08-05: East-West already carries the observe → partial → full ramp,
// with a Console banner that drives it, and the tenant-wide learning mode duplicated that while deferring
// Default Deny with no page to see it on. These replace the tests that pinned the deferral.

// An unmatched request is DENIED. There is no longer a mode that rewrites this verdict into "observe".
func TestUnmatchedRequestIsDeniedNotObserved(t *testing.T) {
	evaluator := testEvaluatorWithPolicies(nil)
	dec := evaluator.Evaluate(model.DecisionRequest{
		TenantID:      "tenant_lab_001",
		ActorType:     "human",
		ApplicationID: "app_not_in_policy",
		ServiceFamily: "https",
	})
	if dec.Decision != "deny" {
		t.Fatalf("decision = %q, want deny — nothing may defer Default Deny any more", dec.Decision)
	}
	if !contains(dec.ReasonCodes, "no_policy_match") {
		t.Fatalf("reason_codes = %v, want no_policy_match", dec.ReasonCodes)
	}
	for _, gone := range []string{"policy_learning_mode_active", "default_deny_deferred", "default_deny_enforced"} {
		if contains(dec.ReasonCodes, gone) {
			t.Fatalf("reason_codes = %v, still carries the removed code %q", dec.ReasonCodes, gone)
		}
	}
	for _, gone := range []string{"policy_learning_stage", "policy_learning_next_stage", "default_deny_enforcement_mode"} {
		if _, ok := dec.Metadata[gone]; ok {
			t.Fatalf("metadata still carries the removed key %q", gone)
		}
	}
	if !IsDefaultDeny(dec) {
		t.Fatalf("IsDefaultDeny = false for an unmatched request; callers use it to find gaps in the policy set")
	}
}

// The distinction the old "observe" decision used to make implicitly, now explicit: a deny an operator WROTE
// is not the catch-all. Callers that record adoptable candidates must not propose the destination an operator
// deliberately refused.
func TestExplicitDenyIsNotADefaultDeny(t *testing.T) {
	evaluator := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:       "pol_https_deny_001",
			TenantID: "tenant_lab_001",
			Priority: 100,
			Conditions: map[string]any{
				"actor_type":     "human",
				"application_id": "app_dummy_https",
				"service_family": "https",
			},
			Action: model.PolicyAction{Decision: "deny"},
			Status: "active",
		},
	})
	dec := evaluator.Evaluate(model.DecisionRequest{
		TenantID:      "tenant_lab_001",
		ActorType:     "human",
		ApplicationID: "app_dummy_https",
		ServiceFamily: "https",
	})
	if dec.Decision != "deny" {
		t.Fatalf("decision = %q, want explicit deny", dec.Decision)
	}
	if dec.PolicyID != "pol_https_deny_001" {
		t.Fatalf("policy_id = %q, want the explicit deny policy", dec.PolicyID)
	}
	if IsDefaultDeny(dec) {
		t.Fatalf("IsDefaultDeny = true for a rule-authored deny — the two must not read the same")
	}
}

// An allow is never a default deny.
func TestAllowIsNotADefaultDeny(t *testing.T) {
	ev := testEvaluator()
	dec := ev.Evaluate(model.DecisionRequest{
		TenantID:      "tenant_lab_001",
		ActorType:     "human",
		ApplicationID: "app_dummy_https",
		ServiceFamily: "https",
	})
	if dec.Decision == "deny" {
		t.Skip("fixture evaluator denied; this case only covers the allow path")
	}
	if IsDefaultDeny(dec) {
		t.Fatalf("IsDefaultDeny = true for decision %q", dec.Decision)
	}
}

func TestEvaluateUsesPriorityAndDenyTieBreaker(t *testing.T) {
	ev := testEvaluator()
	denyPolicy := ev.Policies[0]
	denyPolicy.ID = "pol_https_deny_001"
	denyPolicy.Action.Decision = "deny"
	denyPolicy.Priority = 100
	ev.Policies = append(ev.Policies, denyPolicy)

	dec := ev.Evaluate(model.DecisionRequest{
		TenantID:      "tenant_lab_001",
		ActorType:     "human",
		ApplicationID: "app_dummy_https",
		ServiceFamily: "https",
	})

	if dec.Decision != "deny" {
		t.Fatalf("decision = %q, want deny", dec.Decision)
	}
	if dec.PolicyID != "pol_https_deny_001" {
		t.Fatalf("policy_id = %q, want pol_https_deny_001", dec.PolicyID)
	}
	if !contains(dec.ReasonCodes, "application_denied") {
		t.Fatalf("reason_codes = %v, want application_denied", dec.ReasonCodes)
	}
}

func TestEvaluateSupportsConditionDSL(t *testing.T) {
	ev := testEvaluator()
	ev.Policies[0].Conditions = map[string]any{
		"actor_type": map[string]any{
			"op":    "eq",
			"value": "human",
		},
		"destination_port": map[string]any{
			"op":     "in",
			"values": []any{8443, 9443},
		},
		"user_groups": map[string]any{
			"op":    "contains",
			"value": "security-admins",
		},
	}

	dec := ev.Evaluate(model.DecisionRequest{
		TenantID:        "tenant_lab_001",
		ActorType:       "human",
		UserGroups:      []string{"security-admins", "it-admins"},
		ApplicationID:   "app_dummy_https",
		DestinationPort: 8443,
		ServiceFamily:   "https",
	})

	if dec.Decision != "allow" {
		t.Fatalf("decision = %q, want allow", dec.Decision)
	}
	if len(dec.MatchedConditions) != 3 {
		t.Fatalf("matched_conditions length = %d, want 3", len(dec.MatchedConditions))
	}
	if dec.MatchedConditions[0] != "actor_type" {
		t.Fatalf("matched_conditions = %v, want sorted keys", dec.MatchedConditions)
	}
}

func TestEvaluateContainsUsesExactMemberMatch(t *testing.T) {
	ev := testEvaluator()
	ev.Policies[0].Conditions = map[string]any{
		"user_groups": map[string]any{
			"op":    "contains",
			"value": "admin",
		},
	}

	dec := ev.Evaluate(model.DecisionRequest{
		TenantID:      "tenant_lab_001",
		ActorType:     "human",
		UserGroups:    []string{"/security-admins"},
		ApplicationID: "app_dummy_https",
		ServiceFamily: "https",
	})

	if dec.Decision != "deny" {
		t.Fatalf("decision = %q, want deny because contains is exact membership", dec.Decision)
	}
	if !contains(dec.ReasonCodes, "no_policy_match") {
		t.Fatalf("reason_codes = %v, want no_policy_match", dec.ReasonCodes)
	}
}

func TestEvaluateSupportsAuthContextConditions(t *testing.T) {
	evaluator := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:       "pol_mfa_allow_001",
			TenantID: "tenant_lab_001",
			Priority: 100,
			Conditions: map[string]any{
				"actor_type":     "human",
				"application_id": "app_dummy_https",
				"service_family": "https",
				"mfa_state":      "fresh",
				"amr": map[string]any{
					"op":    "contains",
					"value": "otp",
				},
			},
			Action: model.PolicyAction{Decision: "allow"},
			Status: "active",
		},
	})

	dec := evaluator.Evaluate(model.DecisionRequest{
		TenantID:              "tenant_lab_001",
		SessionID:             "sess_lab_001",
		AuthenticationEventID: "auth_lab_001",
		UserID:                "user_lab_001",
		ActorType:             "human",
		ApplicationID:         "app_dummy_https",
		ServiceFamily:         "https",
		MFAState:              "fresh",
		AMR:                   []string{"pwd", "otp"},
	})

	if dec.Decision != "allow" {
		t.Fatalf("decision = %q, want allow", dec.Decision)
	}
	if dec.AuthenticationEventID == nil || *dec.AuthenticationEventID != "auth_lab_001" {
		t.Fatalf("authentication_event_id = %v", dec.AuthenticationEventID)
	}
	if dec.Metadata["mfa_state"] != "fresh" {
		t.Fatalf("metadata mfa_state = %v", dec.Metadata["mfa_state"])
	}
}

func TestEvaluateSupportsAuthFreshnessCondition(t *testing.T) {
	evaluator := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:       "pol_recent_mfa_allow_001",
			TenantID: "tenant_lab_001",
			Priority: 100,
			Conditions: map[string]any{
				"actor_type":     "human",
				"application_id": "app_dummy_https",
				"service_family": "https",
				"mfa_state":      "fresh",
				"auth_age_seconds": map[string]any{
					"op":    "lte",
					"value": 900,
				},
			},
			Action: model.PolicyAction{Decision: "allow"},
			Status: "active",
		},
	})

	fresh := evaluator.Evaluate(model.DecisionRequest{
		TenantID:      "tenant_lab_001",
		ActorType:     "human",
		ApplicationID: "app_dummy_https",
		ServiceFamily: "https",
		MFAState:      "fresh",
		AuthTime:      time.Now().UTC().Add(-5 * time.Minute).Format(time.RFC3339),
	})
	if fresh.Decision != "allow" {
		t.Fatalf("fresh decision = %q, want allow", fresh.Decision)
	}
	if !contains(fresh.MatchedConditions, "auth_age_seconds") {
		t.Fatalf("matched_conditions = %v, want auth_age_seconds", fresh.MatchedConditions)
	}

	stale := evaluator.Evaluate(model.DecisionRequest{
		TenantID:      "tenant_lab_001",
		ActorType:     "human",
		ApplicationID: "app_dummy_https",
		ServiceFamily: "https",
		MFAState:      "fresh",
		AuthTime:      time.Now().UTC().Add(-30 * time.Minute).Format(time.RFC3339),
	})
	if stale.Decision != "deny" {
		t.Fatalf("stale decision = %q, want deny", stale.Decision)
	}
	if !contains(stale.ReasonCodes, "no_policy_match") {
		t.Fatalf("stale reason_codes = %v, want no_policy_match", stale.ReasonCodes)
	}
}

func TestEvaluateRequiresReauthenticationForStaleSSHSession(t *testing.T) {
	evaluator := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:       "pol_ssh_reauth_required_001",
			TenantID: "tenant_lab_001",
			Priority: 50,
			Conditions: map[string]any{
				"actor_type":     "human",
				"application_id": "app_dummy_ssh",
				"service_family": "ssh",
				"auth_age_seconds": map[string]any{
					"op":    "gte",
					"value": 901,
				},
			},
			Action: model.PolicyAction{Decision: "require_reauthentication"},
			Status: "active",
			Metadata: map[string]any{
				"reauth_interval_seconds": 900,
			},
		},
		{
			ID:       "pol_ssh_allow_001",
			TenantID: "tenant_lab_001",
			Priority: 100,
			Conditions: map[string]any{
				"actor_type":     "human",
				"application_id": "app_dummy_ssh",
				"service_family": "ssh",
			},
			Action: model.PolicyAction{Decision: "allow"},
			Status: "active",
		},
	})

	dec := evaluator.Evaluate(model.DecisionRequest{
		TenantID:        "tenant_lab_001",
		SessionID:       "sess_lab_ssh_001",
		UserID:          "user_lab_001",
		ActorType:       "human",
		ApplicationID:   "app_dummy_ssh",
		DestinationPort: 22,
		Protocol:        "tcp",
		ServiceFamily:   "ssh",
		AuthTime:        time.Now().Add(-20 * time.Minute).UTC().Format(time.RFC3339),
	})

	if dec.Decision != "require_reauthentication" {
		t.Fatalf("decision = %q, want require_reauthentication", dec.Decision)
	}
	if dec.PolicyID != "pol_ssh_reauth_required_001" {
		t.Fatalf("policy_id = %q, want pol_ssh_reauth_required_001", dec.PolicyID)
	}
	if !contains(dec.ReasonCodes, "reauthentication_required") {
		t.Fatalf("reason_codes = %v, want reauthentication_required", dec.ReasonCodes)
	}
	if len(dec.Actions) != 1 || dec.Actions[0].Type != "prompt_reauthentication" {
		t.Fatalf("actions = %#v, want prompt_reauthentication", dec.Actions)
	}
	if dec.Actions[0].Target == nil || *dec.Actions[0].Target != "app_dummy_ssh" {
		t.Fatalf("action target = %#v, want app_dummy_ssh", dec.Actions[0].Target)
	}
	if dec.Actions[0].TTLSeconds == nil || *dec.Actions[0].TTLSeconds != 900 {
		t.Fatalf("action ttl = %#v, want 900", dec.Actions[0].TTLSeconds)
	}
}

func TestEvaluateSupportsCIDRAndDeviceTrustConditions(t *testing.T) {
	evaluator := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:       "pol_trusted_device_cidr_allow_001",
			TenantID: "tenant_lab_001",
			Priority: 100,
			Conditions: map[string]any{
				"actor_type":         "human",
				"application_id":     "app_dummy_https",
				"service_family":     "https",
				"device_trust_level": "managed",
				"source_ip": map[string]any{
					"op":    "cidr_contains",
					"value": "10.10.0.0/16",
				},
			},
			Action: model.PolicyAction{Decision: "allow"},
			Status: "active",
		},
	})

	allow := evaluator.Evaluate(model.DecisionRequest{
		TenantID:         "tenant_lab_001",
		ActorType:        "human",
		ApplicationID:    "app_dummy_https",
		ServiceFamily:    "https",
		SourceIP:         "10.10.20.30",
		DeviceTrustLevel: "managed",
	})
	if allow.Decision != "allow" {
		t.Fatalf("decision = %q, want allow", allow.Decision)
	}
	if !contains(allow.MatchedConditions, "source_ip") || !contains(allow.MatchedConditions, "device_trust_level") {
		t.Fatalf("matched_conditions = %v, want source_ip and device_trust_level", allow.MatchedConditions)
	}
	if allow.Metadata["device_trust_level"] != "managed" {
		t.Fatalf("metadata device_trust_level = %v", allow.Metadata["device_trust_level"])
	}

	deny := evaluator.Evaluate(model.DecisionRequest{
		TenantID:         "tenant_lab_001",
		ActorType:        "human",
		ApplicationID:    "app_dummy_https",
		ServiceFamily:    "https",
		SourceIP:         "192.168.100.10",
		DeviceTrustLevel: "managed",
	})
	if deny.Decision != "deny" {
		t.Fatalf("decision = %q, want deny", deny.Decision)
	}
}

func TestEvaluateCIDRConditionMasksHostBits(t *testing.T) {
	evaluator := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:       "pol_unmasked_cidr_allow_001",
			TenantID: "tenant_lab_001",
			Priority: 100,
			Conditions: map[string]any{
				"actor_type":     "human",
				"application_id": "app_dummy_https",
				"service_family": "https",
				"source_ip": map[string]any{
					"op":    "cidr_contains",
					"value": "10.10.1.0/16",
				},
			},
			Action: model.PolicyAction{Decision: "allow"},
			Status: "active",
		},
	})

	dec := evaluator.Evaluate(model.DecisionRequest{
		TenantID:      "tenant_lab_001",
		ActorType:     "human",
		ApplicationID: "app_dummy_https",
		ServiceFamily: "https",
		SourceIP:      "10.10.20.30",
	})
	if dec.Decision != "allow" {
		t.Fatalf("decision = %q, want allow", dec.Decision)
	}
}

func TestEvaluateSupportsDelegatedAgentToolConditions(t *testing.T) {
	evaluator := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:       "pol_nhi_tool_allow_001",
			TenantID: "tenant_lab_001",
			Priority: 80,
			Conditions: map[string]any{
				"actor_type":                   "delegated_agent",
				"actor_nhi_id":                 "nhi_soc_agent_001",
				"delegated_access_grant_id":    "dag_lab_001",
				"tool_id":                      "tool_ticket_create_001",
				"tool_action_type":             "ticket:create",
				"tool_permission_profile":      "write_ticket_only",
				"tool_signature_state":         "signed",
				"mcp_server_id":                "mcp_soc_lab_001",
				"mcp_token_passthrough_policy": "blocked",
				"runtime_environment_id":       "runtime_managed_cloud_lab_001",
				"human_approval_event_id":      "hae_lab_001",
				"data_classification":          "confidential",
			},
			Action:                      model.PolicyAction{Decision: "allow"},
			RequiredTokenBinding:        true,
			RequiredHumanApproval:       true,
			RequiredWorkloadAttestation: true,
			Status:                      "active",
		},
	})

	dec := evaluator.Evaluate(model.DecisionRequest{
		TenantID:                  "tenant_lab_001",
		UserID:                    "user_lab_001",
		SubjectUserID:             "user_lab_001",
		ActorType:                 "delegated_agent",
		ActorNHIID:                "nhi_soc_agent_001",
		DelegatedAccessGrantID:    "dag_lab_001",
		AgentTaskSessionID:        "ats_lab_001",
		ToolID:                    "tool_ticket_create_001",
		ToolActionType:            "ticket:create",
		ToolPermissionProfile:     "write_ticket_only",
		ToolVersion:               "0.1.0",
		ToolSignatureState:        "signed",
		MCPServerID:               "mcp_soc_lab_001",
		MCPResourceURI:            "https://mcp.local/soc",
		MCPAudience:               "https://mcp.local/soc",
		MCPTokenPassthroughPolicy: "blocked",
		RuntimeEnvironmentID:      "runtime_managed_cloud_lab_001",
		ContextBoundaryID:         "ctx_incident_lab_001",
		DataClassification:        "confidential",
		HumanApprovalEventID:      "hae_lab_001",
		ApplicationID:             "app_dummy_https",
		Destination:               "mcp.local:443",
		DestinationPort:           443,
		Protocol:                  "tcp",
		FQDN:                      "mcp.local",
		SNI:                       "mcp.local",
		ServiceFamily:             "https",
		DestinationRole:           "mcp_server",
		WorkloadAttestationState:  "verified",
	})

	if dec.Decision != "allow" {
		t.Fatalf("decision = %q, want allow", dec.Decision)
	}
	if dec.ActorNHIID == nil || *dec.ActorNHIID != "nhi_soc_agent_001" {
		t.Fatalf("actor_nhi_id = %#v", dec.ActorNHIID)
	}
	if dec.ToolID == nil || *dec.ToolID != "tool_ticket_create_001" {
		t.Fatalf("tool_id = %#v", dec.ToolID)
	}
	if dec.HumanApprovalEventID == nil || *dec.HumanApprovalEventID != "hae_lab_001" {
		t.Fatalf("human_approval_event_id = %#v", dec.HumanApprovalEventID)
	}
	if dec.TokenBindingState == nil || *dec.TokenBindingState != "required" {
		t.Fatalf("token_binding_state = %#v, want required", dec.TokenBindingState)
	}
	if dec.WorkloadAttestationState == nil || *dec.WorkloadAttestationState != "verified" {
		t.Fatalf("workload_attestation_state = %#v, want verified", dec.WorkloadAttestationState)
	}
	for _, code := range []string{"delegated_grant_valid", "scope_allowed", "approval_valid", "tool_allowed"} {
		if !contains(dec.ReasonCodes, code) {
			t.Fatalf("reason_codes = %v, want %s", dec.ReasonCodes, code)
		}
	}
	if dec.Metadata["actor_nhi_id"] != "nhi_soc_agent_001" || dec.Metadata["tool_action_type"] != "ticket:create" {
		t.Fatalf("metadata = %#v", dec.Metadata)
	}
	if dec.MCPServerID == nil || *dec.MCPServerID != "mcp_soc_lab_001" || dec.RuntimeEnvironmentID == nil || *dec.RuntimeEnvironmentID != "runtime_managed_cloud_lab_001" {
		t.Fatalf("tool/mcp ids = mcp:%#v runtime:%#v", dec.MCPServerID, dec.RuntimeEnvironmentID)
	}
	if dec.Metadata["tool_permission_profile"] != "write_ticket_only" || dec.Metadata["mcp_token_passthrough_policy"] != "blocked" || dec.Metadata["tool_payload_recorded"] != false || dec.Metadata["tool_secret_recorded"] != false || dec.Metadata["tool_credentials_recorded"] != false {
		t.Fatalf("tool/mcp metadata = %#v", dec.Metadata)
	}
	accessLog := AccessLogFromDecision(dec)
	if accessLog.ToolID == nil || *accessLog.ToolID != "tool_ticket_create_001" || accessLog.MCPServerID == nil || *accessLog.MCPServerID != "mcp_soc_lab_001" || accessLog.RuntimeEnvironmentID == nil || *accessLog.RuntimeEnvironmentID != "runtime_managed_cloud_lab_001" {
		t.Fatalf("access log tool/mcp top-level fields = %#v", accessLog)
	}
	trace := DecisionTraceFromDecision(dec)
	if trace.Metadata["mcp_server_id"] != "mcp_soc_lab_001" || trace.Metadata["agent_tool_metadata_scope"] != "metadata_only" || trace.Metadata["mcp_metadata_scope"] != "metadata_only" || trace.Metadata["tool_payload_recorded"] != false {
		t.Fatalf("trace metadata = %#v, want non-secret tool/mcp evidence", trace.Metadata)
	}
}

func TestEvaluateRequiresHumanApprovalForDelegatedPolicy(t *testing.T) {
	evaluator := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:       "pol_nhi_tool_human_approval_001",
			TenantID: "tenant_lab_001",
			Priority: 80,
			Conditions: map[string]any{
				"actor_type":                "delegated_agent",
				"actor_nhi_id":              "nhi_soc_agent_001",
				"delegated_access_grant_id": "dag_lab_001",
				"tool_id":                   "tool_ticket_create_001",
				"tool_action_type":          "ticket:create",
				"data_classification":       "confidential",
			},
			Action:                model.PolicyAction{Decision: "allow"},
			RequiredHumanApproval: true,
			Metadata: map[string]any{
				"human_approval_ttl_seconds": 600,
			},
			Status: "active",
		},
	})

	req := model.DecisionRequest{
		TenantID:               "tenant_lab_001",
		UserID:                 "user_lab_001",
		SubjectUserID:          "user_lab_001",
		ActorType:              "delegated_agent",
		ActorNHIID:             "nhi_soc_agent_001",
		DelegatedAccessGrantID: "dag_lab_001",
		AgentTaskSessionID:     "ats_lab_001",
		ToolID:                 "tool_ticket_create_001",
		ToolActionType:         "ticket:create",
		DataClassification:     "confidential",
		ApplicationID:          "app_recovery_console",
		ServiceFamily:          "https",
	}

	missingApproval := evaluator.Evaluate(req)
	if missingApproval.Decision != "require_human_approval" {
		t.Fatalf("decision = %q, want require_human_approval", missingApproval.Decision)
	}
	if missingApproval.HumanApprovalEventID != nil && *missingApproval.HumanApprovalEventID != "" {
		t.Fatalf("human_approval_event_id = %#v, want empty", missingApproval.HumanApprovalEventID)
	}
	for _, code := range []string{"policy_matched", "human_approval_required", "approval_absent"} {
		if !contains(missingApproval.ReasonCodes, code) {
			t.Fatalf("reason_codes = %v, want %s", missingApproval.ReasonCodes, code)
		}
	}
	if len(missingApproval.Actions) != 1 || missingApproval.Actions[0].Type != "request_human_approval" {
		t.Fatalf("actions = %#v, want request_human_approval", missingApproval.Actions)
	}
	action := missingApproval.Actions[0]
	if action.Target == nil || *action.Target != "app_recovery_console" || action.TTLSeconds == nil || *action.TTLSeconds != 600 {
		t.Fatalf("action target/ttl = %#v, want app_recovery_console ttl 600", action)
	}
	if action.Metadata["actor_nhi_id"] != "nhi_soc_agent_001" || action.Metadata["delegated_access_grant_id"] != "dag_lab_001" || action.Metadata["tool_id"] != "tool_ticket_create_001" || action.Metadata["tool_payload_recorded"] != false || action.Metadata["tool_secret_recorded"] != false || action.Metadata["tool_credentials_recorded"] != false {
		t.Fatalf("action metadata = %#v, want non-secret delegated approval metadata", action.Metadata)
	}
	if missingApproval.Metadata["human_approval_required"] != true || missingApproval.Metadata["human_approval_request_scope"] != "metadata_only" {
		t.Fatalf("decision metadata = %#v, want human approval metadata-only scope", missingApproval.Metadata)
	}

	req.HumanApprovalEventID = "hae_lab_001"
	approved := evaluator.Evaluate(req)
	if approved.Decision != "allow" {
		t.Fatalf("approved decision = %q, want allow", approved.Decision)
	}
	if approved.HumanApprovalEventID == nil || *approved.HumanApprovalEventID != "hae_lab_001" {
		t.Fatalf("approved human_approval_event_id = %#v", approved.HumanApprovalEventID)
	}
	if !contains(approved.ReasonCodes, "approval_valid") {
		t.Fatalf("approved reason_codes = %v, want approval_valid", approved.ReasonCodes)
	}
}

func TestEvaluateRequiresTrustedBoundFreshHumanApprovalEvent(t *testing.T) {
	evaluator := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:       "pol_nhi_tool_human_approval_trust_001",
			TenantID: "tenant_lab_001",
			Priority: 80,
			Conditions: map[string]any{
				"actor_type":                "delegated_agent",
				"actor_nhi_id":              "nhi_soc_agent_001",
				"delegated_access_grant_id": "dag_lab_001",
				"tool_id":                   "tool_ticket_create_001",
				"tool_action_type":          "ticket:create",
			},
			Action:                model.PolicyAction{Decision: "allow"},
			RequiredHumanApproval: true,
			Metadata: map[string]any{
				"human_approval_event_contract": "trust_binding_freshness",
			},
			Status: "active",
		},
	})
	baseReq := model.DecisionRequest{
		TenantID:                         "tenant_lab_001",
		UserID:                           "user_lab_001",
		SubjectUserID:                    "user_lab_001",
		ActorType:                        "delegated_agent",
		ActorNHIID:                       "nhi_soc_agent_001",
		DelegatedAccessGrantID:           "dag_lab_001",
		AgentTaskSessionID:               "ats_lab_001",
		ToolID:                           "tool_ticket_create_001",
		ToolActionType:                   "ticket:create",
		ApplicationID:                    "app_recovery_console",
		ServiceFamily:                    "https",
		HumanApprovalEventID:             "hae_lab_001",
		HumanApprovalEventTrustState:     "trusted",
		HumanApprovalEventBindingState:   "bound",
		HumanApprovalEventFreshnessState: "fresh",
	}

	tests := []struct {
		name       string
		mutate     func(*model.DecisionRequest)
		reasonCode string
	}{
		{
			name: "untrusted",
			mutate: func(req *model.DecisionRequest) {
				req.HumanApprovalEventTrustState = "untrusted"
			},
			reasonCode: "approval_untrusted",
		},
		{
			name: "unbound",
			mutate: func(req *model.DecisionRequest) {
				req.HumanApprovalEventBindingState = "mismatch"
			},
			reasonCode: "approval_unbound",
		},
		{
			name: "not fresh",
			mutate: func(req *model.DecisionRequest) {
				req.HumanApprovalEventFreshnessState = "stale"
			},
			reasonCode: "approval_not_fresh",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := baseReq
			tt.mutate(&req)
			dec := evaluator.Evaluate(req)
			if dec.Decision != "require_human_approval" {
				t.Fatalf("decision = %q, want require_human_approval", dec.Decision)
			}
			for _, code := range []string{"policy_matched", "human_approval_required", tt.reasonCode} {
				if !contains(dec.ReasonCodes, code) {
					t.Fatalf("reason_codes = %v, want %s", dec.ReasonCodes, code)
				}
			}
			if len(dec.Actions) != 1 || dec.Actions[0].Type != "request_human_approval" {
				t.Fatalf("actions = %#v, want request_human_approval", dec.Actions)
			}
			if dec.Metadata["human_approval_event_contract"] != "trust_binding_freshness" || dec.Metadata["human_approval_event_contract_result"] != "invalid" {
				t.Fatalf("metadata = %#v, want invalid trust/binding/freshness contract", dec.Metadata)
			}
			if dec.Actions[0].Metadata["tool_payload_recorded"] != false || dec.Actions[0].Metadata["tool_secret_recorded"] != false || dec.Actions[0].Metadata["tool_credentials_recorded"] != false {
				t.Fatalf("action metadata = %#v, want metadata-only request", dec.Actions[0].Metadata)
			}
		})
	}

	approved := evaluator.Evaluate(baseReq)
	if approved.Decision != "allow" {
		t.Fatalf("approved decision = %q, want allow", approved.Decision)
	}
	if !contains(approved.ReasonCodes, "approval_valid") {
		t.Fatalf("approved reason_codes = %v, want approval_valid", approved.ReasonCodes)
	}
	if approved.Metadata["human_approval_event_contract"] != "trust_binding_freshness" || approved.Metadata["human_approval_event_contract_result"] != "valid" {
		t.Fatalf("approved metadata = %#v, want valid trust/binding/freshness contract", approved.Metadata)
	}
	if hasDecisionAction(approved.Actions, "request_human_approval") {
		t.Fatalf("approved actions = %#v, did not expect request_human_approval", approved.Actions)
	}

	boolMetadataEvaluator := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:       "pol_nhi_tool_human_approval_trust_bool_001",
			TenantID: "tenant_lab_001",
			Priority: 80,
			Conditions: map[string]any{
				"actor_type":                "delegated_agent",
				"actor_nhi_id":              "nhi_soc_agent_001",
				"delegated_access_grant_id": "dag_lab_001",
				"tool_id":                   "tool_ticket_create_001",
				"tool_action_type":          "ticket:create",
			},
			Action:                model.PolicyAction{Decision: "allow"},
			RequiredHumanApproval: true,
			Metadata: map[string]any{
				"human_approval_event_require_trusted_binding_freshness": true,
			},
			Status: "active",
		},
	})
	boolMetadataReq := baseReq
	boolMetadataReq.HumanApprovalEventBindingState = ""
	boolMetadataDecision := boolMetadataEvaluator.Evaluate(boolMetadataReq)
	if boolMetadataDecision.Decision != "require_human_approval" || !contains(boolMetadataDecision.ReasonCodes, "approval_unbound") {
		t.Fatalf("bool metadata decision = %q reason_codes=%v, want approval_unbound requirement", boolMetadataDecision.Decision, boolMetadataDecision.ReasonCodes)
	}
}

func TestEvaluateRequiresWorkloadAttestationForDelegatedPolicy(t *testing.T) {
	evaluator := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:       "pol_nhi_attestation_required_001",
			TenantID: "tenant_lab_001",
			Priority: 80,
			Conditions: map[string]any{
				"actor_type":   "delegated_agent",
				"actor_nhi_id": "nhi_soc_agent_001",
				"tool_id":      "tool_ticket_create_001",
			},
			Action:                      model.PolicyAction{Decision: "allow"},
			RequiredWorkloadAttestation: true,
			Status:                      "active",
		},
	})

	missing := evaluator.Evaluate(model.DecisionRequest{
		TenantID:      "tenant_lab_001",
		ActorType:     "delegated_agent",
		ActorNHIID:    "nhi_soc_agent_001",
		ToolID:        "tool_ticket_create_001",
		ApplicationID: "app_dummy_https",
		ServiceFamily: "https",
	})
	if missing.Decision != "require_workload_attestation" {
		t.Fatalf("missing decision = %q, want require_workload_attestation", missing.Decision)
	}
	if missing.WorkloadAttestationState == nil || *missing.WorkloadAttestationState != "required" {
		t.Fatalf("missing workload_attestation_state = %#v, want required", missing.WorkloadAttestationState)
	}
	if len(missing.Actions) != 1 || missing.Actions[0].Type != "request_workload_attestation" {
		t.Fatalf("missing actions = %#v, want request_workload_attestation", missing.Actions)
	}

	verified := evaluator.Evaluate(model.DecisionRequest{
		TenantID:                 "tenant_lab_001",
		ActorType:                "delegated_agent",
		ActorNHIID:               "nhi_soc_agent_001",
		ToolID:                   "tool_ticket_create_001",
		ApplicationID:            "app_dummy_https",
		ServiceFamily:            "https",
		WorkloadAttestationState: "verified",
	})
	if verified.Decision != "allow" {
		t.Fatalf("verified decision = %q, want allow", verified.Decision)
	}
	if verified.WorkloadAttestationState == nil || *verified.WorkloadAttestationState != "verified" {
		t.Fatalf("verified workload_attestation_state = %#v, want verified", verified.WorkloadAttestationState)
	}
}

func TestEvaluatePrioritizesWorkloadAttestationBeforeHumanApproval(t *testing.T) {
	evaluator := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:       "pol_nhi_attestation_and_approval_001",
			TenantID: "tenant_lab_001",
			Priority: 80,
			Conditions: map[string]any{
				"actor_type":   "delegated_agent",
				"actor_nhi_id": "nhi_soc_agent_001",
				"tool_id":      "tool_ticket_create_001",
			},
			Action:                      model.PolicyAction{Decision: "allow"},
			RequiredHumanApproval:       true,
			RequiredWorkloadAttestation: true,
			Status:                      "active",
		},
	})

	dec := evaluator.Evaluate(model.DecisionRequest{
		TenantID:      "tenant_lab_001",
		ActorType:     "delegated_agent",
		ActorNHIID:    "nhi_soc_agent_001",
		ToolID:        "tool_ticket_create_001",
		ApplicationID: "app_dummy_https",
		ServiceFamily: "https",
	})
	if dec.Decision != "require_workload_attestation" {
		t.Fatalf("decision = %q, want require_workload_attestation", dec.Decision)
	}
	if contains(dec.ReasonCodes, "human_approval_required") {
		t.Fatalf("reason_codes = %v, did not expect human approval before attestation", dec.ReasonCodes)
	}
	if !hasDecisionAction(dec.Actions, "request_workload_attestation") || hasDecisionAction(dec.Actions, "request_human_approval") {
		t.Fatalf("actions = %#v, want workload attestation only", dec.Actions)
	}
}

func TestEvaluateSupportsBreakGlassAuthMethodCondition(t *testing.T) {
	identityID := "bg_identity_lab_001"
	maxSessionSeconds := 900
	evaluator := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:                           "pol_break_glass_allow_001",
			TenantID:                     "tenant_lab_001",
			Priority:                     100,
			BreakGlassPolicy:             true,
			BreakGlassIdentityID:         &identityID,
			BreakGlassMaxSessionSeconds:  &maxSessionSeconds,
			BreakGlassStrongAuthRequired: true,
			BreakGlassAuditRequired:      true,
			Conditions: map[string]any{
				"actor_type":     "human",
				"application_id": "app_recovery_console",
				"service_family": "https",
				"auth_method":    "break_glass",
			},
			Action: model.PolicyAction{Decision: "allow"},
			Status: "active",
		},
	})

	dec := evaluator.Evaluate(model.DecisionRequest{
		TenantID:                  "tenant_lab_001",
		ActorType:                 "human",
		ApplicationID:             "app_recovery_console",
		ServiceFamily:             "https",
		AuthMethod:                "break_glass",
		AuthTime:                  time.Now().UTC().Add(-2 * time.Minute).Format(time.RFC3339),
		MFAState:                  "fresh",
		AMR:                       []string{"pwd", "otp", "break_glass"},
		BreakGlassRequestID:       "bgr_lab_001",
		BreakGlassReasonPresent:   true,
		BreakGlassTicketIDPresent: true,
	})
	if dec.Decision != "allow" {
		t.Fatalf("decision = %q, want allow", dec.Decision)
	}
	if dec.Metadata["auth_method"] != "break_glass" {
		t.Fatalf("metadata auth_method = %v", dec.Metadata["auth_method"])
	}
	if dec.Metadata["break_glass_identity_id"] != identityID || dec.Metadata["break_glass_max_session_seconds"] != maxSessionSeconds {
		t.Fatalf("break-glass metadata = %#v", dec.Metadata)
	}
	for _, code := range []string{"break_glass_policy_matched", "break_glass_short_ttl_valid", "break_glass_strong_auth_satisfied", "break_glass_audit_required"} {
		if !contains(dec.ReasonCodes, code) {
			t.Fatalf("reason_codes = %v, want %s", dec.ReasonCodes, code)
		}
	}
	if !hasDecisionAction(dec.Actions, "emit_audit_event") {
		t.Fatalf("actions = %#v, want break-glass audit event", dec.Actions)
	}
	trace := DecisionTraceFromDecision(dec)
	if trace.Metadata["break_glass_request_id"] != "bgr_lab_001" {
		t.Fatalf("trace metadata = %#v, want break_glass_request_id", trace.Metadata)
	}
}

func TestEvaluateBlocksBreakGlassPolicyWithoutRequiredSafeguards(t *testing.T) {
	evaluator := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:       "pol_break_glass_unsafe_001",
			TenantID: "tenant_lab_001",
			Priority: 100,
			Conditions: map[string]any{
				"actor_type":     "human",
				"application_id": "app_recovery_console",
				"service_family": "https",
				"auth_method":    "break_glass",
			},
			Action: model.PolicyAction{Decision: "allow"},
			Status: "active",
		},
	})

	dec := evaluator.Evaluate(model.DecisionRequest{
		TenantID:      "tenant_lab_001",
		ActorType:     "human",
		ApplicationID: "app_recovery_console",
		ServiceFamily: "https",
		AuthMethod:    "break_glass",
		AuthTime:      time.Now().UTC().Add(-2 * time.Minute).Format(time.RFC3339),
		MFAState:      "fresh",
		AMR:           []string{"pwd", "otp", "break_glass"},
	})
	if dec.Decision != "deny" {
		t.Fatalf("decision = %q, want deny", dec.Decision)
	}
	for _, code := range []string{"break_glass_policy_guard_failed", "break_glass_ttl_missing", "break_glass_strong_auth_requirement_missing", "break_glass_audit_requirement_missing"} {
		if !contains(dec.ReasonCodes, code) {
			t.Fatalf("reason_codes = %v, want %s", dec.ReasonCodes, code)
		}
	}
	if !hasDecisionAction(dec.Actions, "emit_audit_event") {
		t.Fatalf("actions = %#v, want audit event even for blocked break-glass policy", dec.Actions)
	}
}

func TestEvaluateRequiresFreshStrongBreakGlassAuthentication(t *testing.T) {
	identityID := "bg_identity_lab_001"
	maxSessionSeconds := 900
	evaluator := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:                           "pol_break_glass_allow_001",
			TenantID:                     "tenant_lab_001",
			Priority:                     100,
			BreakGlassPolicy:             true,
			BreakGlassIdentityID:         &identityID,
			BreakGlassMaxSessionSeconds:  &maxSessionSeconds,
			BreakGlassStrongAuthRequired: true,
			BreakGlassAuditRequired:      true,
			Conditions: map[string]any{
				"actor_type":     "human",
				"application_id": "app_recovery_console",
				"service_family": "https",
				"auth_method":    "break_glass",
			},
			Action: model.PolicyAction{Decision: "allow"},
			Status: "active",
		},
	})

	dec := evaluator.Evaluate(model.DecisionRequest{
		TenantID:      "tenant_lab_001",
		ActorType:     "human",
		ApplicationID: "app_recovery_console",
		ServiceFamily: "https",
		AuthMethod:    "break_glass",
		AuthTime:      time.Now().UTC().Add(-2 * time.Minute).Format(time.RFC3339),
		MFAState:      "stale",
		AMR:           []string{"pwd"},
	})
	if dec.Decision != "require_reauthentication" {
		t.Fatalf("decision = %q, want require_reauthentication", dec.Decision)
	}
	for _, code := range []string{"reauthentication_required", "break_glass_strong_auth_required"} {
		if !contains(dec.ReasonCodes, code) {
			t.Fatalf("reason_codes = %v, want %s", dec.ReasonCodes, code)
		}
	}
	if !hasDecisionAction(dec.Actions, "prompt_reauthentication") || !hasDecisionAction(dec.Actions, "emit_audit_event") {
		t.Fatalf("actions = %#v, want prompt_reauthentication and emit_audit_event", dec.Actions)
	}
}

func TestEvaluateUsesRandomDecisionAndLogIDs(t *testing.T) {
	evaluator := testEvaluator()
	seen := map[string]bool{}
	for i := 0; i < 256; i++ {
		dec := evaluator.Evaluate(model.DecisionRequest{
			TenantID:      "tenant_lab_001",
			ActorType:     "human",
			ApplicationID: "app_dummy_https",
			ServiceFamily: "https",
		})
		accessLog := AccessLogFromDecision(dec)
		trace := DecisionTraceFromDecision(dec)
		for _, id := range []string{dec.ID, accessLog.ID, trace.ID} {
			if seen[id] {
				t.Fatalf("duplicate id generated: %s", id)
			}
			seen[id] = true
		}
		if !strings.HasPrefix(dec.ID, "dec_") || !strings.HasPrefix(accessLog.ID, "alog_") || !strings.HasPrefix(trace.ID, "trace_") {
			t.Fatalf("unexpected id prefixes: %s %s %s", dec.ID, accessLog.ID, trace.ID)
		}
	}
}

func testEvaluator() Evaluator {
	return testEvaluatorWithPolicies([]model.Policy{
		{
			ID:       "pol_https_allow_001",
			TenantID: "tenant_lab_001",
			Priority: 100,
			Conditions: map[string]any{
				"actor_type":     "human",
				"application_id": "app_dummy_https",
				"service_family": "https",
			},
			Action: model.PolicyAction{
				Decision: "allow",
			},
			Status: "active",
		},
	})
}

func testTLSReadinessEvaluator(profileID string) Evaluator {
	inspectionProfileID := profileID
	ev := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:       "pol_tls_readiness_allow_001",
			TenantID: "tenant_lab_001",
			Priority: 100,
			Conditions: map[string]any{
				"actor_type":     "human",
				"application_id": "app_dummy_https",
			},
			Action:              model.PolicyAction{Decision: "allow"},
			InspectionProfileID: &inspectionProfileID,
			Status:              "active",
		},
	})
	ev.PolicyBundle.TenantRootCAs = []model.TenantRootCA{
		{
			ID:               "trca_lab_001",
			TenantID:         "tenant_lab_001",
			Name:             "Lab Tenant Root CA",
			Status:           "configured",
			DistributionMode: "mdm_or_browser_trust_store",
			TrustStoreTarget: "os_and_browser",
			PrivateKeyStatus: "not_recorded",
		},
	}
	ev.PolicyBundle.TrustProfiles = []model.TrustProfile{
		{
			ID:                       "tp_lab_managed_browser_001",
			TenantID:                 "tenant_lab_001",
			Name:                     "Managed browser trust profile",
			TenantRootCAID:           "trca_lab_001",
			TrustStoreState:          "planned",
			CertificatePinningPolicy: "bypass_required",
			Status:                   "active",
		},
	}
	ev.PolicyBundle.InspectionProfiles = []model.InspectionProfile{
		{
			ID:                         profileID,
			TenantID:                   "tenant_lab_001",
			Name:                       "TLS readiness metadata profile",
			InspectionMode:             "tls_readiness",
			TrustProfileID:             "tp_lab_managed_browser_001",
			TenantRootCAID:             "trca_lab_001",
			QUICPolicyMode:             "prefer_tcp_tls",
			QUICPolicyAction:           "tcp_tls_required",
			PayloadPolicy:              "metadata_only",
			CertificateIssuanceMode:    "not_issued",
			TLSInterceptionEnabled:     false,
			NetworkExtensionDependency: "none_policy_layer",
			Status:                     "active",
		},
	}
	return ev
}

func testEvaluatorWithPolicies(policies []model.Policy) Evaluator {
	return Evaluator{
		Policies: policies,
		PolicyBundle: model.PolicyBundle{
			ID:       "pb_lab_20260522_001",
			TenantID: "tenant_lab_001",
			Version:  "2026.05.22.001",
		},
		EdgeRegionID:  "local",
		EdgeClusterID: "local-edge-001",
	}
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func hasDecisionAction(actions []model.DecisionAction, expected string) bool {
	for _, action := range actions {
		if action.Type == expected {
			return true
		}
	}
	return false
}

// An egress rule authored for an IP LITERAL must match a steered flow to that address.
//
// The Console offers this shape directly — its "add a server" form suggests "10.0.0.10, 10.0.0.0/24, or
// db.example.com" — and such a rule compiles to an fqdn/sni condition. But a steered flow to a bare address
// carries it in Destination and leaves FQDN empty: DNS recovery only fills FQDN when the conntrack store has
// an answer, and a client that dialled an address never asked. So the rule was inert on exactly the traffic
// it was written for. Found on 2026-08-05 when a rule for the lab's own management address stayed denied with
// no_policy_match while /admin/effective-policy called the same rule the winner.
func TestEgressRuleForAnIPLiteralMatchesASteeredFlow(t *testing.T) {
	evaluator := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:       "pol_ip_literal_allow",
			TenantID: "tenant_lab_001",
			Priority: 100,
			Conditions: map[string]any{
				"fqdn":             "192.168.100.10",
				"destination_port": 8088,
			},
			Action: model.PolicyAction{Decision: "allow"},
			Status: "active",
		},
	})
	// The shape the steer-mux OPEN actually builds: Destination set, FQDN empty.
	dec := evaluator.Evaluate(model.DecisionRequest{
		TenantID:        "tenant_lab_001",
		ActorType:       "human",
		Destination:     "192.168.100.10",
		DestinationPort: 8088,
		Protocol:        "tcp",
	})
	if dec.Decision != "allow" {
		t.Fatalf("decision = %q (%v), want allow — a rule naming an IP must match a flow to that IP",
			dec.Decision, dec.ReasonCodes)
	}
	if dec.PolicyID != "pol_ip_literal_allow" {
		t.Fatalf("policy_id = %q, want pol_ip_literal_allow", dec.PolicyID)
	}
}

// The narrowing holds: a HOSTNAME rule is not loosened by the fallback, and a different IP does not match.
func TestIPLiteralFallbackDoesNotLoosenHostnameRules(t *testing.T) {
	evaluator := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:         "pol_hostname_allow",
			TenantID:   "tenant_lab_001",
			Priority:   100,
			Conditions: map[string]any{"fqdn": "db.example.com"},
			Action:     model.PolicyAction{Decision: "allow"},
			Status:     "active",
		},
		{
			ID:         "pol_other_ip_allow",
			TenantID:   "tenant_lab_001",
			Priority:   101,
			Conditions: map[string]any{"fqdn": "10.0.0.10"},
			Action:     model.PolicyAction{Decision: "allow"},
			Status:     "active",
		},
	})
	dec := evaluator.Evaluate(model.DecisionRequest{
		TenantID: "tenant_lab_001", ActorType: "human",
		Destination: "192.168.100.10", Protocol: "tcp",
	})
	if dec.Decision == "allow" {
		t.Fatalf("decision = allow via %q — an IP flow must not match a hostname rule or a different IP", dec.PolicyID)
	}
	if !IsDefaultDeny(dec) {
		t.Fatalf("expected a default deny, got %q / %v", dec.Decision, dec.ReasonCodes)
	}
}

// The other shape the Console's endpoint form offers — a RANGE. An endpoint authored as "10.20.0.0/24"
// compiles to the same fqdn condition as a single address, so before this it exact-compared a CIDR string
// against an IP and matched nothing: a rule for a subnet was inert for every host in it. Found by running the
// single-address fix and then asking whether the neighbouring case worked, instead of assuming it did.
func TestEgressRuleForACIDRMatchesAFlowInsideIt(t *testing.T) {
	evaluator := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:         "pol_cidr_allow",
			TenantID:   "tenant_lab_001",
			Priority:   100,
			Conditions: map[string]any{"fqdn": "10.20.0.0/24"},
			Action:     model.PolicyAction{Decision: "allow"},
			Status:     "active",
		},
	})
	inside := evaluator.Evaluate(model.DecisionRequest{
		TenantID: "tenant_lab_001", ActorType: "human",
		Destination: "10.20.0.10", DestinationPort: 22, Protocol: "tcp",
	})
	if inside.Decision != "allow" || inside.PolicyID != "pol_cidr_allow" {
		t.Fatalf("in-range flow = %q via %q (%v), want allow via pol_cidr_allow",
			inside.Decision, inside.PolicyID, inside.ReasonCodes)
	}
	// The range must not leak: an address outside it falls through to the default deny.
	outside := evaluator.Evaluate(model.DecisionRequest{
		TenantID: "tenant_lab_001", ActorType: "human",
		Destination: "10.21.0.10", DestinationPort: 22, Protocol: "tcp",
	})
	if outside.Decision == "allow" {
		t.Fatalf("out-of-range flow matched %q — a /24 must not cover a neighbouring subnet", outside.PolicyID)
	}
	if !IsDefaultDeny(outside) {
		t.Fatalf("expected a default deny outside the range, got %q / %v", outside.Decision, outside.ReasonCodes)
	}
}
