package decision

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

type trackASWGPreflightConfig struct {
	SchemaVersion                 string                   `json:"schema_version"`
	Status                        string                   `json:"status"`
	Milestone                     string                   `json:"milestone"`
	DepthLockedUnit               string                   `json:"depth_locked_unit"`
	TenantID                      string                   `json:"tenant_id"`
	DefaultTLSDecryptionRequired  bool                     `json:"default_tls_decryption_required"`
	PerDestinationBypassRequired  bool                     `json:"per_destination_tls_bypass_required"`
	MacCATrustRequired            bool                     `json:"mac_ca_trust_required"`
	HeaderValueMaterialInDecision bool                     `json:"header_value_material_in_decision"`
	PolicyBundle                  model.PolicyBundle       `json:"policy_bundle"`
	Policies                      []model.Policy           `json:"policies"`
	Fixtures                      []trackASWGPreflightCase `json:"fixtures"`
	ClaimGuard                    map[string]any           `json:"claim_guard"`
}

type trackASWGPreflightCase struct {
	FixtureID    string                `json:"fixture_id"`
	FixtureClass string                `json:"fixture_class"`
	Request      model.DecisionRequest `json:"request"`
	Expected     struct {
		Decision                          string   `json:"decision"`
		PolicyID                          string   `json:"policy_id"`
		SaaSApplicationID                 string   `json:"saas_application_id"`
		HeaderInjectionApplied            bool     `json:"header_injection_applied"`
		HeaderInjectionSuppressedByBypass bool     `json:"header_injection_suppressed_by_bypass"`
		HeaderName                        string   `json:"header_name"`
		TLSBypassApplied                  bool     `json:"tls_bypass_applied"`
		TLSBypassRuleID                   string   `json:"tls_bypass_rule_id"`
		ReasonCodes                       []string `json:"reason_codes"`
	} `json:"expected"`
}

func TestSWGSWGSaaSTenantEnforcementPreflightFixtures(t *testing.T) {
	config := loadTrackASWGPreflightConfig(t)
	if config.SchemaVersion != "swg_saas_tenant_enforcement_preflight.v1" || config.Status != "passed" || config.Milestone != "" {
		t.Fatalf("config header = %s/%s/%s, want passed preflight", config.SchemaVersion, config.Status, config.Milestone)
	}
	if !config.DefaultTLSDecryptionRequired || !config.PerDestinationBypassRequired || !config.MacCATrustRequired || config.HeaderValueMaterialInDecision {
		t.Fatalf("config gates = tls:%v bypass:%v ca:%v header_material:%v, want required/required/required/false", config.DefaultTLSDecryptionRequired, config.PerDestinationBypassRequired, config.MacCATrustRequired, config.HeaderValueMaterialInDecision)
	}
	if len(config.PolicyBundle.SWGTenantRestrictionRules) != 2 {
		t.Fatalf("tenant restriction rules = %d, want 2", len(config.PolicyBundle.SWGTenantRestrictionRules))
	}
	if len(config.PolicyBundle.SWGTLSBypassRules) != 2 {
		t.Fatalf("TLS bypass rules = %d, want 2", len(config.PolicyBundle.SWGTLSBypassRules))
	}
	for _, field := range []string{
		"swg_runtime_traffic_observed",
		"tls_runtime_decryption_observed",
		"header_injection_runtime_observed",
		"mac_ca_trust_observed",
		"human_boundary_created",
		"gui_buildout_started",
		"paper_only_contract_slice_started",
		"p4_packaging_mdm_signing_install_started",
		"shipping_product_claimed",
		"production_scale_claimed",
		"mvp_pilot_success_claimed",
		"windows_work_started",
		"captured_secret_material_committed",
	} {
		if config.ClaimGuard[field] != false {
			t.Fatalf("claim_guard[%s] = %#v, want false", field, config.ClaimGuard[field])
		}
	}
	if config.ClaimGuard["no_secret_attestation"] != true {
		t.Fatalf("claim_guard no_secret_attestation = %#v, want true", config.ClaimGuard["no_secret_attestation"])
	}

	ev := Evaluator{
		Policies:      config.Policies,
		PolicyBundle:  config.PolicyBundle,
		EdgeRegionID:  "local",
		EdgeClusterID: "local-edge-a",
	}
	if len(config.Fixtures) != 4 {
		t.Fatalf("fixtures = %d, want 4", len(config.Fixtures))
	}
	for _, fixture := range config.Fixtures {
		dec := ev.Evaluate(fixture.Request)
		assertTrackASWGFixtureDecision(t, fixture, dec)
	}
}

func loadTrackASWGPreflightConfig(t *testing.T) trackASWGPreflightConfig {
	t.Helper()
	path := filepath.Join("..", "swghttprewrite", "testdata", "swg_saas_tenant_enforcement_preflight.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			t.Skipf("fixture not shipped with the dsse-core module (monorepo-only): %s", path)
		}
		t.Fatalf("read %s: %v", path, err)
	}
	var config trackASWGPreflightConfig
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return config
}

func assertTrackASWGFixtureDecision(t *testing.T, fixture trackASWGPreflightCase, dec model.AccessDecision) {
	t.Helper()
	if dec.Decision != fixture.Expected.Decision {
		t.Fatalf("%s decision = %q, want %q; metadata=%#v", fixture.FixtureID, dec.Decision, fixture.Expected.Decision, dec.Metadata)
	}
	if dec.PolicyID != fixture.Expected.PolicyID {
		t.Fatalf("%s policy_id = %q, want %q", fixture.FixtureID, dec.PolicyID, fixture.Expected.PolicyID)
	}
	if dec.SaaSContext == nil || dec.SaaSContext.SaaSApplicationID != fixture.Expected.SaaSApplicationID {
		t.Fatalf("%s saas_context = %#v, want %s", fixture.FixtureID, dec.SaaSContext, fixture.Expected.SaaSApplicationID)
	}
	for _, code := range append(fixture.Expected.ReasonCodes, "swg_saas_tenant_enforcement_preflight") {
		if !contains(dec.ReasonCodes, code) {
			t.Fatalf("%s reason_codes = %v, want %s", fixture.FixtureID, dec.ReasonCodes, code)
		}
	}
	for key, want := range map[string]any{
		"swg_tenant_enforcement_preflight":      "policy_layer",
		"swg_default_tls_decryption_required":   true,
		"swg_tls_bypass_policy":                 "per_destination_bypass_list",
		"swg_tls_runtime_decryption_observed":   false,
		"swg_header_injection_runtime_observed": false,
		"swg_macos_ca_trust_required":           true,
		"swg_macos_ca_trust_observed":           false,
		"tls_interception_enabled":              true,
		"network_extension_runtime_used":        false,
	} {
		if got := dec.Metadata[key]; got != want {
			t.Fatalf("%s metadata[%s] = %#v, want %#v; metadata=%#v", fixture.FixtureID, key, got, want, dec.Metadata)
		}
	}
	if got := dec.Metadata["swg_tls_bypass_applied"]; got != fixture.Expected.TLSBypassApplied {
		t.Fatalf("%s swg_tls_bypass_applied = %#v, want %#v", fixture.FixtureID, got, fixture.Expected.TLSBypassApplied)
	}
	if dec.Bypass != fixture.Expected.TLSBypassApplied {
		t.Fatalf("%s bypass = %v, want %v", fixture.FixtureID, dec.Bypass, fixture.Expected.TLSBypassApplied)
	}
	wantRouteCategory := "tls_readiness_candidate"
	wantExecutionScope := "post_mvp_tls"
	wantPolicyDecision := "intercept_candidate"
	wantDecisionSource := "inspection_profile"
	if fixture.Expected.TLSBypassApplied {
		wantRouteCategory = "passthrough"
		wantExecutionScope = "not_executed_metadata_only"
		wantPolicyDecision = "bypass"
		wantDecisionSource = "swg_tls_bypass_rule"
	}
	if stringPtrValue(dec.InspectionRouteCategory) != wantRouteCategory || stringPtrValue(dec.InspectionExecutionScope) != wantExecutionScope {
		t.Fatalf("%s inspection route = %s/%s, want %s/%s", fixture.FixtureID, stringPtrValue(dec.InspectionRouteCategory), stringPtrValue(dec.InspectionExecutionScope), wantRouteCategory, wantExecutionScope)
	}
	for key, want := range map[string]any{
		"inspection_route_category":       wantRouteCategory,
		"inspection_execution_scope":      wantExecutionScope,
		"edge_tls_policy_decision":        wantPolicyDecision,
		"edge_tls_policy_decision_source": wantDecisionSource,
		"edge_tls_policy_bypass":          fixture.Expected.TLSBypassApplied,
	} {
		if got := dec.Metadata[key]; got != want {
			t.Fatalf("%s metadata[%s] = %#v, want %#v; metadata=%#v", fixture.FixtureID, key, got, want, dec.Metadata)
		}
	}
	assertOptionalBoolMetadata(t, fixture, dec, "swg_tenant_restriction_header_injection_applied", fixture.Expected.HeaderInjectionApplied)
	assertOptionalBoolMetadata(t, fixture, dec, "swg_tenant_restriction_header_injection_suppressed_by_bypass", fixture.Expected.HeaderInjectionSuppressedByBypass)
	if fixture.Expected.HeaderName != "" && dec.Metadata["swg_tenant_restriction_header_name"] != fixture.Expected.HeaderName {
		t.Fatalf("%s header metadata = %#v, want %s", fixture.FixtureID, dec.Metadata["swg_tenant_restriction_header_name"], fixture.Expected.HeaderName)
	}
	if fixture.Expected.TLSBypassRuleID != "" && dec.Metadata["swg_tls_bypass_rule_id"] != fixture.Expected.TLSBypassRuleID {
		t.Fatalf("%s bypass rule metadata = %#v, want %s", fixture.FixtureID, dec.Metadata["swg_tls_bypass_rule_id"], fixture.Expected.TLSBypassRuleID)
	}
	if _, ok := dec.Metadata["swg_tenant_restriction_header_value"]; ok {
		t.Fatalf("%s decision metadata included header value material: %#v", fixture.FixtureID, dec.Metadata)
	}
	if valueMaterial, ok := dec.Metadata["swg_tenant_restriction_header_value_material_in_decision"]; ok && valueMaterial != false {
		t.Fatalf("%s header value material flag = %#v, want false", fixture.FixtureID, valueMaterial)
	}

	injectAction, hasInjectAction := decisionActionByType(dec.Actions, "inject_saas_tenant_restriction_header")
	if hasInjectAction != fixture.Expected.HeaderInjectionApplied {
		t.Fatalf("%s inject action present = %v, want %v; actions=%#v", fixture.FixtureID, hasInjectAction, fixture.Expected.HeaderInjectionApplied, dec.Actions)
	}
	if hasInjectAction {
		if injectAction.Metadata["header_name"] != fixture.Expected.HeaderName {
			t.Fatalf("%s inject action header = %#v, want %s", fixture.FixtureID, injectAction.Metadata["header_name"], fixture.Expected.HeaderName)
		}
		if _, ok := injectAction.Metadata["header_value"]; ok {
			t.Fatalf("%s inject action included header value material: %#v", fixture.FixtureID, injectAction.Metadata)
		}
		if injectAction.Metadata["header_value_material_in_decision"] != false || injectAction.Metadata["runtime_tls_decryption_observed"] != false || injectAction.Metadata["runtime_header_injection_observed"] != false {
			t.Fatalf("%s inject action metadata = %#v, want non-runtime non-value action", fixture.FixtureID, injectAction.Metadata)
		}
	}

	if fixture.Expected.TLSBypassApplied {
		bypassAction, ok := decisionActionByType(dec.Actions, "emit_audit_event")
		if !ok || bypassAction.Metadata["swg_tls_bypass_rule_id"] != fixture.Expected.TLSBypassRuleID {
			t.Fatalf("%s bypass action = %#v, want rule %s", fixture.FixtureID, bypassAction, fixture.Expected.TLSBypassRuleID)
		}
	}
	accessLog := AccessLogFromDecision(dec)
	if accessLog.Metadata["swg_tenant_enforcement_preflight"] != "policy_layer" {
		t.Fatalf("%s access log metadata missing SWG preflight: %#v", fixture.FixtureID, accessLog.Metadata)
	}
	trace := DecisionTraceFromDecision(dec)
	if trace.Metadata["swg_default_tls_decryption_required"] != true {
		t.Fatalf("%s trace metadata missing SWG TLS gate: %#v", fixture.FixtureID, trace.Metadata)
	}
}

func assertOptionalBoolMetadata(t *testing.T, fixture trackASWGPreflightCase, dec model.AccessDecision, key string, want bool) {
	t.Helper()
	got, ok := dec.Metadata[key]
	if want && (!ok || got != true) {
		t.Fatalf("%s metadata[%s] = %#v, want true", fixture.FixtureID, key, got)
	}
	if ok && got != want {
		t.Fatalf("%s metadata[%s] = %#v, want %#v", fixture.FixtureID, key, got, want)
	}
}

func decisionActionByType(actions []model.DecisionAction, expected string) (model.DecisionAction, bool) {
	for _, action := range actions {
		if action.Type == expected {
			return action, true
		}
	}
	return model.DecisionAction{}, false
}

func stringPtrValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
