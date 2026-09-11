package swghttprewrite

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

const (
	googleHeader    = "X-GoogApps-Allowed-Domains"
	microsoftHeader = "Restrict-Access-To-Tenants"
)

type trackARewritePreflightConfig struct {
	PolicyBundle model.PolicyBundle       `json:"policy_bundle"`
	Policies     []model.Policy           `json:"policies"`
	Fixtures     []trackARewritePreflight `json:"fixtures"`
}

type trackARewritePreflight struct {
	FixtureID    string                `json:"fixture_id"`
	FixtureClass string                `json:"fixture_class"`
	Request      model.DecisionRequest `json:"request"`
	Expected     struct {
		Decision                          string `json:"decision"`
		PolicyID                          string `json:"policy_id"`
		SaaSApplicationID                 string `json:"saas_application_id"`
		HeaderInjectionApplied            bool   `json:"header_injection_applied"`
		HeaderInjectionSuppressedByBypass bool   `json:"header_injection_suppressed_by_bypass"`
		HeaderName                        string `json:"header_name"`
		TLSBypassApplied                  bool   `json:"tls_bypass_applied"`
		TLSBypassRuleID                   string `json:"tls_bypass_rule_id"`
	} `json:"expected"`
}

func TestSWGRewriteHarnessAppliesDecisionActions(t *testing.T) {
	config := loadRewritePreflightConfig(t)
	resolver := loadRewriteOperatorResolver(t, config.PolicyBundle)
	ev := decision.Evaluator{
		Policies:      config.Policies,
		PolicyBundle:  config.PolicyBundle,
		EdgeRegionID:  "local",
		EdgeClusterID: "local-edge-a",
	}

	for _, fixture := range config.Fixtures {
		t.Run(fixture.FixtureID, func(t *testing.T) {
			dec := ev.Evaluate(fixture.Request)
			if dec.Decision != fixture.Expected.Decision || dec.PolicyID != fixture.Expected.PolicyID {
				t.Fatalf("decision = %s/%s, want %s/%s", dec.Decision, dec.PolicyID, fixture.Expected.Decision, fixture.Expected.PolicyID)
			}
			seen := make(chan map[string]bool, 1)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				observed := map[string]bool{
					googleHeader:    r.Header.Values(googleHeader) != nil,
					microsoftHeader: r.Header.Values(microsoftHeader) != nil,
				}
				if fixture.Expected.HeaderInjectionApplied {
					ref := headerValueRefForDecision(t, dec)
					wantValue, ok := resolver.ResolveHeaderValue(ref)
					if !ok {
						t.Fatalf("operator config did not resolve %s", ref)
					}
					if got := r.Header.Get(fixture.Expected.HeaderName); got != wantValue {
						t.Fatalf("upstream header %s = %q, want configured value for %s", fixture.Expected.HeaderName, got, ref)
					}
				}
				seen <- observed
				w.WriteHeader(http.StatusNoContent)
			}))
			defer upstream.Close()

			req, err := http.NewRequest(http.MethodGet, upstream.URL+"/fixture", nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			rewritten, result, err := RewriteRequestFromDecision(req, dec, resolver)
			if err != nil {
				t.Fatalf("rewrite request: %v", err)
			}
			resp, err := upstream.Client().Do(rewritten)
			if err != nil {
				t.Fatalf("send rewritten request: %v", err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusNoContent {
				t.Fatalf("upstream status = %d, want 204", resp.StatusCode)
			}
			observed := <-seen

			if result.HeaderApplied != fixture.Expected.HeaderInjectionApplied {
				t.Fatalf("result HeaderApplied = %v, want %v; result=%#v", result.HeaderApplied, fixture.Expected.HeaderInjectionApplied, result)
			}
			if result.InjectActionSeen != fixture.Expected.HeaderInjectionApplied {
				t.Fatalf("result InjectActionSeen = %v, want %v; result=%#v", result.InjectActionSeen, fixture.Expected.HeaderInjectionApplied, result)
			}
			if result.HeaderInjectionSuppressedByBypass != fixture.Expected.HeaderInjectionSuppressedByBypass {
				t.Fatalf("result suppressed = %v, want %v", result.HeaderInjectionSuppressedByBypass, fixture.Expected.HeaderInjectionSuppressedByBypass)
			}
			if result.TLSBypassApplied != fixture.Expected.TLSBypassApplied {
				t.Fatalf("result TLSBypassApplied = %v, want %v", result.TLSBypassApplied, fixture.Expected.TLSBypassApplied)
			}
			if result.HeaderValueMaterialLogged || result.RuntimeTLSDecryptionObserved || result.RuntimeHeaderInjectionObserved || result.NetworkExtensionRuntimeUsed {
				t.Fatalf("result overclaimed or logged value material: %#v", result)
			}
			if fixture.Expected.HeaderInjectionApplied {
				if !observed[fixture.Expected.HeaderName] || result.HeaderName != fixture.Expected.HeaderName || !result.HeaderValueResolved {
					t.Fatalf("observed=%#v result=%#v, want applied %s", observed, result, fixture.Expected.HeaderName)
				}
			} else if observed[googleHeader] || observed[microsoftHeader] {
				t.Fatalf("unexpected tenant restriction header for bypass fixture: %#v", observed)
			}
		})
	}
}

// A client-forged tenant-restriction header must be stripped even when NO inject action applies to the
// request: Set-on-inject alone lets the forged header ride through on every non-injecting decision and
// impose the CLIENT's tenant allowlist upstream.
func TestRewriteStripsClientForgedTenantRestrictionHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://upstream.example.test/", nil)
	req.Header.Set(googleHeader, "attacker.example")
	req.Header.Set(microsoftHeader, "attacker-tenant-id")
	req.Header.Set("Restrict-Access-Context", "attacker-context-tenant")
	req.Header.Set("X-Unrelated", "keep-me")

	// No inject action at all — the pre-fix behavior forwarded the forged headers untouched.
	rewritten, result, err := RewriteRequestFromDecision(req, model.AccessDecision{ID: "dec_test", PolicyID: "pol_test"}, HeaderValueMap{})
	if err != nil {
		t.Fatalf("rewrite request: %v", err)
	}
	if result.InjectActionSeen || result.HeaderApplied {
		t.Fatalf("no inject action expected: %#v", result)
	}
	for _, name := range []string{googleHeader, microsoftHeader, "Restrict-Access-Context"} {
		if got := rewritten.Header.Get(name); got != "" {
			t.Fatalf("client-forged %s must be stripped, got %q", name, got)
		}
	}
	if rewritten.Header.Get("X-Unrelated") != "keep-me" {
		t.Fatalf("unrelated client headers must survive the strip")
	}

	// With an inject action for ONE header, the OTHER forged enterprise headers must still be stripped.
	req2 := httptest.NewRequest(http.MethodGet, "http://upstream.example.test/", nil)
	req2.Header.Set(googleHeader, "attacker.example")
	req2.Header.Set(microsoftHeader, "attacker-tenant-id")
	dec := model.AccessDecision{
		ID:       "dec_test",
		PolicyID: "pol_test",
		Actions: []model.DecisionAction{{
			Type: injectTenantRestrictionHeaderAction,
			Metadata: map[string]any{
				"header_name":      googleHeader,
				"header_value_ref": "operator_config_ref:google_workspace_allowed_domains",
			},
		}},
	}
	resolver := HeaderValueMap{"operator_config_ref:google_workspace_allowed_domains": "corp.example"}
	rewritten2, result2, err := RewriteRequestFromDecision(req2, dec, resolver)
	if err != nil {
		t.Fatalf("rewrite request with inject: %v", err)
	}
	if !result2.HeaderApplied || rewritten2.Header.Get(googleHeader) != "corp.example" {
		t.Fatalf("operator-configured value must replace the forged one: %#v", result2)
	}
	if got := rewritten2.Header.Get(microsoftHeader); got != "" {
		t.Fatalf("forged %s must be stripped even when a different header is injected, got %q", microsoftHeader, got)
	}

	// The forward-proxy ingress strip is the redundant outer layer for paths that skip the rewrite.
	stripped := forwardProxyRequestHeaders(req.Header)
	for _, name := range []string{googleHeader, microsoftHeader, "Restrict-Access-Context"} {
		if got := stripped.Get(name); got != "" {
			t.Fatalf("forwardProxyRequestHeaders must strip %s, got %q", name, got)
		}
	}
}

func TestRewriteHarnessRejectsHeaderValueMaterialInDecisionAction(t *testing.T) {
	config := loadRewritePreflightConfig(t)
	resolver := loadRewriteOperatorResolver(t, config.PolicyBundle)
	req := httptest.NewRequest(http.MethodGet, "http://upstream.example.test/", nil)
	dec := model.AccessDecision{
		ID:       "dec_test",
		PolicyID: "pol_test",
		Actions: []model.DecisionAction{
			{
				Type: "inject_saas_tenant_restriction_header",
				Metadata: map[string]any{
					"header_name":      googleHeader,
					"header_value_ref": "operator_config_ref:google_workspace_allowed_domains",
					"header_value":     "must-not-come-from-decision",
				},
			},
		},
	}
	if _, _, err := RewriteRequestFromDecision(req, dec, resolver); err == nil {
		t.Fatalf("expected header value material in decision action to be rejected")
	}
}

func TestSWGOperatorManagedResolverRejectsMismatchedConfig(t *testing.T) {
	config := loadRewritePreflightConfig(t)
	operatorConfig := loadRewriteOperatorConfig(t)
	operatorConfig.HeaderValues = operatorConfig.HeaderValues[:1]
	if _, err := NewOperatorManagedHeaderValueResolver(operatorConfig, config.PolicyBundle); err == nil {
		t.Fatalf("expected missing microsoft operator_config_ref to be rejected")
	}

	operatorConfig = loadRewriteOperatorConfig(t)
	operatorConfig.HeaderValues[0].Metadata["operator_config_value_secret"] = true
	if _, err := NewOperatorManagedHeaderValueResolver(operatorConfig, config.PolicyBundle); err == nil {
		t.Fatalf("expected secret-marked operator config value to be rejected")
	}
}

func loadRewritePreflightConfig(t *testing.T) trackARewritePreflightConfig {
	t.Helper()
	path := filepath.Join("testdata", "swg_saas_tenant_enforcement_preflight.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			t.Skipf("fixture not shipped with the dsse-core module (monorepo-only): %s", path)
		}
		t.Fatalf("read %s: %v", path, err)
	}
	var config trackARewritePreflightConfig
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return config
}

func loadRewriteOperatorResolver(t *testing.T, bundle model.PolicyBundle) OperatorManagedHeaderValueResolver {
	t.Helper()
	opPath := filepath.Join("testdata", "swg_tenant_restriction_operator_config.json")
	if _, statErr := os.Stat(opPath); statErr != nil {
		t.Skipf("fixture not shipped with the dsse-core module (monorepo-only): %s", opPath)
	}
	resolver, err := LoadOperatorManagedHeaderValueResolver(opPath, bundle)
	if err != nil {
		t.Fatalf("load operator config: %v", err)
	}
	return resolver
}

func loadRewriteOperatorConfig(t *testing.T) OperatorManagedHeaderValueConfig {
	t.Helper()
	path := filepath.Join("testdata", "swg_tenant_restriction_operator_config.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			t.Skipf("fixture not shipped with the dsse-core module (monorepo-only): %s", path)
		}
		t.Fatalf("read %s: %v", path, err)
	}
	var config OperatorManagedHeaderValueConfig
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return config
}

func headerValueRefForDecision(t *testing.T, dec model.AccessDecision) string {
	t.Helper()
	for _, action := range dec.Actions {
		if action.Type != "inject_saas_tenant_restriction_header" {
			continue
		}
		ref, ok := action.Metadata["header_value_ref"].(string)
		if !ok || ref == "" {
			t.Fatalf("decision action missing header_value_ref: %#v", action.Metadata)
		}
		return ref
	}
	t.Fatalf("decision missing inject action: %#v", dec.Actions)
	return ""
}

// Tenant restriction is OFF by default: a bundle with ZERO active tenant-restriction rules is valid (no
// headers injected), while the operator config keeps its header values configured + ready for opt-in.
func TestSWGOperatorResolverDefaultInactiveIsValid(t *testing.T) {
	config := loadRewritePreflightConfig(t)
	operatorConfig := loadRewriteOperatorConfig(t)

	// Deactivate every tenant-restriction rule (the product default) but keep the operator values.
	bundle := config.PolicyBundle
	for i := range bundle.SWGTenantRestrictionRules {
		bundle.SWGTenantRestrictionRules[i].Status = "inactive"
	}

	resolver, err := NewOperatorManagedHeaderValueResolver(operatorConfig, bundle)
	if err != nil {
		t.Fatalf("zero active tenant-restriction rules must be a VALID (default-off) state: %v", err)
	}
	// The configured values are still resolvable (ready for when an admin enables a rule).
	if v, ok := resolver.ResolveHeaderValue("operator_config_ref:google_workspace_allowed_domains"); !ok || v == "" {
		t.Fatalf("operator config value should stay configured/ready while the rule is inactive")
	}

	// A value that maps to NO rule at all is still rejected (no stray values).
	stray := loadRewriteOperatorConfig(t)
	stray.HeaderValues[0].Ref = "operator_config_ref:does_not_exist"
	if _, err := NewOperatorManagedHeaderValueResolver(stray, bundle); err == nil {
		t.Fatalf("an operator value with no matching rule must still be rejected")
	}
}
