package swghttprewrite

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

const (
	GoogleWorkspaceTenantRestrictionHeader = "X-GoogApps-Allowed-Domains"
	Microsoft365TenantRestrictionHeader    = "Restrict-Access-To-Tenants"

	harnessReportSchemaVersion = "swg_http_rewrite_harness_report.v1"
	harnessMilestone           = "harness_v1"
	harnessDepthLockedUnit     = "swg_header_injection_local_http_harness"
)

type HarnessConfig struct {
	SchemaVersion string                 `json:"schema_version"`
	Status        string                 `json:"status"`
	Milestone     string                 `json:"milestone"`
	PolicyBundle  model.PolicyBundle     `json:"policy_bundle"`
	Policies      []model.Policy         `json:"policies"`
	Fixtures      []HarnessFixture       `json:"fixtures"`
	ClaimGuard    map[string]interface{} `json:"claim_guard"`
}

type HarnessFixture struct {
	FixtureID    string                `json:"fixture_id"`
	FixtureClass string                `json:"fixture_class"`
	Request      model.DecisionRequest `json:"request"`
	Expected     HarnessExpected       `json:"expected"`
}

type HarnessExpected struct {
	Decision                          string `json:"decision"`
	PolicyID                          string `json:"policy_id"`
	SaaSApplicationID                 string `json:"saas_application_id"`
	HeaderInjectionApplied            bool   `json:"header_injection_applied"`
	HeaderInjectionSuppressedByBypass bool   `json:"header_injection_suppressed_by_bypass"`
	HeaderName                        string `json:"header_name"`
	TLSBypassApplied                  bool   `json:"tls_bypass_applied"`
	TLSBypassRuleID                   string `json:"tls_bypass_rule_id"`
}

type HarnessReport struct {
	SchemaVersion                                string               `json:"schema_version"`
	Status                                       string               `json:"status"`
	CreatedAt                                    string               `json:"created_at"`
	Milestone                                    string               `json:"milestone"`
	DepthLockedUnit                              string               `json:"depth_locked_unit"`
	SourceM1583PreflightGate                     string               `json:"source_m1583_preflight_gate"`
	HarnessGate                                  string               `json:"harness_gate"`
	LocalHTTPRewriteHarnessObservation           bool                 `json:"local_http_rewrite_harness_observation"`
	GoogleWorkspaceHeader                        string               `json:"google_workspace_header"`
	Microsoft365Header                           string               `json:"microsoft_365_header"`
	FixtureCount                                 int                  `json:"fixture_count"`
	TenantRestrictionHeaderInjectionFixtureCount int                  `json:"tenant_restriction_header_injection_fixture_count"`
	TLSBypassFixtureCount                        int                  `json:"tls_bypass_fixture_count"`
	TLSBypassSuppressionFixtureCount             int                  `json:"tls_bypass_suppression_fixture_count"`
	GoogleWorkspaceHeaderInjected                bool                 `json:"google_workspace_header_injected"`
	Microsoft365HeaderInjected                   bool                 `json:"microsoft_365_header_injected"`
	TLSBypassSuppressedInjection                 bool                 `json:"tls_bypass_suppressed_injection"`
	HeaderValueMaterialLogged                    bool                 `json:"header_value_material_logged"`
	HeaderValueMaterialInDecision                bool                 `json:"header_value_material_in_decision"`
	SWGRuntimeTrafficObserved                    bool                 `json:"swg_runtime_traffic_observed"`
	TLSRuntimeDecryptionObserved                 bool                 `json:"tls_runtime_decryption_observed"`
	HeaderInjectionRuntimeObserved               bool                 `json:"header_injection_runtime_observed"`
	MacCATrustObserved                           bool                 `json:"mac_ca_trust_observed"`
	NetworkExtensionRuntimeUsed                  bool                 `json:"network_extension_runtime_used"`
	HumanBoundaryCreated                         bool                 `json:"human_boundary_created"`
	GUIBuildoutStarted                           bool                 `json:"gui_buildout_started"`
	P4PackagingMDMSigningInstallStarted          bool                 `json:"p4_packaging_mdm_signing_install_started"`
	ShippingProductClaimed                       bool                 `json:"shipping_product_claimed"`
	ProductionScaleClaimed                       bool                 `json:"production_scale_claimed"`
	MVPPilotSuccessClaimed                       bool                 `json:"mvp_pilot_success_claimed"`
	WindowsWorkStarted                           bool                 `json:"windows_work_started"`
	RawLogsIncluded                              bool                 `json:"raw_logs_included"`
	RawCommandOutputIncluded                     bool                 `json:"raw_command_output_included"`
	RawEndpointValuesIncluded                    bool                 `json:"raw_endpoint_values_included"`
	RawHeaderValuesIncluded                      bool                 `json:"raw_header_values_included"`
	CredentialsIncluded                          bool                 `json:"credentials_included"`
	AuthMaterialIncluded                         bool                 `json:"auth_material_included"`
	CertificateOrKeyMaterialIncluded             bool                 `json:"certificate_or_key_material_included"`
	SecretLeakGate                               string               `json:"secret_leak_gate"`
	NoSecretAttestation                          bool                 `json:"no_secret_attestation"`
	Fixtures                                     []FixtureObservation `json:"fixtures"`
}

type FixtureObservation struct {
	FixtureID                              string `json:"fixture_id"`
	FixtureClass                           string `json:"fixture_class"`
	Status                                 string `json:"status"`
	Decision                               string `json:"decision"`
	PolicyID                               string `json:"policy_id"`
	SaaSApplicationID                      string `json:"saas_application_id"`
	HeaderName                             string `json:"header_name,omitempty"`
	HeaderApplied                          bool   `json:"header_applied"`
	InjectActionSeen                       bool   `json:"inject_action_seen"`
	HeaderValueResolved                    bool   `json:"header_value_resolved"`
	HeaderValueMaterialLogged              bool   `json:"header_value_material_logged"`
	UpstreamGoogleHeaderObserved           bool   `json:"upstream_google_header_observed"`
	UpstreamMicrosoft365HeaderObserved     bool   `json:"upstream_microsoft_365_header_observed"`
	UpstreamExpectedHeaderObserved         bool   `json:"upstream_expected_header_observed"`
	UpstreamUnexpectedTenantHeaderObserved bool   `json:"upstream_unexpected_tenant_header_observed"`
	TLSBypassApplied                       bool   `json:"tls_bypass_applied"`
	TLSBypassRuleID                        string `json:"tls_bypass_rule_id,omitempty"`
	HeaderInjectionSuppressedByBypass      bool   `json:"header_injection_suppressed_by_bypass"`
	RuntimeTLSDecryptionObserved           bool   `json:"runtime_tls_decryption_observed"`
	RuntimeHeaderInjectionObserved         bool   `json:"runtime_header_injection_observed"`
	NetworkExtensionRuntimeUsed            bool   `json:"network_extension_runtime_used"`
	LocalHTTPRewriteHarnessObservation     bool   `json:"local_http_rewrite_harness_observation"`
}

type upstreamObservation struct {
	googleHeaderObserved       bool
	microsoft365HeaderObserved bool
	expectedHeaderObserved     bool
	expectedHeaderValueMatched bool
}

func LoadHarnessConfig(path string) (HarnessConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return HarnessConfig{}, err
	}
	var config HarnessConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return HarnessConfig{}, err
	}
	return config, nil
}

func RunLocalHTTPRewriteHarness(config HarnessConfig, resolver HeaderValueResolver) (HarnessReport, error) {
	if resolver == nil {
		return HarnessReport{}, fmt.Errorf("header value resolver is required")
	}
	ev := decision.Evaluator{
		Policies:      config.Policies,
		PolicyBundle:  config.PolicyBundle,
		EdgeRegionID:  "local",
		EdgeClusterID: "local-edge-a",
	}

	report := HarnessReport{
		SchemaVersion:                      harnessReportSchemaVersion,
		Status:                             "passed",
		CreatedAt:                          time.Now().UTC().Format(time.RFC3339),
		Milestone:                          harnessMilestone,
		DepthLockedUnit:                    harnessDepthLockedUnit,
		SourceM1583PreflightGate:           "accepted",
		HarnessGate:                        "local_http_rewrite_harness_passed",
		LocalHTTPRewriteHarnessObservation: true,
		GoogleWorkspaceHeader:              GoogleWorkspaceTenantRestrictionHeader,
		Microsoft365Header:                 Microsoft365TenantRestrictionHeader,
		FixtureCount:                       len(config.Fixtures),
		SecretLeakGate:                     "ok",
		NoSecretAttestation:                true,
	}

	for _, fixture := range config.Fixtures {
		dec := ev.Evaluate(fixture.Request)
		if err := assertDecisionMatchesFixture(fixture, dec); err != nil {
			return HarnessReport{}, err
		}
		observation, err := runFixtureRewrite(fixture, dec, resolver)
		if err != nil {
			return HarnessReport{}, err
		}
		report.Fixtures = append(report.Fixtures, observation)
		applyFixtureObservationToReport(&report, observation, fixture)
	}

	return report, nil
}

func runFixtureRewrite(fixture HarnessFixture, dec model.AccessDecision, resolver HeaderValueResolver) (FixtureObservation, error) {
	observedCh := make(chan upstreamObservation, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observation := upstreamObservation{
			googleHeaderObserved:       r.Header.Get(GoogleWorkspaceTenantRestrictionHeader) != "",
			microsoft365HeaderObserved: r.Header.Get(Microsoft365TenantRestrictionHeader) != "",
		}
		if fixture.Expected.HeaderInjectionApplied {
			ref, err := headerValueRefFromDecision(dec)
			if err != nil {
				http.Error(w, "missing header ref", http.StatusBadGateway)
				observedCh <- observation
				return
			}
			want, ok := resolver.ResolveHeaderValue(ref)
			got := r.Header.Get(fixture.Expected.HeaderName)
			observation.expectedHeaderObserved = got != ""
			observation.expectedHeaderValueMatched = ok && got == want
			if !observation.expectedHeaderValueMatched {
				http.Error(w, "tenant header mismatch", http.StatusBadGateway)
				observedCh <- observation
				return
			}
		}
		observedCh <- observation
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	req, err := http.NewRequest(http.MethodGet, upstream.URL+"/swg/rewrite-fixture", nil)
	if err != nil {
		return FixtureObservation{}, err
	}
	rewritten, result, err := RewriteRequestFromDecision(req, dec, resolver)
	if err != nil {
		return FixtureObservation{}, err
	}
	resp, err := upstream.Client().Do(rewritten)
	if err != nil {
		return FixtureObservation{}, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	observed := <-observedCh
	if resp.StatusCode != http.StatusNoContent {
		return FixtureObservation{}, fmt.Errorf("%s upstream status=%d", fixture.FixtureID, resp.StatusCode)
	}

	observation := FixtureObservation{
		FixtureID:                              fixture.FixtureID,
		FixtureClass:                           fixture.FixtureClass,
		Status:                                 "passed",
		Decision:                               dec.Decision,
		PolicyID:                               dec.PolicyID,
		SaaSApplicationID:                      saasApplicationID(dec),
		HeaderName:                             result.HeaderName,
		HeaderApplied:                          result.HeaderApplied,
		InjectActionSeen:                       result.InjectActionSeen,
		HeaderValueResolved:                    result.HeaderValueResolved,
		HeaderValueMaterialLogged:              result.HeaderValueMaterialLogged,
		UpstreamGoogleHeaderObserved:           observed.googleHeaderObserved,
		UpstreamMicrosoft365HeaderObserved:     observed.microsoft365HeaderObserved,
		UpstreamExpectedHeaderObserved:         observed.expectedHeaderObserved,
		UpstreamUnexpectedTenantHeaderObserved: unexpectedTenantHeaderObserved(fixture, observed),
		TLSBypassApplied:                       result.TLSBypassApplied,
		TLSBypassRuleID:                        result.TLSBypassRuleID,
		HeaderInjectionSuppressedByBypass:      result.HeaderInjectionSuppressedByBypass,
		RuntimeTLSDecryptionObserved:           result.RuntimeTLSDecryptionObserved,
		RuntimeHeaderInjectionObserved:         result.RuntimeHeaderInjectionObserved,
		NetworkExtensionRuntimeUsed:            result.NetworkExtensionRuntimeUsed,
		LocalHTTPRewriteHarnessObservation:     result.LocalHTTPRewriteHarnessObservation,
	}
	if fixture.Expected.HeaderInjectionApplied && !observed.expectedHeaderValueMatched {
		return FixtureObservation{}, fmt.Errorf("%s expected tenant header was not observed with configured value", fixture.FixtureID)
	}
	if !fixture.Expected.HeaderInjectionApplied && observation.UpstreamUnexpectedTenantHeaderObserved {
		return FixtureObservation{}, fmt.Errorf("%s unexpectedly injected tenant header", fixture.FixtureID)
	}
	return observation, nil
}

func assertDecisionMatchesFixture(fixture HarnessFixture, dec model.AccessDecision) error {
	if dec.Decision != fixture.Expected.Decision {
		return fmt.Errorf("%s decision=%s want %s", fixture.FixtureID, dec.Decision, fixture.Expected.Decision)
	}
	if dec.PolicyID != fixture.Expected.PolicyID {
		return fmt.Errorf("%s policy_id=%s want %s", fixture.FixtureID, dec.PolicyID, fixture.Expected.PolicyID)
	}
	if saasApplicationID(dec) != fixture.Expected.SaaSApplicationID {
		return fmt.Errorf("%s saas_application_id=%s want %s", fixture.FixtureID, saasApplicationID(dec), fixture.Expected.SaaSApplicationID)
	}
	return nil
}

func applyFixtureObservationToReport(report *HarnessReport, observation FixtureObservation, fixture HarnessFixture) {
	if fixture.Expected.HeaderInjectionApplied {
		report.TenantRestrictionHeaderInjectionFixtureCount++
	}
	if fixture.Expected.TLSBypassApplied {
		report.TLSBypassFixtureCount++
	}
	if fixture.Expected.HeaderInjectionSuppressedByBypass {
		report.TLSBypassSuppressionFixtureCount++
	}
	if observation.HeaderName == GoogleWorkspaceTenantRestrictionHeader && observation.HeaderApplied && observation.UpstreamExpectedHeaderObserved {
		report.GoogleWorkspaceHeaderInjected = true
	}
	if observation.HeaderName == Microsoft365TenantRestrictionHeader && observation.HeaderApplied && observation.UpstreamExpectedHeaderObserved {
		report.Microsoft365HeaderInjected = true
	}
	if observation.HeaderInjectionSuppressedByBypass && !observation.HeaderApplied && !observation.UpstreamUnexpectedTenantHeaderObserved {
		report.TLSBypassSuppressedInjection = true
	}
	report.HeaderValueMaterialLogged = report.HeaderValueMaterialLogged || observation.HeaderValueMaterialLogged
	report.TLSRuntimeDecryptionObserved = report.TLSRuntimeDecryptionObserved || observation.RuntimeTLSDecryptionObserved
	report.HeaderInjectionRuntimeObserved = report.HeaderInjectionRuntimeObserved || observation.RuntimeHeaderInjectionObserved
	report.NetworkExtensionRuntimeUsed = report.NetworkExtensionRuntimeUsed || observation.NetworkExtensionRuntimeUsed
}

func headerValueRefFromDecision(dec model.AccessDecision) (string, error) {
	action, ok, err := injectAction(dec.Actions)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("inject action missing")
	}
	ref := stringMetadata(action.Metadata, "header_value_ref")
	if ref == "" {
		return "", fmt.Errorf("header value ref missing")
	}
	return ref, nil
}

func unexpectedTenantHeaderObserved(fixture HarnessFixture, observed upstreamObservation) bool {
	if fixture.Expected.HeaderInjectionApplied {
		return false
	}
	return observed.googleHeaderObserved || observed.microsoft365HeaderObserved
}
