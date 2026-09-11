package swghttprewrite

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

const (
	forwardProxyReportSchemaVersion = "swg_operator_config_resolver_product_unit_report.v1"
	forwardProxyMilestone           = "forward_proxy_v1"
	forwardProxyDepthLockedUnit     = "swg_operator_config_resolver_product_unit"
)

type ForwardProxyReport struct {
	SchemaVersion                                string                           `json:"schema_version"`
	Status                                       string                           `json:"status"`
	CreatedAt                                    string                           `json:"created_at"`
	Milestone                                    string                           `json:"milestone"`
	DepthLockedUnit                              string                           `json:"depth_locked_unit"`
	SourceM1584RewriteHarnessGate                string                           `json:"source_m1584_rewrite_harness_gate"`
	SourceM1586ForwardProxyHarnessGate           string                           `json:"source_m1586_forward_proxy_harness_gate"`
	HarnessGate                                  string                           `json:"harness_gate"`
	ForwardProxyStyleRequestPath                 bool                             `json:"forward_proxy_style_request_path"`
	ForwardProxyHandlerPathObserved              bool                             `json:"forward_proxy_handler_path_observed"`
	LocalHTTPOnly                                bool                             `json:"local_http_only"`
	LocalHttptestUpstreamRoundTripObserved       bool                             `json:"local_httptest_upstream_round_trip_observed"`
	DecisionEvaluatorConnected                   bool                             `json:"decision_evaluator_connected"`
	RewriteHarnessConnected                      bool                             `json:"rewrite_harness_connected"`
	ProxyRequestDerivedDecisionRequest           bool                             `json:"proxy_request_derived_decision_request"`
	DerivedSaaSContextFromProxyRequest           bool                             `json:"derived_saas_context_from_proxy_request"`
	OperatorConfigResolverConnected              bool                             `json:"operator_config_resolver_connected"`
	OperatorConfigRefResolutionCount             int                              `json:"operator_config_ref_resolution_count"`
	OperatorConfigRefs                           []string                         `json:"operator_config_refs"`
	GoogleWorkspaceOperatorConfigRef             string                           `json:"google_workspace_operator_config_ref"`
	Microsoft365OperatorConfigRef                string                           `json:"microsoft_365_operator_config_ref"`
	OperatorConfigValuesCommitted                bool                             `json:"operator_config_values_committed"`
	OperatorConfigValuesSecret                   bool                             `json:"operator_config_values_secret"`
	OperatorConfigValueMaterialLogged            bool                             `json:"operator_config_value_material_logged"`
	OperatorConfigValueMaterialInReport          bool                             `json:"operator_config_value_material_in_report"`
	CapturedSecretMaterialCommitted              bool                             `json:"captured_secret_material_committed"`
	ConfigurationRealness                        string                           `json:"configuration_realness"`
	ProductizationClaimsMade                     bool                             `json:"productization_claims_made"`
	NewProductClaimsMade                         bool                             `json:"new_product_claims_made"`
	GoogleWorkspaceHeader                        string                           `json:"google_workspace_header"`
	Microsoft365Header                           string                           `json:"microsoft_365_header"`
	FixtureCount                                 int                              `json:"fixture_count"`
	TenantRestrictionHeaderInjectionFixtureCount int                              `json:"tenant_restriction_header_injection_fixture_count"`
	TLSBypassFixtureCount                        int                              `json:"tls_bypass_fixture_count"`
	TLSBypassSuppressionFixtureCount             int                              `json:"tls_bypass_suppression_fixture_count"`
	GoogleWorkspaceHeaderInjected                bool                             `json:"google_workspace_header_injected"`
	Microsoft365HeaderInjected                   bool                             `json:"microsoft_365_header_injected"`
	TLSBypassSuppressedInjection                 bool                             `json:"tls_bypass_suppressed_injection"`
	HeaderValueMaterialLogged                    bool                             `json:"header_value_material_logged"`
	HeaderValueMaterialInDecision                bool                             `json:"header_value_material_in_decision"`
	SWGRuntimeTrafficObserved                    bool                             `json:"swg_runtime_traffic_observed"`
	TLSRuntimeDecryptionObserved                 bool                             `json:"tls_runtime_decryption_observed"`
	HeaderInjectionRuntimeObserved               bool                             `json:"header_injection_runtime_observed"`
	MacCATrustObserved                           bool                             `json:"mac_ca_trust_observed"`
	NetworkExtensionRuntimeUsed                  bool                             `json:"network_extension_runtime_used"`
	HumanBoundaryCreated                         bool                             `json:"human_boundary_created"`
	GUIBuildoutStarted                           bool                             `json:"gui_buildout_started"`
	P4PackagingMDMSigningInstallStarted          bool                             `json:"p4_packaging_mdm_signing_install_started"`
	ShippingProductClaimed                       bool                             `json:"shipping_product_claimed"`
	ProductionScaleClaimed                       bool                             `json:"production_scale_claimed"`
	MVPPilotSuccessClaimed                       bool                             `json:"mvp_pilot_success_claimed"`
	WindowsWorkStarted                           bool                             `json:"windows_work_started"`
	RawLogsIncluded                              bool                             `json:"raw_logs_included"`
	RawCommandOutputIncluded                     bool                             `json:"raw_command_output_included"`
	RawEndpointValuesIncluded                    bool                             `json:"raw_endpoint_values_included"`
	RawHeaderValuesIncluded                      bool                             `json:"raw_header_values_included"`
	CredentialsIncluded                          bool                             `json:"credentials_included"`
	AuthMaterialIncluded                         bool                             `json:"auth_material_included"`
	CertificateOrKeyMaterialIncluded             bool                             `json:"certificate_or_key_material_included"`
	SecretLeakGate                               string                           `json:"secret_leak_gate"`
	NoSecretAttestation                          bool                             `json:"no_secret_attestation"`
	Fixtures                                     []ForwardProxyFixtureObservation `json:"fixtures"`
}

type ForwardProxyFixtureObservation struct {
	FixtureID                              string `json:"fixture_id"`
	FixtureClass                           string `json:"fixture_class"`
	Status                                 string `json:"status"`
	Decision                               string `json:"decision"`
	PolicyID                               string `json:"policy_id"`
	SaaSApplicationID                      string `json:"saas_application_id"`
	ForwardProxyAbsoluteFormRequest        bool   `json:"forward_proxy_absolute_form_request"`
	ProxyHandlerPathObserved               bool   `json:"proxy_handler_path_observed"`
	ProxyRequestDerivedDecisionRequest     bool   `json:"proxy_request_derived_decision_request"`
	DerivedFQDNMatchesFixture              bool   `json:"derived_fqdn_matches_fixture"`
	DerivedSNIMatchesFixture               bool   `json:"derived_sni_matches_fixture"`
	DerivedDestinationPort                 int    `json:"derived_destination_port"`
	DerivedServiceFamily                   string `json:"derived_service_family"`
	LocalHTTPOnly                          bool   `json:"local_http_only"`
	LocalHttptestUpstreamRoundTripObserved bool   `json:"local_httptest_upstream_round_trip_observed"`
	ClientHTTPStatus                       int    `json:"client_http_status"`
	UpstreamHTTPStatus                     int    `json:"upstream_http_status"`
	HeaderName                             string `json:"header_name,omitempty"`
	HeaderValueRef                         string `json:"header_value_ref,omitempty"`
	HeaderValueKind                        string `json:"header_value_kind,omitempty"`
	HeaderApplied                          bool   `json:"header_applied"`
	InjectActionSeen                       bool   `json:"inject_action_seen"`
	HeaderValueResolved                    bool   `json:"header_value_resolved"`
	OperatorConfigRefResolved              bool   `json:"operator_config_ref_resolved"`
	HeaderValueMaterialLogged              bool   `json:"header_value_material_logged"`
	OperatorConfigValueMaterialLogged      bool   `json:"operator_config_value_material_logged"`
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

type forwardProxyFixtureResult struct {
	observation ForwardProxyFixtureObservation
	err         error
}

func RunLocalForwardProxyRoundTripHarness(config HarnessConfig, resolver HeaderValueResolver) (ForwardProxyReport, error) {
	if resolver == nil {
		return ForwardProxyReport{}, fmt.Errorf("header value resolver is required")
	}
	operatorConfig, ok := resolver.(OperatorManagedHeaderValueResolver)
	if !ok {
		return ForwardProxyReport{}, fmt.Errorf("operator-managed header value resolver is required")
	}
	ev := decision.Evaluator{
		Policies:      config.Policies,
		PolicyBundle:  config.PolicyBundle,
		EdgeRegionID:  "local",
		EdgeClusterID: "local-edge-a",
	}

	report := ForwardProxyReport{
		SchemaVersion:                      forwardProxyReportSchemaVersion,
		Status:                             "passed",
		CreatedAt:                          time.Now().UTC().Format(time.RFC3339),
		Milestone:                          forwardProxyMilestone,
		DepthLockedUnit:                    forwardProxyDepthLockedUnit,
		SourceM1584RewriteHarnessGate:      "passed",
		SourceM1586ForwardProxyHarnessGate: "passed",
		HarnessGate:                        "operator_config_resolver_forward_proxy_http_round_trip_harness_passed",
		ForwardProxyStyleRequestPath:       true,
		LocalHTTPOnly:                      true,
		DecisionEvaluatorConnected:         true,
		RewriteHarnessConnected:            true,
		OperatorConfigResolverConnected:    true,
		OperatorConfigRefResolutionCount:   operatorConfig.OperatorConfigRefCount(),
		OperatorConfigRefs:                 operatorConfig.OperatorConfigRefs(),
		OperatorConfigValuesCommitted:      true,
		OperatorConfigValuesSecret:         false,
		ConfigurationRealness:              "operator_managed_config_refs_resolved_by_forward_proxy_local_http_harness",
		GoogleWorkspaceHeader:              GoogleWorkspaceTenantRestrictionHeader,
		Microsoft365Header:                 Microsoft365TenantRestrictionHeader,
		FixtureCount:                       len(config.Fixtures),
		ProxyRequestDerivedDecisionRequest: true,
		DerivedSaaSContextFromProxyRequest: true,
		SecretLeakGate:                     "ok",
		NoSecretAttestation:                true,
	}
	for _, rule := range config.PolicyBundle.SWGTenantRestrictionRules {
		if rule.SaaSApplicationID == "saas_google_workspace" {
			report.GoogleWorkspaceOperatorConfigRef = rule.HeaderValueRef
		}
		if rule.SaaSApplicationID == "saas_microsoft_365" {
			report.Microsoft365OperatorConfigRef = rule.HeaderValueRef
		}
	}

	for _, fixture := range config.Fixtures {
		observation, err := runForwardProxyFixture(fixture, ev, resolver)
		if err != nil {
			return ForwardProxyReport{}, err
		}
		report.Fixtures = append(report.Fixtures, observation)
		applyForwardProxyObservationToReport(&report, observation, fixture)
	}

	return report, nil
}

func runForwardProxyFixture(fixture HarnessFixture, ev decision.Evaluator, resolver HeaderValueResolver) (ForwardProxyFixtureObservation, error) {
	observedCh := make(chan upstreamObservation, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observation := upstreamObservation{
			googleHeaderObserved:       r.Header.Get(GoogleWorkspaceTenantRestrictionHeader) != "",
			microsoft365HeaderObserved: r.Header.Get(Microsoft365TenantRestrictionHeader) != "",
		}
		if fixture.Expected.HeaderInjectionApplied {
			dec := ev.Evaluate(fixture.Request)
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

	resultCh := make(chan forwardProxyFixtureResult, 1)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observation, err := handleForwardProxyFixtureRequest(w, r, fixture, ev, resolver, upstream.URL, observedCh)
		resultCh <- forwardProxyFixtureResult{observation: observation, err: err}
	}))
	defer proxy.Close()

	targetURL, err := forwardProxyFixtureTargetURL(fixture)
	if err != nil {
		return ForwardProxyFixtureObservation{}, err
	}
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		return ForwardProxyFixtureObservation{}, err
	}
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return ForwardProxyFixtureObservation{}, err
	}
	req.Header.Set("X-SWG-Forward-Proxy-Local-HTTP-Harness", "fixture")
	resp, err := client.Do(req)
	if err != nil {
		return ForwardProxyFixtureObservation{}, fmt.Errorf("%s proxy client round trip: %w", fixture.FixtureID, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	proxyResult := <-resultCh
	if proxyResult.err != nil {
		return ForwardProxyFixtureObservation{}, proxyResult.err
	}
	observation := proxyResult.observation
	observation.ClientHTTPStatus = resp.StatusCode
	if resp.StatusCode != http.StatusNoContent {
		return ForwardProxyFixtureObservation{}, fmt.Errorf("%s proxy client status=%d", fixture.FixtureID, resp.StatusCode)
	}
	return observation, nil
}

func handleForwardProxyFixtureRequest(w http.ResponseWriter, r *http.Request, fixture HarnessFixture, ev decision.Evaluator, resolver HeaderValueResolver, upstreamURL string, observedCh <-chan upstreamObservation) (ForwardProxyFixtureObservation, error) {
	observation := ForwardProxyFixtureObservation{
		FixtureID:                       fixture.FixtureID,
		FixtureClass:                    fixture.FixtureClass,
		ProxyHandlerPathObserved:        true,
		ForwardProxyAbsoluteFormRequest: r.URL != nil && r.URL.IsAbs() && r.URL.Host != "",
		LocalHTTPOnly:                   true,
	}
	derivedReq, err := decisionRequestFromForwardProxyRequest(r, fixture.Request)
	if err != nil {
		http.Error(w, "derive request failed", http.StatusBadGateway)
		return observation, fmt.Errorf("%s derive proxy decision request: %w", fixture.FixtureID, err)
	}
	observation.ProxyRequestDerivedDecisionRequest = true
	observation.DerivedFQDNMatchesFixture = sameNormalizedHost(derivedReq.FQDN, fixture.Request.FQDN)
	observation.DerivedSNIMatchesFixture = sameNormalizedHost(derivedReq.SNI, fixture.Request.SNI)
	observation.DerivedDestinationPort = derivedReq.DestinationPort
	observation.DerivedServiceFamily = derivedReq.ServiceFamily

	dec := ev.Evaluate(derivedReq)
	if err := assertDecisionMatchesFixture(fixture, dec); err != nil {
		http.Error(w, "decision mismatch", http.StatusBadGateway)
		return observation, err
	}

	upstreamReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL+r.URL.RequestURI(), r.Body)
	if err != nil {
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return observation, fmt.Errorf("%s build upstream request: %w", fixture.FixtureID, err)
	}
	upstreamReq.Header = forwardProxyRequestHeaders(r.Header)
	rewritten, rewriteResult, err := RewriteRequestFromDecision(upstreamReq, dec, resolver)
	if err != nil {
		http.Error(w, "rewrite failed", http.StatusBadGateway)
		return observation, fmt.Errorf("%s rewrite request: %w", fixture.FixtureID, err)
	}
	resp, err := http.DefaultClient.Do(rewritten)
	if err != nil {
		http.Error(w, "upstream round trip failed", http.StatusBadGateway)
		return observation, fmt.Errorf("%s upstream round trip: %w", fixture.FixtureID, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	observed := <-observedCh

	observation.Status = "passed"
	observation.Decision = dec.Decision
	observation.PolicyID = dec.PolicyID
	observation.SaaSApplicationID = saasApplicationID(dec)
	observation.LocalHttptestUpstreamRoundTripObserved = true
	observation.UpstreamHTTPStatus = resp.StatusCode
	observation.HeaderName = rewriteResult.HeaderName
	observation.HeaderValueRef = rewriteResult.HeaderValueRef
	observation.HeaderValueKind = rewriteResult.HeaderValueKind
	observation.HeaderApplied = rewriteResult.HeaderApplied
	observation.InjectActionSeen = rewriteResult.InjectActionSeen
	observation.HeaderValueResolved = rewriteResult.HeaderValueResolved
	observation.OperatorConfigRefResolved = rewriteResult.HeaderValueResolved && rewriteResult.HeaderValueRef != ""
	observation.HeaderValueMaterialLogged = rewriteResult.HeaderValueMaterialLogged
	observation.OperatorConfigValueMaterialLogged = rewriteResult.HeaderValueMaterialLogged
	observation.UpstreamGoogleHeaderObserved = observed.googleHeaderObserved
	observation.UpstreamMicrosoft365HeaderObserved = observed.microsoft365HeaderObserved
	observation.UpstreamExpectedHeaderObserved = observed.expectedHeaderObserved
	observation.UpstreamUnexpectedTenantHeaderObserved = unexpectedTenantHeaderObserved(fixture, observed)
	observation.TLSBypassApplied = rewriteResult.TLSBypassApplied
	observation.TLSBypassRuleID = rewriteResult.TLSBypassRuleID
	observation.HeaderInjectionSuppressedByBypass = rewriteResult.HeaderInjectionSuppressedByBypass
	observation.RuntimeTLSDecryptionObserved = rewriteResult.RuntimeTLSDecryptionObserved
	observation.RuntimeHeaderInjectionObserved = rewriteResult.RuntimeHeaderInjectionObserved
	observation.NetworkExtensionRuntimeUsed = rewriteResult.NetworkExtensionRuntimeUsed
	observation.LocalHTTPRewriteHarnessObservation = rewriteResult.LocalHTTPRewriteHarnessObservation

	if resp.StatusCode != http.StatusNoContent {
		http.Error(w, "upstream status mismatch", http.StatusBadGateway)
		return observation, fmt.Errorf("%s upstream status=%d", fixture.FixtureID, resp.StatusCode)
	}
	if fixture.Expected.HeaderInjectionApplied && !observed.expectedHeaderValueMatched {
		http.Error(w, "expected header not observed", http.StatusBadGateway)
		return observation, fmt.Errorf("%s expected tenant header was not observed with configured value", fixture.FixtureID)
	}
	if !fixture.Expected.HeaderInjectionApplied && observation.UpstreamUnexpectedTenantHeaderObserved {
		http.Error(w, "unexpected tenant header", http.StatusBadGateway)
		return observation, fmt.Errorf("%s unexpectedly injected tenant header", fixture.FixtureID)
	}

	w.WriteHeader(http.StatusNoContent)
	return observation, nil
}

func decisionRequestFromForwardProxyRequest(r *http.Request, base model.DecisionRequest) (model.DecisionRequest, error) {
	if r == nil || r.URL == nil {
		return model.DecisionRequest{}, fmt.Errorf("http request is required")
	}
	authority := r.URL.Host
	if authority == "" {
		authority = r.Host
	}
	host := normalizedForwardProxyHost(authority)
	if host == "" {
		return model.DecisionRequest{}, fmt.Errorf("forward proxy request missing target host")
	}
	req := base
	req.FQDN = host
	req.SNI = host
	req.Destination = host
	req.DestinationIP = ""
	req.SourceIP = ""
	req.SourcePort = 0
	req.DestinationPort = 443
	req.Protocol = "tcp"
	req.ServiceFamily = "https"
	req.SteeringMode = "network_extension"
	return req, nil
}

func forwardProxyFixtureTargetURL(fixture HarnessFixture) (string, error) {
	host := strings.TrimSpace(fixture.Request.FQDN)
	if host == "" {
		host = strings.TrimSpace(fixture.Request.SNI)
	}
	if host == "" {
		host = strings.TrimSpace(fixture.Request.Destination)
	}
	host = normalizedForwardProxyHost(host)
	if host == "" {
		return "", fmt.Errorf("%s fixture missing forward proxy target host", fixture.FixtureID)
	}
	return "http://" + host + "/swg/forward-proxy-fixture", nil
}

func normalizedForwardProxyHost(authority string) string {
	authority = strings.TrimSpace(strings.ToLower(authority))
	if authority == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(authority); err == nil {
		authority = host
	}
	authority = strings.TrimSuffix(authority, ".")
	return strings.TrimSpace(authority)
}

func sameNormalizedHost(a, b string) bool {
	return normalizedForwardProxyHost(a) == normalizedForwardProxyHost(b)
}

func forwardProxyRequestHeaders(src http.Header) http.Header {
	dst := src.Clone()
	for _, name := range []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Proxy-Connection",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		dst.Del(name)
	}
	// Enterprise-controlled tenant-restriction headers are never client-suppliable. RewriteRequestFromDecision
	// strips them again downstream; stripping here too keeps the proxy safe even if a path skips the rewrite.
	StripEnterpriseControlledHeaders(dst)
	return dst
}

func applyForwardProxyObservationToReport(report *ForwardProxyReport, observation ForwardProxyFixtureObservation, fixture HarnessFixture) {
	if fixture.Expected.HeaderInjectionApplied {
		report.TenantRestrictionHeaderInjectionFixtureCount++
	}
	if fixture.Expected.TLSBypassApplied {
		report.TLSBypassFixtureCount++
	}
	if fixture.Expected.HeaderInjectionSuppressedByBypass {
		report.TLSBypassSuppressionFixtureCount++
	}
	report.ForwardProxyHandlerPathObserved = report.ForwardProxyHandlerPathObserved || observation.ProxyHandlerPathObserved
	report.LocalHttptestUpstreamRoundTripObserved = report.LocalHttptestUpstreamRoundTripObserved || observation.LocalHttptestUpstreamRoundTripObserved
	report.ProxyRequestDerivedDecisionRequest = report.ProxyRequestDerivedDecisionRequest && observation.ProxyRequestDerivedDecisionRequest && observation.DerivedFQDNMatchesFixture && observation.DerivedSNIMatchesFixture
	report.DerivedSaaSContextFromProxyRequest = report.DerivedSaaSContextFromProxyRequest && observation.SaaSApplicationID == fixture.Expected.SaaSApplicationID
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
	report.OperatorConfigValueMaterialLogged = report.OperatorConfigValueMaterialLogged || observation.OperatorConfigValueMaterialLogged
	report.TLSRuntimeDecryptionObserved = report.TLSRuntimeDecryptionObserved || observation.RuntimeTLSDecryptionObserved
	report.HeaderInjectionRuntimeObserved = report.HeaderInjectionRuntimeObserved || observation.RuntimeHeaderInjectionObserved
	report.NetworkExtensionRuntimeUsed = report.NetworkExtensionRuntimeUsed || observation.NetworkExtensionRuntimeUsed
}
