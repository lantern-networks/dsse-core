package swghttprewrite

import (
	"os"
	"testing"
)

func TestSWGForwardProxyHarnessRoundTrip(t *testing.T) {
	cfgPath := "testdata/swg_saas_tenant_enforcement_preflight.json"
	if _, statErr := os.Stat(cfgPath); statErr != nil {
		t.Fatalf("read %s: %v — this fixture ships with the package, so its absence is a broken tree, not a monorepo-only path", cfgPath, statErr)
	}
	config, err := LoadHarnessConfig(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	resolver := loadTrackAOperatorResolver(t, config)
	report, err := RunLocalForwardProxyRoundTripHarness(config, resolver)
	if err != nil {
		t.Fatalf("run forward proxy harness: %v", err)
	}

	if report.SchemaVersion != "swg_operator_config_resolver_product_unit_report.v1" ||
		report.Milestone != "forward_proxy_v1" ||
		report.DepthLockedUnit != "swg_operator_config_resolver_product_unit" ||
		report.SourceM1586ForwardProxyHarnessGate != "passed" ||
		report.HarnessGate != "operator_config_resolver_forward_proxy_http_round_trip_harness_passed" {
		t.Fatalf("report identity = %s/%s/%s/%s", report.SchemaVersion, report.Milestone, report.DepthLockedUnit, report.HarnessGate)
	}
	for field, value := range map[string]bool{
		"forward_proxy_style_request_path":                  report.ForwardProxyStyleRequestPath,
		"forward_proxy_handler_path_observed":               report.ForwardProxyHandlerPathObserved,
		"local_http_only":                                   report.LocalHTTPOnly,
		"local_httptest_upstream_round_trip_observed":       report.LocalHttptestUpstreamRoundTripObserved,
		"decision_evaluator_connected":                      report.DecisionEvaluatorConnected,
		"rewrite_harness_connected":                         report.RewriteHarnessConnected,
		"proxy_request_derived_decision_request":            report.ProxyRequestDerivedDecisionRequest,
		"derived_saas_context_from_proxy_request":           report.DerivedSaaSContextFromProxyRequest,
		"operator_config_resolver_connected":                report.OperatorConfigResolverConnected,
		"operator_config_ref_resolution_count":              report.OperatorConfigRefResolutionCount == 2,
		"operator_config_refs":                              len(report.OperatorConfigRefs) == 2,
		"google_workspace_operator_config_ref":              report.GoogleWorkspaceOperatorConfigRef == "operator_config_ref:google_workspace_allowed_domains",
		"microsoft_365_operator_config_ref":                 report.Microsoft365OperatorConfigRef == "operator_config_ref:microsoft_365_allowed_tenants",
		"operator_config_values_committed":                  report.OperatorConfigValuesCommitted,
		"configuration_realness":                            report.ConfigurationRealness == "operator_managed_config_refs_resolved_by_forward_proxy_local_http_harness",
		"google_workspace_header_injected":                  report.GoogleWorkspaceHeaderInjected,
		"microsoft_365_header_injected":                     report.Microsoft365HeaderInjected,
		"tls_bypass_suppressed_injection":                   report.TLSBypassSuppressedInjection,
		"secret no_secret_attestation":                      report.NoSecretAttestation,
		"secret leak gate ok":                               report.SecretLeakGate == "ok",
		"fixture_count":                                     report.FixtureCount == 4,
		"tenant_restriction_header_injection_fixture_count": report.TenantRestrictionHeaderInjectionFixtureCount == 2,
		"tls_bypass_fixture_count":                          report.TLSBypassFixtureCount == 2,
		"tls_bypass_suppression_fixture_count":              report.TLSBypassSuppressionFixtureCount == 1,
	} {
		if !value {
			t.Fatalf("%s not satisfied; report=%#v", field, report)
		}
	}
	for field, value := range map[string]bool{
		"header_value_material_logged":           report.HeaderValueMaterialLogged,
		"header_value_material_in_decision":      report.HeaderValueMaterialInDecision,
		"operator_config_values_secret":          report.OperatorConfigValuesSecret,
		"operator_config_value_material_logged":  report.OperatorConfigValueMaterialLogged,
		"operator_config_value_material_report":  report.OperatorConfigValueMaterialInReport,
		"captured_secret_material_committed":     report.CapturedSecretMaterialCommitted,
		"productization_claims_made":             report.ProductizationClaimsMade,
		"new_product_claims_made":                report.NewProductClaimsMade,
		"swg_runtime_traffic_observed":           report.SWGRuntimeTrafficObserved,
		"tls_runtime_decryption_observed":        report.TLSRuntimeDecryptionObserved,
		"header_injection_runtime_observed":      report.HeaderInjectionRuntimeObserved,
		"mac_ca_trust_observed":                  report.MacCATrustObserved,
		"network_extension_runtime_used":         report.NetworkExtensionRuntimeUsed,
		"p4_packaging_mdm_signing_install_start": report.P4PackagingMDMSigningInstallStarted,
		"shipping_product_claimed":               report.ShippingProductClaimed,
		"production_scale_claimed":               report.ProductionScaleClaimed,
		"mvp_pilot_success_claimed":              report.MVPPilotSuccessClaimed,
		"windows_work_started":                   report.WindowsWorkStarted,
		"raw_logs_included":                      report.RawLogsIncluded,
		"raw_endpoint_values_included":           report.RawEndpointValuesIncluded,
		"raw_header_values_included":             report.RawHeaderValuesIncluded,
	} {
		if value {
			t.Fatalf("%s = true, want false; report=%#v", field, report)
		}
	}

	fixtures := map[string]ForwardProxyFixtureObservation{}
	for _, fixture := range report.Fixtures {
		fixtures[fixture.FixtureID] = fixture
		assertForwardProxyFixtureCommon(t, fixture)
	}

	google := fixtures["swg_google_workspace_header_injection"]
	if google.PolicyID != "pol_google_workspace_swg_allow_001" ||
		google.SaaSApplicationID != "saas_google_workspace" ||
		google.HeaderName != GoogleWorkspaceTenantRestrictionHeader ||
		google.HeaderValueRef != "operator_config_ref:google_workspace_allowed_domains" ||
		google.HeaderValueKind != "configured_allowed_domains" ||
		!google.HeaderApplied ||
		!google.OperatorConfigRefResolved ||
		!google.UpstreamGoogleHeaderObserved ||
		google.UpstreamMicrosoft365HeaderObserved ||
		!google.UpstreamExpectedHeaderObserved ||
		google.TLSBypassApplied {
		t.Fatalf("google fixture observation = %#v", google)
	}

	microsoft := fixtures["swg_microsoft_365_header_injection"]
	if microsoft.PolicyID != "pol_microsoft_365_swg_allow_001" ||
		microsoft.SaaSApplicationID != "saas_microsoft_365" ||
		microsoft.HeaderName != Microsoft365TenantRestrictionHeader ||
		microsoft.HeaderValueRef != "operator_config_ref:microsoft_365_allowed_tenants" ||
		microsoft.HeaderValueKind != "configured_allowed_tenant_ids" ||
		!microsoft.HeaderApplied ||
		!microsoft.OperatorConfigRefResolved ||
		microsoft.UpstreamGoogleHeaderObserved ||
		!microsoft.UpstreamMicrosoft365HeaderObserved ||
		!microsoft.UpstreamExpectedHeaderObserved ||
		microsoft.TLSBypassApplied {
		t.Fatalf("microsoft fixture observation = %#v", microsoft)
	}

	banking := fixtures["swg_sensitive_banking_tls_bypass"]
	if banking.PolicyID != "pol_sensitive_banking_bypass_allow_001" ||
		banking.SaaSApplicationID != "saas_sensitive_banking" ||
		banking.HeaderApplied ||
		banking.UpstreamGoogleHeaderObserved ||
		banking.UpstreamMicrosoft365HeaderObserved ||
		!banking.TLSBypassApplied ||
		banking.TLSBypassRuleID != "swg_tls_bypass_banking_category" ||
		banking.HeaderInjectionSuppressedByBypass {
		t.Fatalf("banking fixture observation = %#v", banking)
	}

	pinned := fixtures["swg_pinned_google_tls_bypass_suppresses_header"]
	if pinned.PolicyID != "pol_google_workspace_swg_allow_001" ||
		pinned.SaaSApplicationID != "saas_google_workspace" ||
		pinned.HeaderApplied ||
		pinned.UpstreamGoogleHeaderObserved ||
		pinned.UpstreamMicrosoft365HeaderObserved ||
		!pinned.TLSBypassApplied ||
		pinned.TLSBypassRuleID != "swg_tls_bypass_pinned_google_exact" ||
		!pinned.HeaderInjectionSuppressedByBypass {
		t.Fatalf("pinned fixture observation = %#v", pinned)
	}
}

func assertForwardProxyFixtureCommon(t *testing.T, fixture ForwardProxyFixtureObservation) {
	t.Helper()
	for field, value := range map[string]bool{
		"status":                                   fixture.Status == "passed",
		"decision":                                 fixture.Decision == "allow",
		"forward_proxy_absolute_form_request":      fixture.ForwardProxyAbsoluteFormRequest,
		"proxy_handler_path_observed":              fixture.ProxyHandlerPathObserved,
		"proxy_request_derived_decision_request":   fixture.ProxyRequestDerivedDecisionRequest,
		"derived_fqdn_matches_fixture":             fixture.DerivedFQDNMatchesFixture,
		"derived_sni_matches_fixture":              fixture.DerivedSNIMatchesFixture,
		"derived_destination_port":                 fixture.DerivedDestinationPort == 443,
		"derived_service_family":                   fixture.DerivedServiceFamily == "https",
		"local_http_only":                          fixture.LocalHTTPOnly,
		"local_httptest_upstream_round_trip":       fixture.LocalHttptestUpstreamRoundTripObserved,
		"client_http_status":                       fixture.ClientHTTPStatus == 204,
		"upstream_http_status":                     fixture.UpstreamHTTPStatus == 204,
		"local_http_rewrite_harness_observation":   fixture.LocalHTTPRewriteHarnessObservation,
		"header_value_material_logged false":       !fixture.HeaderValueMaterialLogged,
		"runtime_tls_decryption_observed false":    !fixture.RuntimeTLSDecryptionObserved,
		"runtime_header_injection_observed false":  !fixture.RuntimeHeaderInjectionObserved,
		"network_extension_runtime_used false":     !fixture.NetworkExtensionRuntimeUsed,
		"unexpected tenant header observed false":  !fixture.UpstreamUnexpectedTenantHeaderObserved,
		"upstream_expected_header_for_inject_only": fixture.UpstreamExpectedHeaderObserved == fixture.HeaderApplied,
		"operator_config_ref_resolved_for_inject":  fixture.OperatorConfigRefResolved == fixture.HeaderApplied,
		"operator_config_value_material_logged":    !fixture.OperatorConfigValueMaterialLogged,
	} {
		if !value {
			t.Fatalf("%s not satisfied for fixture %#v", field, fixture)
		}
	}
}

func loadTrackAOperatorResolver(t *testing.T, config HarnessConfig) OperatorManagedHeaderValueResolver {
	t.Helper()
	opPath := "testdata/swg_tenant_restriction_operator_config.json"
	if _, statErr := os.Stat(opPath); statErr != nil {
		t.Skipf("fixture not shipped with the dsse-core module (monorepo-only): %s", opPath)
	}
	resolver, err := LoadOperatorManagedHeaderValueResolver(opPath, config.PolicyBundle)
	if err != nil {
		t.Fatalf("load operator config: %v", err)
	}
	return resolver
}
