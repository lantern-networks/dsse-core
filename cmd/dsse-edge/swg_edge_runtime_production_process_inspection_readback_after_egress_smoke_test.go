package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
	swg "github.com/lantern-networks/dsse-core/swg"

	"github.com/lantern-networks/dsse-core/swghttprewrite"
)

const (
	sWGEdgeRuntimeProductionProcessInspectionReadbackAfterEgressSmokeReportEnv = "SWG_EDGE_RUNTIME_PRODUCTION_PROCESS_INSPECTION_READBACK_AFTER_EGRESS_SMOKE_REPORT"
	sWGEdgeRuntimeProductionProcessInspectionReadbackAfterEgressSmokeDSNEnv    = "SWG_EDGE_RUNTIME_PRODUCTION_PROCESS_INSPECTION_READBACK_AFTER_EGRESS_SMOKE_POSTGRES_DSN"
)

func TestSWGEdgeSWGProductionProcessInspectionReadbackAfterEgressSmoke(t *testing.T) {
	postgresDSN := strings.TrimSpace(os.Getenv(sWGEdgeRuntimeProductionProcessInspectionReadbackAfterEgressSmokeDSNEnv))
	if postgresDSN == "" {
		t.Skipf("%s is required for production-mode cmd/edge process inspection readback after egress smoke", sWGEdgeRuntimeProductionProcessInspectionReadbackAfterEgressSmokeDSNEnv)
	}

	moduleRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve module root: %v", err)
	}
	repoRoot, err := filepath.Abs(filepath.Join(moduleRoot, ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}

	workDir := t.TempDir()
	policyPaths, bundlePath := m1602WriteProcessEgressRuntimeInputs(t, filepath.Join(moduleRoot, "swghttprewrite", "testdata", "swg_saas_tenant_enforcement_preflight.json"), workDir)

	binaryPath := filepath.Join(workDir, "edge-process-inspection-readback-after-egress-smoke")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	build.Dir = filepath.Join(moduleRoot, "cmd", "edge")
	build.Env = os.Environ()
	build.Stdout = io.Discard
	var buildErr bytes.Buffer
	build.Stderr = &buildErr
	if err := build.Run(); err != nil {
		t.Fatalf("build cmd/edge failed: %v; stderr redacted=%s", err, m1600RedactedLine(buildErr.String()))
	}

	proxy := m1602StartLocalCaptureProxy(t)
	operatorConfigPath := filepath.Join(moduleRoot, "swghttprewrite", "testdata", "swg_tenant_restriction_operator_config.json")
	common := m1602ProcessEgressInputs{
		ModuleRoot:         moduleRoot,
		RepoRoot:           repoRoot,
		WorkDir:            workDir,
		BinaryPath:         binaryPath,
		PolicyPaths:        policyPaths,
		BundlePath:         bundlePath,
		OperatorConfigPath: operatorConfigPath,
		PostgresDSN:        postgresDSN,
		ProxyURL:           proxy.URL,
		Proxy:              proxy,
	}

	runtimeTLSMissing := m1603RunProcessEgressReadbackCase(t, common, m1602ReadinessProcessCase{
		Name:                        "runtime_tls_missing",
		RuntimeTLSObservedFlagInput: false,
		MacCATrustObservedFlagInput: false,
		Requests: []m1602EgressRequestCase{
			{
				Name:                        "google_workspace_tls_missing",
				TargetURL:                   "http://mail.google.com:443/lab/product-egress",
				WantStatusCode:              http.StatusPreconditionRequired,
				WantReadinessDependency:     edgeplane.EdgeSWGHTTPEgressReadinessReason,
				WantSaaSApplicationID:       "saas_google_workspace",
				WantPolicyID:                "pol_google_workspace_swg_allow_001",
				WantDefaultTLSObserved:      false,
				WantMacCATrustObserved:      false,
				WantForwarded:               false,
				WantHeaderName:              swghttprewrite.GoogleWorkspaceTenantRestrictionHeader,
				WantCurrentTLSBypassApplied: false,
			},
			{
				Name:                        "pinned_google_tls_bypass_with_missing_readiness",
				TargetURL:                   "http://pinned-client.google.com:443/lab/product-egress",
				WantStatusCode:              http.StatusNoContent,
				WantReadinessDependency:     "none",
				WantSaaSApplicationID:       "saas_google_workspace",
				WantPolicyID:                "pol_google_workspace_swg_allow_001",
				WantDefaultTLSObserved:      false,
				WantMacCATrustObserved:      false,
				WantForwarded:               true,
				WantHeaderName:              "",
				WantCurrentTLSBypassApplied: true,
				WantTLSBypassRuleID:         "swg_tls_bypass_pinned_google_exact",
			},
		},
	})

	tlsObservedMacCAMissing := m1603RunProcessEgressReadbackCase(t, common, m1602ReadinessProcessCase{
		Name:                        "tls_observed_mac_ca_missing",
		RuntimeTLSObservedFlagInput: true,
		MacCATrustObservedFlagInput: false,
		Requests: []m1602EgressRequestCase{
			{
				Name:                        "google_workspace_mac_ca_missing",
				TargetURL:                   "http://mail.google.com:443/lab/product-egress",
				WantStatusCode:              http.StatusPreconditionRequired,
				WantReadinessDependency:     edgeplane.EdgeSWGHTTPEgressMacCAReason,
				WantSaaSApplicationID:       "saas_google_workspace",
				WantPolicyID:                "pol_google_workspace_swg_allow_001",
				WantDefaultTLSObserved:      true,
				WantMacCATrustObserved:      false,
				WantForwarded:               false,
				WantHeaderName:              swghttprewrite.GoogleWorkspaceTenantRestrictionHeader,
				WantCurrentTLSBypassApplied: false,
			},
		},
	})

	bothSignalsObserved := m1603RunProcessEgressReadbackCase(t, common, m1602ReadinessProcessCase{
		Name:                        "both_readiness_signals_observed",
		RuntimeTLSObservedFlagInput: true,
		MacCATrustObservedFlagInput: true,
		Requests: []m1602EgressRequestCase{
			{
				Name:                        "google_workspace_ready",
				TargetURL:                   "http://mail.google.com:443/lab/product-egress",
				WantStatusCode:              http.StatusNoContent,
				WantReadinessDependency:     "none",
				WantSaaSApplicationID:       "saas_google_workspace",
				WantPolicyID:                "pol_google_workspace_swg_allow_001",
				WantDefaultTLSObserved:      true,
				WantMacCATrustObserved:      true,
				WantForwarded:               true,
				WantHeaderName:              swghttprewrite.GoogleWorkspaceTenantRestrictionHeader,
				WantCurrentTLSBypassApplied: false,
			},
			{
				Name:                        "microsoft_365_ready",
				TargetURL:                   "http://www.office.com:443/lab/product-egress",
				WantStatusCode:              http.StatusNoContent,
				WantReadinessDependency:     "none",
				WantSaaSApplicationID:       "saas_microsoft_365",
				WantPolicyID:                "pol_microsoft_365_swg_allow_001",
				WantDefaultTLSObserved:      true,
				WantMacCATrustObserved:      true,
				WantForwarded:               true,
				WantHeaderName:              swghttprewrite.Microsoft365TenantRestrictionHeader,
				WantCurrentTLSBypassApplied: false,
			},
		},
	})

	report := m1603ProcessInspectionReadbackAfterEgressReport(runtimeTLSMissing, tlsObservedMacCAMissing, bothSignalsObserved)
	forbidden := []string{
		"google-workspace.lab.example",
		"microsoft-365-tenant.lab.example",
		"swg_tenant_restriction_operator_config.json",
		"connector-auth-value",
		"attestation-auth-value",
		postgresDSN,
		proxy.URL,
		"127.0.0.1",
		"mail.google.com",
		"www.office.com",
		"pinned-client.google.com",
	}
	for _, processCase := range []m1603ReadinessProcessCaseResult{runtimeTLSMissing, tlsObservedMacCAMissing, bothSignalsObserved} {
		for _, request := range processCase.Requests {
			m1600AssertNoForbiddenMaterial(t, request.Egress.Case.Name+" diagnostic", request.Egress.Diagnostic, forbidden[:6])
		}
	}
	m1600AssertNoForbiddenMaterial(t, "report", report, forbidden)

	if path := strings.TrimSpace(os.Getenv(sWGEdgeRuntimeProductionProcessInspectionReadbackAfterEgressSmokeReportEnv)); path != "" {
		writeSWGM1600JSON(t, path, report)
	}
}

type m1603ReadinessProcessCaseResult struct {
	Case             m1602ReadinessProcessCase
	Health           map[string]any
	HealthStatusCode int
	Requests         []m1603EgressRequestResult
}

type m1603EgressRequestResult struct {
	Egress         m1602EgressRequestResult
	StatusReadback map[string]any
}

func m1603RunProcessEgressReadbackCase(t *testing.T, inputs m1602ProcessEgressInputs, processCase m1602ReadinessProcessCase) m1603ReadinessProcessCaseResult {
	t.Helper()
	listen := m1600FreeListenAddress(t)
	baseURL := "http://" + listen
	connectorAuthValue := "connector-auth-value-" + processCase.Name
	attestationAuthValue := "attestation-auth-value-" + processCase.Name
	logDir := filepath.Join(inputs.WorkDir, "logs", "inspection-readback", processCase.Name)

	args := []string{
		// Single-process smoke: not a deployment, so it says so (see requireControlPlaneOrExit).
		"-no-control-plane",
		"-mode", "edge",
		"-listen", listen,
		"-policy", strings.Join(inputs.PolicyPaths, ","),
		"-bundle", inputs.BundlePath,
		"-schema-dir", filepath.Join(inputs.RepoRoot, "schemas"),
		"-migration-dir", filepath.Join(inputs.ModuleRoot, "migrations"),
		"-log-dir", logDir,
		"-lab-mode=false",
		"-connector-secret", connectorAuthValue,
		"-workload-attestation-secret", attestationAuthValue,
		"-workload-attestation-nonce-store", "postgres",
		"-workload-attestation-nonce-postgres-dsn", inputs.PostgresDSN,
		"-swg-tenant-restriction-operator-config", inputs.OperatorConfigPath,
	}
	if processCase.RuntimeTLSObservedFlagInput {
		args = append(args, "-swg-runtime-tls-decryption-observed")
	}
	if processCase.MacCATrustObservedFlagInput {
		args = append(args, "-swg-mac-ca-trust-observed")
	}

	cmd := exec.CommandContext(context.Background(), inputs.BinaryPath, args...)
	cmd.Dir = inputs.ModuleRoot
	cmd.Env = append(os.Environ(),
		"HTTP_PROXY="+inputs.ProxyURL,
		"http_proxy="+inputs.ProxyURL,
		"HTTPS_PROXY=",
		"https_proxy=",
		"ALL_PROXY=",
		"all_proxy=",
		"NO_PROXY=",
		"no_proxy=",
	)
	cmd.Stdout = io.Discard
	var processErr bytes.Buffer
	cmd.Stderr = &processErr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start cmd/edge process for %s: %v", processCase.Name, err)
	}
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()
	defer m1600StopProcess(t, cmd, waitCh)

	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	health := m1600WaitForHealthz(t, client, baseURL, waitCh, &processErr)
	results := make([]m1603EgressRequestResult, 0, len(processCase.Requests))
	visibleHeaderNames := []string{}
	visibleOperatorRefs := []string{}
	for index, requestCase := range processCase.Requests {
		egress := m1602DoEgressRequest(t, client, baseURL, connectorAuthValue, inputs.Proxy, waitCh, &processErr, requestCase)
		status := m1600GetJSON(t, client, baseURL+swg.EdgeSWGTLSReadinessStatusPath, connectorAuthValue, waitCh, &processErr)
		visibleHeaderNames = swg.AppendUniqueNonEmpty(visibleHeaderNames, m1603InspectionHeaderName(requestCase))
		visibleOperatorRefs = swg.AppendUniqueNonEmpty(visibleOperatorRefs, m1603InspectionOperatorConfigRef(requestCase))
		wantHeaderNames := append([]string{}, visibleHeaderNames...)
		wantOperatorRefs := append([]string{}, visibleOperatorRefs...)
		sort.Strings(wantHeaderNames)
		sort.Strings(wantOperatorRefs)
		m1603AssertInspectionStatusAfterEgress(t, processCase, requestCase, status, index+1, wantHeaderNames, wantOperatorRefs)
		results = append(results, m1603EgressRequestResult{Egress: egress, StatusReadback: status})
		if index+1 < len(processCase.Requests) {
			time.Sleep(1100 * time.Millisecond)
		}
	}
	return m1603ReadinessProcessCaseResult{
		Case:             processCase,
		Health:           health,
		HealthStatusCode: http.StatusOK,
		Requests:         results,
	}
}

func m1603AssertInspectionStatusAfterEgress(t *testing.T, processCase m1602ReadinessProcessCase, requestCase m1602EgressRequestCase, status map[string]any, wantEventCount int, wantHeaderNames, wantOperatorRefs []string) {
	t.Helper()
	wantDefaultTLSStatus := swg.TlsReadinessRequiredObservedStatus(true, requestCase.WantDefaultTLSObserved)
	wantVisibilityStatus := swg.TlsReadinessVisibilityStatus(true, requestCase.WantDefaultTLSObserved)
	wantMacCATrustStatus := swg.MacCATrustRequiredStatus(true, requestCase.WantMacCATrustObserved)
	for key, want := range map[string]any{
		"schema_version":                           "swg_tls_readiness_status.v1",
		"status":                                   wantVisibilityStatus,
		"tenant_id":                                "tenant_swg_lab",
		"policy_bundle_id":                         "pb_swg_preflight_m1583",
		"policy_bundle_version":                    "swg-saas-tenant-preflight",
		"readback_path":                            swg.EdgeSWGTLSReadinessStatusPath,
		"edge_http_egress_handler_path":            edgeplane.EdgeSWGHTTPEgressPath,
		"default_tls_decryption_required":          true,
		"default_tls_decryption_observed":          requestCase.WantDefaultTLSObserved,
		"default_tls_decryption_status":            wantDefaultTLSStatus,
		"tenant_header_rewrite_dependency_count":   float64(2),
		"per_destination_tls_bypass_required":      true,
		"tls_bypass_rule_count":                    float64(2),
		"mac_ca_trust_required":                    true,
		"mac_ca_trust_observed":                    requestCase.WantMacCATrustObserved,
		"mac_ca_trust_mutated":                     false,
		"mac_ca_trust_status":                      wantMacCATrustStatus,
		"inspection_metadata_readback_observed":    true,
		"inspection_event_count":                   float64(wantEventCount),
		"runtime_tls_decryption_observed":          requestCase.WantDefaultTLSObserved,
		"runtime_header_injection_observed":        false,
		"network_extension_runtime_used":           false,
		"swg_runtime_traffic_observed":             false,
		"real_tls_interception_runtime_executed":   false,
		"header_value_material_in_status":          false,
		"operator_config_value_material_in_status": false,
		"mac_ca_trust_mutation_started":            false,
		"p4_packaging_mdm_signing_install_started": false,
		"shipping_product_claimed":                 false,
		"production_scale_claimed":                 false,
		"mvp_pilot_success_claimed":                false,
		"windows_work_started":                     false,
		"productization_claims_made":               false,
		"new_product_claims_made":                  false,
		"secret_leak_gate":                         "ok",
		"no_secret_attestation":                    true,
	} {
		if got := status[key]; got != want {
			t.Fatalf("%s status[%s] = %#v, want %#v; status=%#v", requestCase.Name, key, got, want, status)
		}
	}
	if processCase.RuntimeTLSObservedFlagInput != requestCase.WantDefaultTLSObserved {
		t.Fatalf("%s runtime TLS flag input = %v, request expectation = %v", requestCase.Name, processCase.RuntimeTLSObservedFlagInput, requestCase.WantDefaultTLSObserved)
	}
	if processCase.MacCATrustObservedFlagInput != requestCase.WantMacCATrustObserved {
		t.Fatalf("%s Mac CA flag input = %v, request expectation = %v", requestCase.Name, processCase.MacCATrustObservedFlagInput, requestCase.WantMacCATrustObserved)
	}
	if !m1600StringArrayEquals(status["required_inspection_profile_ids"], []string{"ip_swg_default_tls_decrypt"}) {
		t.Fatalf("%s required inspection profiles = %#v", requestCase.Name, status["required_inspection_profile_ids"])
	}
	if !m1600StringArrayEquals(status["mac_trust_profile_ids"], []string{"tp_swg_mac_trust"}) {
		t.Fatalf("%s Mac trust profiles = %#v", requestCase.Name, status["mac_trust_profile_ids"])
	}
	if !m1600StringArrayEquals(status["tenant_root_ca_ids"], []string{"trca_swg_lab"}) {
		t.Fatalf("%s tenant root CAs = %#v", requestCase.Name, status["tenant_root_ca_ids"])
	}
	deps, ok := status["tenant_header_rewrite_dependencies"].([]any)
	if !ok || len(deps) != 2 {
		t.Fatalf("%s tenant header dependencies = %#v", requestCase.Name, status["tenant_header_rewrite_dependencies"])
	}
	m1600AssertDependency(t, deps, swghttprewrite.GoogleWorkspaceTenantRestrictionHeader, "operator_config_ref:google_workspace_allowed_domains")
	m1600AssertDependency(t, deps, swghttprewrite.Microsoft365TenantRestrictionHeader, "operator_config_ref:microsoft_365_allowed_tenants")
	bypassRules, ok := status["tls_bypass_rules"].([]any)
	if !ok || len(bypassRules) != 2 || !m1600RulePresent(bypassRules, "swg_tls_bypass_banking_category") || !m1600RulePresent(bypassRules, "swg_tls_bypass_pinned_google_exact") {
		t.Fatalf("%s TLS bypass rules = %#v", requestCase.Name, status["tls_bypass_rules"])
	}
	inspectionMetadata, ok := status["inspection_metadata"].(map[string]any)
	if !ok {
		t.Fatalf("%s inspection metadata = %#v", requestCase.Name, status["inspection_metadata"])
	}
	wantGoogle, wantMicrosoft, wantTLSSuppress := m1603InspectionOutcomes(requestCase)
	for key, want := range map[string]any{
		"latest_event_type":                              edgeplane.EdgeSWGHTTPEgressRewriteEvent,
		"latest_finding_type":                            "saas_tenant_restriction_rewrite",
		"google_workspace_rewrite_outcome":               wantGoogle,
		"microsoft_365_rewrite_outcome":                  wantMicrosoft,
		"tls_bypass_suppression_outcome":                 wantTLSSuppress,
		"header_value_material_in_inspection_event":      false,
		"header_value_material_in_api_readback":          false,
		"operator_config_value_material_in_inspection":   false,
		"operator_config_value_material_in_api_readback": false,
	} {
		if got := inspectionMetadata[key]; got != want {
			t.Fatalf("%s inspection metadata[%s] = %#v, want %#v; metadata=%#v", requestCase.Name, key, got, want, inspectionMetadata)
		}
	}
	if !m1600StringArrayEquals(inspectionMetadata["header_names_visible"], wantHeaderNames) {
		t.Fatalf("%s inspection header names = %#v, want %#v", requestCase.Name, inspectionMetadata["header_names_visible"], wantHeaderNames)
	}
	if !m1600StringArrayEquals(inspectionMetadata["operator_config_refs_visible"], wantOperatorRefs) {
		t.Fatalf("%s inspection operator refs = %#v, want %#v", requestCase.Name, inspectionMetadata["operator_config_refs_visible"], wantOperatorRefs)
	}
	if _, ok := status["latest_inspection_event_id"].(string); !ok {
		t.Fatalf("%s latest inspection event id absent", requestCase.Name)
	}
	if _, ok := status["latest_access_decision_id"].(string); !ok {
		t.Fatalf("%s latest access decision id absent", requestCase.Name)
	}
}

func m1603InspectionOutcomes(requestCase m1602EgressRequestCase) (string, string, string) {
	if requestCase.WantCurrentTLSBypassApplied {
		return "suppressed_by_tls_bypass", "not_applicable", "header_injection_suppressed"
	}
	switch requestCase.WantSaaSApplicationID {
	case "saas_google_workspace":
		return "rewritten_by_operator_config_ref", "not_applicable", "not_applied"
	case "saas_microsoft_365":
		return "not_applicable", "rewritten_by_operator_config_ref", "not_applied"
	default:
		return "not_applicable", "not_applicable", "not_applied"
	}
}

func m1603InspectionHeaderName(requestCase m1602EgressRequestCase) string {
	switch requestCase.WantSaaSApplicationID {
	case "saas_google_workspace":
		return swghttprewrite.GoogleWorkspaceTenantRestrictionHeader
	case "saas_microsoft_365":
		return swghttprewrite.Microsoft365TenantRestrictionHeader
	default:
		return ""
	}
}

func m1603InspectionOperatorConfigRef(requestCase m1602EgressRequestCase) string {
	switch requestCase.WantSaaSApplicationID {
	case "saas_google_workspace":
		return "operator_config_ref:google_workspace_allowed_domains"
	case "saas_microsoft_365":
		return "operator_config_ref:microsoft_365_allowed_tenants"
	default:
		return ""
	}
}

func m1603ProcessInspectionReadbackAfterEgressReport(runtimeTLSMissing, tlsObservedMacCAMissing, bothSignalsObserved m1603ReadinessProcessCaseResult) map[string]any {
	tlsMissingGoogle := m1603RequestResultByName(runtimeTLSMissing, "google_workspace_tls_missing")
	tlsMissingBypass := m1603RequestResultByName(runtimeTLSMissing, "pinned_google_tls_bypass_with_missing_readiness")
	macCAMissingGoogle := m1603RequestResultByName(tlsObservedMacCAMissing, "google_workspace_mac_ca_missing")
	readyGoogle := m1603RequestResultByName(bothSignalsObserved, "google_workspace_ready")
	readyMicrosoft := m1603RequestResultByName(bothSignalsObserved, "microsoft_365_ready")

	return map[string]any{
		"schema_version":    "swg_edge_runtime_production_process_inspection_readback_after_egress_smoke.v1",
		"status":            "passed",
		"depth_locked_unit": "swg_edge_runtime_production_process_inspection_readback_after_egress_smoke_product_unit",
		"source_m1602_process_egress_readiness_matrix_smoke_gate":             "accepted",
		"egress_readiness_matrix_replayed":                                    true,
		"inspection_readback_source":                                          "cmd_edge_process_tls_readiness_status_after_http_egress",
		"cmd_edge_process_inspection_readback_after_egress_smoke_gate":        "passed",
		"cmd_edge_process_started":                                            true,
		"cmd_edge_process_launch_count":                                       3,
		"cmd_edge_process_output_included":                                    false,
		"raw_command_output_included":                                         false,
		"raw_process_output_included":                                         false,
		"process_id_included":                                                 false,
		"process_listen_address_material_in_report":                           false,
		"runtime_auth_material_in_report":                                     false,
		"postgres_dsn_material_in_report":                                     false,
		"upstream_proxy_address_material_in_report":                           false,
		"target_url_material_in_report":                                       false,
		"target_fqdn_material_in_report":                                      false,
		"startup_flag_names_exercised":                                        []string{"-swg-tenant-restriction-operator-config", "-swg-runtime-tls-decryption-observed", "-swg-mac-ca-trust-observed"},
		"production_mode_lab_mode":                                            false,
		"healthz_readback_observed":                                           runtimeTLSMissing.Health["status"] == "ok" && tlsObservedMacCAMissing.Health["status"] == "ok" && bothSignalsObserved.Health["status"] == "ok",
		"healthz_status_code":                                                 http.StatusOK,
		"edge_http_egress_handler_path":                                       edgeplane.EdgeSWGHTTPEgressPath,
		"tls_readiness_status_api_path":                                       swg.EdgeSWGTLSReadinessStatusPath,
		"http_egress_case_count":                                              5,
		"tls_readiness_status_readback_count":                                 5,
		"inspection_metadata_readback_after_egress_observed":                  true,
		"google_workspace_inspection_metadata_readback_observed":              m1603InspectionMetadataObserved(tlsMissingGoogle) && m1603InspectionMetadataObserved(macCAMissingGoogle) && m1603InspectionMetadataObserved(readyGoogle),
		"microsoft_365_inspection_metadata_readback_observed":                 m1603InspectionMetadataObserved(readyMicrosoft),
		"tls_bypass_inspection_metadata_readback_observed":                    m1603InspectionMetadataObserved(tlsMissingBypass),
		"runtime_tls_missing_google_workspace_status_code":                    tlsMissingGoogle.Egress.StatusCode,
		"runtime_tls_missing_google_workspace_readiness_dependency":           tlsMissingGoogle.Egress.Diagnostic["readiness_dependency"],
		"runtime_tls_missing_google_workspace_egress_forwarded":               tlsMissingGoogle.Egress.Diagnostic["egress_forwarded"],
		"runtime_tls_missing_google_workspace_inspection_event_count":         tlsMissingGoogle.StatusReadback["inspection_event_count"],
		"runtime_tls_missing_google_workspace_status_visibility":              tlsMissingGoogle.StatusReadback["status"],
		"runtime_tls_missing_google_workspace_rewrite_outcome":                m1603InspectionMetadataValue(tlsMissingGoogle, "google_workspace_rewrite_outcome"),
		"runtime_tls_missing_google_workspace_tls_bypass_suppression_outcome": m1603InspectionMetadataValue(tlsMissingGoogle, "tls_bypass_suppression_outcome"),
		"tls_bypass_with_missing_readiness_status_code":                       tlsMissingBypass.Egress.StatusCode,
		"tls_bypass_with_missing_readiness_readiness_dependency":              "none",
		"tls_bypass_with_missing_readiness_egress_forwarded":                  tlsMissingBypass.Egress.UpstreamRequestObserved,
		"tls_bypass_with_missing_readiness_rule_id":                           tlsMissingBypass.Egress.Case.WantTLSBypassRuleID,
		"tls_bypass_with_missing_readiness_header_injection_suppressed":       !tlsMissingBypass.Egress.GoogleWorkspaceHeaderNameForwarded && !tlsMissingBypass.Egress.Microsoft365HeaderNameForwarded,
		"tls_bypass_with_missing_readiness_inspection_event_count":            tlsMissingBypass.StatusReadback["inspection_event_count"],
		"tls_bypass_with_missing_readiness_status_visibility":                 tlsMissingBypass.StatusReadback["status"],
		"tls_bypass_with_missing_readiness_google_workspace_rewrite_outcome":  m1603InspectionMetadataValue(tlsMissingBypass, "google_workspace_rewrite_outcome"),
		"tls_bypass_with_missing_readiness_tls_bypass_suppression_outcome":    m1603InspectionMetadataValue(tlsMissingBypass, "tls_bypass_suppression_outcome"),
		"tls_observed_mac_ca_missing_google_workspace_status_code":            macCAMissingGoogle.Egress.StatusCode,
		"tls_observed_mac_ca_missing_google_workspace_readiness_dependency":   macCAMissingGoogle.Egress.Diagnostic["readiness_dependency"],
		"tls_observed_mac_ca_missing_google_workspace_egress_forwarded":       macCAMissingGoogle.Egress.Diagnostic["egress_forwarded"],
		"tls_observed_mac_ca_missing_google_workspace_inspection_event_count": macCAMissingGoogle.StatusReadback["inspection_event_count"],
		"tls_observed_mac_ca_missing_google_workspace_status_visibility":      macCAMissingGoogle.StatusReadback["status"],
		"tls_observed_mac_ca_missing_google_workspace_rewrite_outcome":        m1603InspectionMetadataValue(macCAMissingGoogle, "google_workspace_rewrite_outcome"),
		"both_readiness_google_workspace_status_code":                         readyGoogle.Egress.StatusCode,
		"both_readiness_google_workspace_readiness_dependency":                "none",
		"both_readiness_google_workspace_egress_forwarded":                    readyGoogle.Egress.UpstreamRequestObserved,
		"both_readiness_google_workspace_header_name_forwarded":               readyGoogle.Egress.GoogleWorkspaceHeaderNameForwarded,
		"both_readiness_google_workspace_other_tenant_header_suppressed":      !readyGoogle.Egress.Microsoft365HeaderNameForwarded,
		"both_readiness_google_workspace_inspection_event_count":              readyGoogle.StatusReadback["inspection_event_count"],
		"both_readiness_google_workspace_status_visibility":                   readyGoogle.StatusReadback["status"],
		"both_readiness_google_workspace_rewrite_outcome":                     m1603InspectionMetadataValue(readyGoogle, "google_workspace_rewrite_outcome"),
		"both_readiness_microsoft_365_status_code":                            readyMicrosoft.Egress.StatusCode,
		"both_readiness_microsoft_365_readiness_dependency":                   "none",
		"both_readiness_microsoft_365_egress_forwarded":                       readyMicrosoft.Egress.UpstreamRequestObserved,
		"both_readiness_microsoft_365_header_name_forwarded":                  readyMicrosoft.Egress.Microsoft365HeaderNameForwarded,
		"both_readiness_microsoft_365_other_tenant_header_suppressed":         !readyMicrosoft.Egress.GoogleWorkspaceHeaderNameForwarded,
		"both_readiness_microsoft_365_inspection_event_count":                 readyMicrosoft.StatusReadback["inspection_event_count"],
		"both_readiness_microsoft_365_status_visibility":                      readyMicrosoft.StatusReadback["status"],
		"both_readiness_microsoft_365_rewrite_outcome":                        m1603InspectionMetadataValue(readyMicrosoft, "microsoft_365_rewrite_outcome"),
		"external_saas_egress_attempted":                                      false,
		"local_capture_upstream_used":                                         true,
		"header_values_forwarded_upstream_only":                               true,
		"header_value_material_in_status":                                     false,
		"header_value_material_in_report":                                     false,
		"operator_config_value_material_in_status":                            false,
		"operator_config_value_material_in_report":                            false,
		"operator_config_path_material_in_report":                             false,
		"operator_managed_tenant_header_config_loaded":                        true,
		"tenant_header_rewrite_dependency_count":                              float64(2),
		"operator_config_refs_visible":                                        []string{"operator_config_ref:google_workspace_allowed_domains", "operator_config_ref:microsoft_365_allowed_tenants"},
		"header_names_visible":                                                []string{"X-GoogApps-Allowed-Domains", "Restrict-Access-To-Tenants"},
		"per_destination_tls_bypass_required":                                 true,
		"tls_bypass_rule_count":                                               float64(2),
		"latest_inspection_event_id_material_in_report":                       false,
		"latest_access_decision_id_material_in_report":                        false,
		"swg_runtime_traffic_observed":                                        false,
		"real_tls_interception_runtime_executed":                              false,
		"tls_runtime_decryption_observed":                                     false,
		"header_injection_runtime_observed":                                   false,
		"mac_ca_trust_mutation_started":                                       false,
		"mac_ca_trust_mutated":                                                false,
		"network_extension_runtime_used":                                      false,
		"human_boundary_created":                                              false,
		"gui_buildout_started":                                                false,
		"presentation_only_ui_proxy_topology_started":                         false,
		"p4_packaging_mdm_signing_install_started":                            false,
		"shipping_product_claimed":                                            false,
		"production_scale_claimed":                                            false,
		"mvp_pilot_success_claimed":                                           false,
		"windows_work_started":                                                false,
		"productization_claims_made":                                          false,
		"new_product_claims_made":                                             false,
		"secret_leak_gate":                                                    "ok",
		"no_secret_attestation":                                               true,
	}
}

func m1603RequestResultByName(result m1603ReadinessProcessCaseResult, name string) m1603EgressRequestResult {
	for _, request := range result.Requests {
		if request.Egress.Case.Name == name {
			return request
		}
	}
	return m1603EgressRequestResult{}
}

func m1603InspectionMetadataObserved(result m1603EgressRequestResult) bool {
	observed, _ := result.StatusReadback["inspection_metadata_readback_observed"].(bool)
	return observed
}

func m1603InspectionMetadataValue(result m1603EgressRequestResult, key string) string {
	metadata, _ := result.StatusReadback["inspection_metadata"].(map[string]any)
	value, _ := metadata[key].(string)
	return value
}
