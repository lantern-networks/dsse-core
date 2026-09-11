package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/swghttprewrite"
)

const (
	sWGEdgeRuntimeProductionProcessAccessDecisionAdminAuthNegativeReadbackSmokeReportEnv = "SWG_EDGE_RUNTIME_PRODUCTION_PROCESS_ACCESS_DECISION_ADMIN_AUTH_NEGATIVE_READBACK_SMOKE_REPORT"
	sWGEdgeRuntimeProductionProcessAccessDecisionAdminAuthNegativeReadbackSmokeDSNEnv    = "SWG_EDGE_RUNTIME_PRODUCTION_PROCESS_ACCESS_DECISION_ADMIN_AUTH_NEGATIVE_READBACK_SMOKE_POSTGRES_DSN"
)

func TestSWGEdgeSWGProductionProcessAccessDecisionAdminAuthNegativeReadbackSmoke(t *testing.T) {
	postgresDSN := strings.TrimSpace(os.Getenv(sWGEdgeRuntimeProductionProcessAccessDecisionAdminAuthNegativeReadbackSmokeDSNEnv))
	if postgresDSN == "" {
		t.Skipf("%s is required for production-mode cmd/edge process access-decision admin auth negative readback smoke", sWGEdgeRuntimeProductionProcessAccessDecisionAdminAuthNegativeReadbackSmokeDSNEnv)
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

	binaryPath := filepath.Join(workDir, "edge-process-access-decision-admin-auth-negative-readback-smoke")
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

	runtimeTLSMissing := m1606RunProcessEgressAccessDecisionAdminAuthNegativeReadbackCase(t, common, m1602ReadinessProcessCase{
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

	tlsObservedMacCAMissing := m1606RunProcessEgressAccessDecisionAdminAuthNegativeReadbackCase(t, common, m1602ReadinessProcessCase{
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

	bothSignalsObserved := m1606RunProcessEgressAccessDecisionAdminAuthNegativeReadbackCase(t, common, m1602ReadinessProcessCase{
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

	report := m1606ProcessAccessDecisionAdminAuthNegativeReadbackReport(runtimeTLSMissing, tlsObservedMacCAMissing, bothSignalsObserved)
	forbidden := []string{
		"google-workspace.lab.example",
		"microsoft-365-tenant.lab.example",
		"swg_tenant_restriction_operator_config.json",
		"connector-auth-value",
		"attestation-auth-value",
		"admin-auth-value",
		"invalid-admin-auth-value",
		"invalid-decision-id",
		postgresDSN,
		proxy.URL,
		"127.0.0.1",
		"mail.google.com",
		"www.office.com",
		"pinned-client.google.com",
	}
	m1600AssertNoForbiddenMaterial(t, "report", report, forbidden)

	if path := strings.TrimSpace(os.Getenv(sWGEdgeRuntimeProductionProcessAccessDecisionAdminAuthNegativeReadbackSmokeReportEnv)); path != "" {
		writeSWGM1600JSON(t, path, report)
	}
}

type m1606ReadinessProcessCaseResult struct {
	Case             m1602ReadinessProcessCase
	Health           map[string]any
	HealthStatusCode int
	Requests         []m1606EgressRequestResult
}

type m1606EgressRequestResult struct {
	Egress                        m1602EgressRequestResult
	PositiveReadbackObserved      bool
	MissingAuthStatusCode         int
	InvalidAdminTokenStatusCode   int
	InvalidDecisionIDStatusCode   int
	NegativeResponseBodyCaptured  bool
	NegativeAccessDecisionIDSaved bool
}

func m1606RunProcessEgressAccessDecisionAdminAuthNegativeReadbackCase(t *testing.T, inputs m1602ProcessEgressInputs, processCase m1602ReadinessProcessCase) m1606ReadinessProcessCaseResult {
	t.Helper()
	listen := m1600FreeListenAddress(t)
	baseURL := "http://" + listen
	connectorAuthValue := "connector-auth-value-" + processCase.Name
	attestationAuthValue := "attestation-auth-value-" + processCase.Name
	adminAuthValue := "admin-auth-value-" + processCase.Name
	invalidAdminAuthValue := "invalid-admin-auth-value-" + processCase.Name
	invalidDecisionID := "invalid-decision-id-" + processCase.Name
	logDir := filepath.Join(inputs.WorkDir, "logs", "admin-auth-negative", processCase.Name)

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
		"-admin-token", adminAuthValue,
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
	results := make([]m1606EgressRequestResult, 0, len(processCase.Requests))
	for index, requestCase := range processCase.Requests {
		egress := m1602DoEgressRequest(t, client, baseURL, connectorAuthValue, inputs.Proxy, waitCh, &processErr, requestCase)
		audit := m1604GetAdminJSON(t, client, m1604AdminLogReadbackURL(baseURL, "audit", requestCase), adminAuthValue, waitCh, &processErr)
		inspection := m1604GetAdminJSON(t, client, m1604AdminLogReadbackURL(baseURL, "inspection_events", requestCase), adminAuthValue, waitCh, &processErr)
		m1604AssertLogReadbackAfterEgress(t, "audit", requestCase, audit)
		m1604AssertLogReadbackAfterEgress(t, "inspection_events", requestCase, inspection)
		decisionID := m1605AccessDecisionIDFromReadbacks(t, requestCase, audit, inspection)
		detail := m1605GetAccessDecisionDetail(t, client, baseURL, decisionID, adminAuthValue, waitCh, &processErr)
		m1605AssertAccessDecisionDetailRelatedLogs(t, requestCase, decisionID, detail)

		missingAuthStatus := m1606GetAccessDecisionReadbackStatus(t, client, baseURL, decisionID, "", waitCh, &processErr)
		invalidAdminTokenStatus := m1606GetAccessDecisionReadbackStatus(t, client, baseURL, decisionID, invalidAdminAuthValue, waitCh, &processErr)
		invalidDecisionIDStatus := m1606GetAccessDecisionReadbackStatus(t, client, baseURL, invalidDecisionID, adminAuthValue, waitCh, &processErr)
		if missingAuthStatus != http.StatusUnauthorized {
			t.Fatalf("missing admin auth status for %s = %d, want %d", requestCase.Name, missingAuthStatus, http.StatusUnauthorized)
		}
		if invalidAdminTokenStatus != http.StatusUnauthorized {
			t.Fatalf("invalid admin token status for %s = %d, want %d", requestCase.Name, invalidAdminTokenStatus, http.StatusUnauthorized)
		}
		if invalidDecisionIDStatus != http.StatusNotFound {
			t.Fatalf("invalid decision id status for %s = %d, want %d", requestCase.Name, invalidDecisionIDStatus, http.StatusNotFound)
		}
		results = append(results, m1606EgressRequestResult{
			Egress:                        egress,
			PositiveReadbackObserved:      true,
			MissingAuthStatusCode:         missingAuthStatus,
			InvalidAdminTokenStatusCode:   invalidAdminTokenStatus,
			InvalidDecisionIDStatusCode:   invalidDecisionIDStatus,
			NegativeResponseBodyCaptured:  false,
			NegativeAccessDecisionIDSaved: false,
		})
		if index+1 < len(processCase.Requests) {
			time.Sleep(1100 * time.Millisecond)
		}
	}
	return m1606ReadinessProcessCaseResult{
		Case:             processCase,
		Health:           health,
		HealthStatusCode: http.StatusOK,
		Requests:         results,
	}
}

func m1606GetAccessDecisionReadbackStatus(t *testing.T, client *http.Client, baseURL, decisionID, adminAuthValue string, waitCh chan error, processErr *bytes.Buffer) int {
	t.Helper()
	select {
	case err := <-waitCh:
		waitCh <- err
		t.Fatalf("cmd/edge exited before access-decision negative readback: %v; stderr redacted=%s", err, m1600RedactedLine(processErr.String()))
	default:
	}
	req, err := http.NewRequest(http.MethodGet, baseURL+"/admin/access-decisions/"+url.PathEscape(decisionID), nil)
	if err != nil {
		t.Fatalf("build access-decision negative readback request: %v", err)
	}
	if strings.TrimSpace(adminAuthValue) != "" {
		req.Header.Set("authorization", "Bearer "+adminAuthValue)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("access-decision negative readback request failed: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func m1606ProcessAccessDecisionAdminAuthNegativeReadbackReport(runtimeTLSMissing, tlsObservedMacCAMissing, bothSignalsObserved m1606ReadinessProcessCaseResult) map[string]any {
	requests := m1606AllRequestResults(runtimeTLSMissing, tlsObservedMacCAMissing, bothSignalsObserved)
	return map[string]any{
		"schema_version":    "swg_edge_runtime_production_process_access_decision_admin_auth_negative_readback_smoke.v1",
		"status":            "passed",
		"depth_locked_unit": "swg_edge_runtime_production_process_access_decision_admin_auth_negative_readback_smoke_product_unit",
		"source_m1605_process_access_decision_related_log_readback_after_egress_smoke_gate": "accepted",
		"source_m1604_process_audit_inspection_log_readback_after_egress_smoke_gate":        "accepted",
		"source_m1603_process_inspection_readback_after_egress_smoke_gate":                  "accepted",
		"source_m1602_process_egress_readiness_matrix_smoke_gate":                           "accepted",
		"egress_readiness_matrix_replayed":                                                  true,
		"access_decision_admin_auth_negative_readback_source":                               "cmd_edge_process_admin_access_decisions_detail_negative_readback_after_http_egress",
		"cmd_edge_process_access_decision_admin_auth_negative_readback_smoke_gate":          "passed",
		"cmd_edge_process_started":                                                          true,
		"cmd_edge_process_launch_count":                                                     3,
		"cmd_edge_process_output_included":                                                  false,
		"raw_command_output_included":                                                       false,
		"raw_process_output_included":                                                       false,
		"process_id_included":                                                               false,
		"process_listen_address_material_in_report":                                         false,
		"runtime_auth_material_in_report":                                                   false,
		"admin_auth_material_in_report":                                                     false,
		"invalid_admin_token_material_in_report":                                            false,
		"postgres_dsn_material_in_report":                                                   false,
		"upstream_proxy_address_material_in_report":                                         false,
		"target_url_material_in_report":                                                     false,
		"target_fqdn_material_in_report":                                                    false,
		"access_decision_detail_target_material_in_report":                                  false,
		"startup_flag_names_exercised":                                                      []string{"-admin-token", "-swg-tenant-restriction-operator-config", "-swg-runtime-tls-decryption-observed", "-swg-mac-ca-trust-observed"},
		"production_mode_lab_mode":                                                          false,
		"admin_access_decision_readback_requires_admin_auth":                                true,
		"admin_access_decision_readback_auth_method":                                        "legacy_admin_token",
		"healthz_readback_observed":                                                         runtimeTLSMissing.Health["status"] == "ok" && tlsObservedMacCAMissing.Health["status"] == "ok" && bothSignalsObserved.Health["status"] == "ok",
		"healthz_status_code":                                                               http.StatusOK,
		"edge_http_egress_handler_path":                                                     edgeplane.EdgeSWGHTTPEgressPath,
		"admin_access_decisions_detail_api_path":                                            "/admin/access-decisions/{decision_id}",
		"admin_logs_audit_api_path":                                                         "/admin/logs/audit",
		"admin_logs_inspection_events_api_path":                                             "/admin/logs/inspection_events",
		"http_egress_case_count":                                                            len(requests),
		"access_decision_positive_readback_count":                                           m1606CountPositiveReadbacks(requests),
		"access_decision_admin_auth_negative_readback_count":                                len(requests) * 3,
		"missing_admin_auth_negative_readback_count":                                        m1606CountStatus(requests, "missing_admin_auth", http.StatusUnauthorized),
		"invalid_admin_token_negative_readback_count":                                       m1606CountStatus(requests, "invalid_admin_token", http.StatusUnauthorized),
		"invalid_decision_id_negative_readback_count":                                       m1606CountStatus(requests, "invalid_decision_id", http.StatusNotFound),
		"missing_admin_auth_status_code":                                                    http.StatusUnauthorized,
		"invalid_admin_token_status_code":                                                   http.StatusUnauthorized,
		"invalid_decision_id_status_code":                                                   http.StatusNotFound,
		"missing_admin_auth_rejected":                                                       m1606AllStatus(requests, "missing_admin_auth", http.StatusUnauthorized),
		"invalid_admin_token_rejected":                                                      m1606AllStatus(requests, "invalid_admin_token", http.StatusUnauthorized),
		"invalid_decision_id_rejected":                                                      m1606AllStatus(requests, "invalid_decision_id", http.StatusNotFound),
		"missing_admin_auth_uses_internally_observed_access_decision_id":                    true,
		"invalid_admin_token_uses_internally_observed_access_decision_id":                   true,
		"invalid_decision_id_uses_valid_admin_auth":                                         true,
		"internally_observed_access_decision_id_used_for_negative_auth_readback":            true,
		"negative_readback_response_body_in_report":                                         false,
		"positive_access_decision_detail_body_in_report":                                    false,
		"access_decision_id_material_in_report":                                             false,
		"latest_access_decision_id_material_in_report":                                      false,
		"invalid_decision_id_material_in_report":                                            false,
		"related_audit_log_id_material_in_report":                                           false,
		"related_inspection_event_id_material_in_report":                                    false,
		"external_saas_egress_attempted":                                                    false,
		"local_capture_upstream_used":                                                       true,
		"header_values_forwarded_upstream_only":                                             true,
		"header_value_material_in_related_audit_log_readback":                               false,
		"header_value_material_in_related_inspection_log_readback":                          false,
		"header_value_material_in_report":                                                   false,
		"operator_config_value_material_in_related_audit_log_readback":                      false,
		"operator_config_value_material_in_related_inspection_log_readback":                 false,
		"operator_config_value_material_in_report":                                          false,
		"operator_config_path_material_in_report":                                           false,
		"operator_managed_tenant_header_config_loaded":                                      true,
		"tenant_header_rewrite_dependency_count":                                            float64(2),
		"operator_config_refs_visible":                                                      []string{"operator_config_ref:google_workspace_allowed_domains", "operator_config_ref:microsoft_365_allowed_tenants"},
		"header_names_visible":                                                              []string{"X-GoogApps-Allowed-Domains", "Restrict-Access-To-Tenants"},
		"per_destination_tls_bypass_required":                                               true,
		"tls_bypass_rule_count":                                                             float64(2),
		"runtime_tls_missing_google_workspace_status_code":                                  m1606RequestResultByName(runtimeTLSMissing, "google_workspace_tls_missing").Egress.StatusCode,
		"tls_bypass_with_missing_readiness_status_code":                                     m1606RequestResultByName(runtimeTLSMissing, "pinned_google_tls_bypass_with_missing_readiness").Egress.StatusCode,
		"tls_observed_mac_ca_missing_google_workspace_status_code":                          m1606RequestResultByName(tlsObservedMacCAMissing, "google_workspace_mac_ca_missing").Egress.StatusCode,
		"both_readiness_google_workspace_status_code":                                       m1606RequestResultByName(bothSignalsObserved, "google_workspace_ready").Egress.StatusCode,
		"both_readiness_microsoft_365_status_code":                                          m1606RequestResultByName(bothSignalsObserved, "microsoft_365_ready").Egress.StatusCode,
		"swg_runtime_traffic_observed":                                                      false,
		"real_tls_interception_runtime_executed":                                            false,
		"tls_runtime_decryption_observed":                                                   false,
		"header_injection_runtime_observed":                                                 false,
		"mac_ca_trust_mutation_started":                                                     false,
		"mac_ca_trust_mutated":                                                              false,
		"network_extension_runtime_used":                                                    false,
		"human_boundary_created":                                                            false,
		"gui_buildout_started":                                                              false,
		"presentation_only_ui_proxy_topology_started":                                       false,
		"p4_packaging_mdm_signing_install_started":                                          false,
		"shipping_product_claimed":                                                          false,
		"production_scale_claimed":                                                          false,
		"mvp_pilot_success_claimed":                                                         false,
		"windows_work_started":                                                              false,
		"productization_claims_made":                                                        false,
		"new_product_claims_made":                                                           false,
		"secret_leak_gate":                                                                  "ok",
		"no_secret_attestation":                                                             true,
	}
}

func m1606AllRequestResults(results ...m1606ReadinessProcessCaseResult) []m1606EgressRequestResult {
	var requests []m1606EgressRequestResult
	for _, result := range results {
		requests = append(requests, result.Requests...)
	}
	return requests
}

func m1606CountPositiveReadbacks(requests []m1606EgressRequestResult) int {
	count := 0
	for _, request := range requests {
		if request.PositiveReadbackObserved {
			count++
		}
	}
	return count
}

func m1606CountStatus(requests []m1606EgressRequestResult, kind string, want int) int {
	count := 0
	for _, request := range requests {
		if m1606StatusForKind(request, kind) == want {
			count++
		}
	}
	return count
}

func m1606AllStatus(requests []m1606EgressRequestResult, kind string, want int) bool {
	return m1606CountStatus(requests, kind, want) == len(requests)
}

func m1606StatusForKind(request m1606EgressRequestResult, kind string) int {
	switch kind {
	case "missing_admin_auth":
		return request.MissingAuthStatusCode
	case "invalid_admin_token":
		return request.InvalidAdminTokenStatusCode
	case "invalid_decision_id":
		return request.InvalidDecisionIDStatusCode
	default:
		return 0
	}
}

func m1606RequestResultByName(result m1606ReadinessProcessCaseResult, name string) m1606EgressRequestResult {
	for _, request := range result.Requests {
		if request.Egress.Case.Name == name {
			return request
		}
	}
	return m1606EgressRequestResult{}
}
