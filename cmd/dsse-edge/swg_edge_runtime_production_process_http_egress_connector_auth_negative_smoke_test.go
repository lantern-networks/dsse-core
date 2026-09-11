package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
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
	sWGEdgeRuntimeProductionProcessHTTPEgressConnectorAuthNegativeSmokeReportEnv = "SWG_EDGE_RUNTIME_PRODUCTION_PROCESS_HTTP_EGRESS_CONNECTOR_AUTH_NEGATIVE_SMOKE_REPORT"
	sWGEdgeRuntimeProductionProcessHTTPEgressConnectorAuthNegativeSmokeDSNEnv    = "SWG_EDGE_RUNTIME_PRODUCTION_PROCESS_HTTP_EGRESS_CONNECTOR_AUTH_NEGATIVE_SMOKE_POSTGRES_DSN"
)

func TestSWGEdgeSWGProductionProcessHTTPEgressConnectorAuthNegativeSmoke(t *testing.T) {
	postgresDSN := strings.TrimSpace(os.Getenv(sWGEdgeRuntimeProductionProcessHTTPEgressConnectorAuthNegativeSmokeDSNEnv))
	if postgresDSN == "" {
		t.Skipf("%s is required for production-mode cmd/edge process HTTP egress connector auth negative smoke", sWGEdgeRuntimeProductionProcessHTTPEgressConnectorAuthNegativeSmokeDSNEnv)
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

	binaryPath := filepath.Join(workDir, "edge-process-http-egress-connector-auth-negative-smoke")
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

	runtimeTLSMissing := m1607RunProcessHTTPEgressConnectorAuthNegativeCase(t, common, m1602ReadinessProcessCase{
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

	tlsObservedMacCAMissing := m1607RunProcessHTTPEgressConnectorAuthNegativeCase(t, common, m1602ReadinessProcessCase{
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

	bothSignalsObserved := m1607RunProcessHTTPEgressConnectorAuthNegativeCase(t, common, m1602ReadinessProcessCase{
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

	report := m1607ProcessHTTPEgressConnectorAuthNegativeReport(runtimeTLSMissing, tlsObservedMacCAMissing, bothSignalsObserved)
	forbidden := []string{
		"google-workspace.lab.example",
		"microsoft-365-tenant.lab.example",
		"swg_tenant_restriction_operator_config.json",
		"connector-auth-value",
		"invalid-connector-auth-value",
		"attestation-auth-value",
		postgresDSN,
		proxy.URL,
		"127.0.0.1",
		"mail.google.com",
		"www.office.com",
		"pinned-client.google.com",
	}
	m1600AssertNoForbiddenMaterial(t, "report", report, forbidden)

	if path := strings.TrimSpace(os.Getenv(sWGEdgeRuntimeProductionProcessHTTPEgressConnectorAuthNegativeSmokeReportEnv)); path != "" {
		writeSWGM1600JSON(t, path, report)
	}
}

type m1607ReadinessProcessCaseResult struct {
	Case             m1602ReadinessProcessCase
	Health           map[string]any
	HealthStatusCode int
	Requests         []m1607EgressRequestResult
}

type m1607EgressRequestResult struct {
	Egress                           m1602EgressRequestResult
	MissingConnectorSecretStatusCode int
	InvalidConnectorSecretStatusCode int
	NegativeResponseBodyCaptured     bool
	NegativeUpstreamRequestObserved  bool
}

func m1607RunProcessHTTPEgressConnectorAuthNegativeCase(t *testing.T, inputs m1602ProcessEgressInputs, processCase m1602ReadinessProcessCase) m1607ReadinessProcessCaseResult {
	t.Helper()
	listen := m1600FreeListenAddress(t)
	baseURL := "http://" + listen
	connectorAuthValue := "connector-auth-value-" + processCase.Name
	invalidConnectorAuthValue := "invalid-connector-auth-value-" + processCase.Name
	attestationAuthValue := "attestation-auth-value-" + processCase.Name
	logDir := filepath.Join(inputs.WorkDir, "logs", "connector-auth-negative", processCase.Name)

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
	results := make([]m1607EgressRequestResult, 0, len(processCase.Requests))
	for _, requestCase := range processCase.Requests {
		egress := m1602DoEgressRequest(t, client, baseURL, connectorAuthValue, inputs.Proxy, waitCh, &processErr, requestCase)
		missingStatus := m1607DoConnectorAuthNegativeStatus(t, client, baseURL, "", false, inputs.Proxy, waitCh, &processErr, requestCase, "missing_connector_secret")
		invalidStatus := m1607DoConnectorAuthNegativeStatus(t, client, baseURL, invalidConnectorAuthValue, true, inputs.Proxy, waitCh, &processErr, requestCase, "invalid_connector_secret")
		if missingStatus != http.StatusUnauthorized {
			t.Fatalf("missing connector secret status for %s = %d, want %d", requestCase.Name, missingStatus, http.StatusUnauthorized)
		}
		if invalidStatus != http.StatusUnauthorized {
			t.Fatalf("invalid connector secret status for %s = %d, want %d", requestCase.Name, invalidStatus, http.StatusUnauthorized)
		}
		results = append(results, m1607EgressRequestResult{
			Egress:                           egress,
			MissingConnectorSecretStatusCode: missingStatus,
			InvalidConnectorSecretStatusCode: invalidStatus,
			NegativeResponseBodyCaptured:     false,
			NegativeUpstreamRequestObserved:  false,
		})
	}
	return m1607ReadinessProcessCaseResult{
		Case:             processCase,
		Health:           health,
		HealthStatusCode: http.StatusOK,
		Requests:         results,
	}
}

func m1607DoConnectorAuthNegativeStatus(t *testing.T, client *http.Client, baseURL, connectorAuthValue string, setConnectorAuth bool, proxy *m1602LocalCaptureProxy, waitCh chan error, processErr *bytes.Buffer, requestCase m1602EgressRequestCase, kind string) int {
	t.Helper()
	select {
	case err := <-waitCh:
		waitCh <- err
		t.Fatalf("cmd/edge exited before %s connector auth negative request %s: %v; stderr redacted=%s", kind, requestCase.Name, err, m1600RedactedLine(processErr.String()))
	default:
	}
	req, err := http.NewRequest(http.MethodGet, baseURL+edgeplane.EdgeSWGHTTPEgressPath, nil)
	if err != nil {
		t.Fatalf("build %s connector auth negative request %s: %v", kind, requestCase.Name, err)
	}
	if setConnectorAuth {
		req.Header.Set(connectorSecretHeader, connectorAuthValue)
	}
	req.Header.Set(edgeplane.EdgeSWGHTTPEgressTargetURLHeader, requestCase.TargetURL)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s connector auth negative request %s failed: %v", kind, requestCase.Name, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	m1602AssertNoProxyCapture(t, proxy, requestCase.Name+" "+kind)
	return resp.StatusCode
}

func m1607ProcessHTTPEgressConnectorAuthNegativeReport(runtimeTLSMissing, tlsObservedMacCAMissing, bothSignalsObserved m1607ReadinessProcessCaseResult) map[string]any {
	requests := m1607AllRequestResults(runtimeTLSMissing, tlsObservedMacCAMissing, bothSignalsObserved)
	return map[string]any{
		"schema_version":    "swg_edge_runtime_production_process_http_egress_connector_auth_negative_smoke.v1",
		"status":            "passed",
		"depth_locked_unit": "swg_edge_runtime_production_process_http_egress_connector_auth_negative_smoke_product_unit",
		"source_m1606_process_access_decision_admin_auth_negative_readback_smoke_gate": "accepted",
		"source_m1602_process_egress_readiness_matrix_smoke_gate":                      "accepted",
		"egress_readiness_positive_path_replayed":                                      true,
		"http_egress_connector_auth_negative_source":                                   "cmd_edge_process_http_egress_connector_auth_negative_before_policy_or_upstream",
		"cmd_edge_process_http_egress_connector_auth_negative_smoke_gate":              "passed",
		"cmd_edge_process_started":                                                     true,
		"cmd_edge_process_launch_count":                                                3,
		"cmd_edge_process_output_included":                                             false,
		"raw_command_output_included":                                                  false,
		"raw_process_output_included":                                                  false,
		"process_id_included":                                                          false,
		"process_listen_address_material_in_report":                                    false,
		"runtime_auth_material_in_report":                                              false,
		"connector_auth_material_in_report":                                            false,
		"invalid_connector_secret_material_in_report":                                  false,
		"postgres_dsn_material_in_report":                                              false,
		"upstream_proxy_address_material_in_report":                                    false,
		"target_url_material_in_report":                                                false,
		"target_fqdn_material_in_report":                                               false,
		"startup_flag_names_exercised":                                                 []string{"-swg-tenant-restriction-operator-config", "-swg-runtime-tls-decryption-observed", "-swg-mac-ca-trust-observed"},
		"production_mode_lab_mode":                                                     false,
		"healthz_readback_observed":                                                    runtimeTLSMissing.Health["status"] == "ok" && tlsObservedMacCAMissing.Health["status"] == "ok" && bothSignalsObserved.Health["status"] == "ok",
		"healthz_status_code":                                                          http.StatusOK,
		"edge_http_egress_handler_path":                                                edgeplane.EdgeSWGHTTPEgressPath,
		"http_egress_positive_case_count":                                              len(requests),
		"http_egress_connector_auth_negative_count":                                    len(requests) * 2,
		"missing_connector_secret_negative_count":                                      m1607CountStatus(requests, "missing_connector_secret", http.StatusUnauthorized),
		"invalid_connector_secret_negative_count":                                      m1607CountStatus(requests, "invalid_connector_secret", http.StatusUnauthorized),
		"missing_connector_secret_status_code":                                         http.StatusUnauthorized,
		"invalid_connector_secret_status_code":                                         http.StatusUnauthorized,
		"missing_connector_secret_rejected":                                            m1607AllStatus(requests, "missing_connector_secret", http.StatusUnauthorized),
		"invalid_connector_secret_rejected":                                            m1607AllStatus(requests, "invalid_connector_secret", http.StatusUnauthorized),
		"connector_auth_checked_before_upstream_proxy":                                 true,
		"negative_connector_auth_upstream_request_observed":                            m1607AnyNegativeUpstreamObserved(requests),
		"negative_connector_auth_response_body_in_report":                              false,
		"positive_egress_response_body_in_report":                                      false,
		"external_saas_egress_attempted":                                               false,
		"local_capture_upstream_used":                                                  true,
		"header_values_forwarded_upstream_only":                                        true,
		"header_value_material_in_report":                                              false,
		"operator_config_value_material_in_report":                                     false,
		"operator_config_path_material_in_report":                                      false,
		"operator_managed_tenant_header_config_loaded":                                 true,
		"tenant_header_rewrite_dependency_count":                                       float64(2),
		"operator_config_refs_visible":                                                 []string{"operator_config_ref:google_workspace_allowed_domains", "operator_config_ref:microsoft_365_allowed_tenants"},
		"header_names_visible":                                                         []string{"X-GoogApps-Allowed-Domains", "Restrict-Access-To-Tenants"},
		"per_destination_tls_bypass_required":                                          true,
		"tls_bypass_rule_count":                                                        float64(2),
		"runtime_tls_missing_google_workspace_status_code":                             m1607RequestResultByName(runtimeTLSMissing, "google_workspace_tls_missing").Egress.StatusCode,
		"tls_bypass_with_missing_readiness_status_code":                                m1607RequestResultByName(runtimeTLSMissing, "pinned_google_tls_bypass_with_missing_readiness").Egress.StatusCode,
		"tls_observed_mac_ca_missing_google_workspace_status_code":                     m1607RequestResultByName(tlsObservedMacCAMissing, "google_workspace_mac_ca_missing").Egress.StatusCode,
		"both_readiness_google_workspace_status_code":                                  m1607RequestResultByName(bothSignalsObserved, "google_workspace_ready").Egress.StatusCode,
		"both_readiness_microsoft_365_status_code":                                     m1607RequestResultByName(bothSignalsObserved, "microsoft_365_ready").Egress.StatusCode,
		"swg_runtime_traffic_observed":                                                 false,
		"real_tls_interception_runtime_executed":                                       false,
		"tls_runtime_decryption_observed":                                              false,
		"header_injection_runtime_observed":                                            false,
		"mac_ca_trust_mutation_started":                                                false,
		"mac_ca_trust_mutated":                                                         false,
		"network_extension_runtime_used":                                               false,
		"human_boundary_created":                                                       false,
		"gui_buildout_started":                                                         false,
		"presentation_only_ui_proxy_topology_started":                                  false,
		"p4_packaging_mdm_signing_install_started":                                     false,
		"shipping_product_claimed":                                                     false,
		"production_scale_claimed":                                                     false,
		"mvp_pilot_success_claimed":                                                    false,
		"windows_work_started":                                                         false,
		"productization_claims_made":                                                   false,
		"new_product_claims_made":                                                      false,
		"secret_leak_gate":                                                             "ok",
		"no_secret_attestation":                                                        true,
	}
}

func m1607AllRequestResults(results ...m1607ReadinessProcessCaseResult) []m1607EgressRequestResult {
	var requests []m1607EgressRequestResult
	for _, result := range results {
		requests = append(requests, result.Requests...)
	}
	return requests
}

func m1607CountStatus(requests []m1607EgressRequestResult, kind string, want int) int {
	count := 0
	for _, request := range requests {
		if m1607StatusForKind(request, kind) == want {
			count++
		}
	}
	return count
}

func m1607AllStatus(requests []m1607EgressRequestResult, kind string, want int) bool {
	return m1607CountStatus(requests, kind, want) == len(requests)
}

func m1607StatusForKind(request m1607EgressRequestResult, kind string) int {
	switch kind {
	case "missing_connector_secret":
		return request.MissingConnectorSecretStatusCode
	case "invalid_connector_secret":
		return request.InvalidConnectorSecretStatusCode
	default:
		return 0
	}
}

func m1607AnyNegativeUpstreamObserved(requests []m1607EgressRequestResult) bool {
	for _, request := range requests {
		if request.NegativeUpstreamRequestObserved {
			return true
		}
	}
	return false
}

func m1607RequestResultByName(result m1607ReadinessProcessCaseResult, name string) m1607EgressRequestResult {
	for _, request := range result.Requests {
		if request.Egress.Case.Name == name {
			return request
		}
	}
	return m1607EgressRequestResult{}
}
