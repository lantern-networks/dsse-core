package main

import (
	"bytes"
	"context"
	"encoding/json"
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
	swg "github.com/lantern-networks/dsse-core/swg"

	"github.com/lantern-networks/dsse-core/swghttprewrite"
)

const (
	sWGEdgeRuntimeProductionProcessAuditInspectionLogReadbackAfterEgressSmokeReportEnv = "SWG_EDGE_RUNTIME_PRODUCTION_PROCESS_AUDIT_INSPECTION_LOG_READBACK_AFTER_EGRESS_SMOKE_REPORT"
	sWGEdgeRuntimeProductionProcessAuditInspectionLogReadbackAfterEgressSmokeDSNEnv    = "SWG_EDGE_RUNTIME_PRODUCTION_PROCESS_AUDIT_INSPECTION_LOG_READBACK_AFTER_EGRESS_SMOKE_POSTGRES_DSN"
)

func TestSWGEdgeSWGProductionProcessAuditInspectionLogReadbackAfterEgressSmoke(t *testing.T) {
	postgresDSN := strings.TrimSpace(os.Getenv(sWGEdgeRuntimeProductionProcessAuditInspectionLogReadbackAfterEgressSmokeDSNEnv))
	if postgresDSN == "" {
		t.Skipf("%s is required for production-mode cmd/edge process audit/inspection log readback after egress smoke", sWGEdgeRuntimeProductionProcessAuditInspectionLogReadbackAfterEgressSmokeDSNEnv)
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

	binaryPath := filepath.Join(workDir, "edge-process-audit-inspection-log-readback-after-egress-smoke")
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

	runtimeTLSMissing := m1604RunProcessEgressAuditInspectionLogReadbackCase(t, common, m1602ReadinessProcessCase{
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

	tlsObservedMacCAMissing := m1604RunProcessEgressAuditInspectionLogReadbackCase(t, common, m1602ReadinessProcessCase{
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

	bothSignalsObserved := m1604RunProcessEgressAuditInspectionLogReadbackCase(t, common, m1602ReadinessProcessCase{
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

	report := m1604ProcessAuditInspectionLogReadbackAfterEgressReport(runtimeTLSMissing, tlsObservedMacCAMissing, bothSignalsObserved)
	forbidden := []string{
		"google-workspace.lab.example",
		"microsoft-365-tenant.lab.example",
		"swg_tenant_restriction_operator_config.json",
		"connector-auth-value",
		"attestation-auth-value",
		"admin-auth-value",
		postgresDSN,
		proxy.URL,
		"127.0.0.1",
		"mail.google.com",
		"www.office.com",
		"pinned-client.google.com",
	}
	for _, processCase := range []m1604ReadinessProcessCaseResult{runtimeTLSMissing, tlsObservedMacCAMissing, bothSignalsObserved} {
		for _, request := range processCase.Requests {
			m1600AssertNoForbiddenMaterial(t, request.Egress.Case.Name+" diagnostic", request.Egress.Diagnostic, forbidden[:7])
			m1600AssertNoForbiddenMaterial(t, request.Egress.Case.Name+" audit readback", request.AuditReadback, forbidden)
			m1600AssertNoForbiddenMaterial(t, request.Egress.Case.Name+" inspection readback", request.InspectionReadback, forbidden)
		}
	}
	m1600AssertNoForbiddenMaterial(t, "report", report, forbidden)

	if path := strings.TrimSpace(os.Getenv(sWGEdgeRuntimeProductionProcessAuditInspectionLogReadbackAfterEgressSmokeReportEnv)); path != "" {
		writeSWGM1600JSON(t, path, report)
	}
}

type m1604ReadinessProcessCaseResult struct {
	Case             m1602ReadinessProcessCase
	Health           map[string]any
	HealthStatusCode int
	Requests         []m1604EgressRequestResult
}

type m1604EgressRequestResult struct {
	Egress             m1602EgressRequestResult
	AuditReadback      map[string]any
	InspectionReadback map[string]any
}

func m1604RunProcessEgressAuditInspectionLogReadbackCase(t *testing.T, inputs m1602ProcessEgressInputs, processCase m1602ReadinessProcessCase) m1604ReadinessProcessCaseResult {
	t.Helper()
	listen := m1600FreeListenAddress(t)
	baseURL := "http://" + listen
	connectorAuthValue := "connector-auth-value-" + processCase.Name
	attestationAuthValue := "attestation-auth-value-" + processCase.Name
	adminAuthValue := "admin-auth-value-" + processCase.Name
	logDir := filepath.Join(inputs.WorkDir, "logs", "audit-inspection-readback", processCase.Name)

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
	results := make([]m1604EgressRequestResult, 0, len(processCase.Requests))
	for index, requestCase := range processCase.Requests {
		egress := m1602DoEgressRequest(t, client, baseURL, connectorAuthValue, inputs.Proxy, waitCh, &processErr, requestCase)
		audit := m1604GetAdminJSON(t, client, m1604AdminLogReadbackURL(baseURL, "audit", requestCase), adminAuthValue, waitCh, &processErr)
		inspection := m1604GetAdminJSON(t, client, m1604AdminLogReadbackURL(baseURL, "inspection_events", requestCase), adminAuthValue, waitCh, &processErr)
		m1604AssertLogReadbackAfterEgress(t, "audit", requestCase, audit)
		m1604AssertLogReadbackAfterEgress(t, "inspection_events", requestCase, inspection)
		results = append(results, m1604EgressRequestResult{Egress: egress, AuditReadback: audit, InspectionReadback: inspection})
		if index+1 < len(processCase.Requests) {
			time.Sleep(1100 * time.Millisecond)
		}
	}
	return m1604ReadinessProcessCaseResult{
		Case:             processCase,
		Health:           health,
		HealthStatusCode: http.StatusOK,
		Requests:         results,
	}
}

func m1604AdminLogReadbackURL(baseURL, stream string, requestCase m1602EgressRequestCase) string {
	query := url.Values{}
	query.Set("limit", "5")
	query.Set("q", m1604LogReadbackQuery(requestCase))
	if stream == "audit" {
		query.Set("event_type", edgeplane.EdgeSWGHTTPEgressRewriteEvent)
	}
	return baseURL + "/admin/logs/" + stream + "?" + query.Encode()
}

func m1604LogReadbackQuery(requestCase m1602EgressRequestCase) string {
	if requestCase.WantCurrentTLSBypassApplied {
		return `"tls_bypass_rule_id":"` + requestCase.WantTLSBypassRuleID + `"`
	}
	return `"operator_config_ref":"` + m1603InspectionOperatorConfigRef(requestCase) + `"`
}

func m1604GetAdminJSON(t *testing.T, client *http.Client, endpoint, adminAuthValue string, waitCh chan error, processErr *bytes.Buffer) map[string]any {
	t.Helper()
	select {
	case err := <-waitCh:
		waitCh <- err
		t.Fatalf("cmd/edge exited before admin log readback: %v; stderr redacted=%s", err, m1600RedactedLine(processErr.String()))
	default:
	}
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		t.Fatalf("build admin log readback request: %v", err)
	}
	req.Header.Set("authorization", "Bearer "+adminAuthValue)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("admin log readback request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("admin log readback status = %d, want %d; body=%s", resp.StatusCode, http.StatusOK, m1600RedactedLine(string(body)))
	}
	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode admin log readback: %v", err)
	}
	return result
}

func m1604AssertLogReadbackAfterEgress(t *testing.T, stream string, requestCase m1602EgressRequestCase, readback map[string]any) {
	t.Helper()
	if readback["stream"] != stream || readback["total_matches"] != float64(1) || readback["returned"] != float64(1) {
		t.Fatalf("%s readback for %s = %#v, want exactly one row", stream, requestCase.Name, readback)
	}
	rows, ok := readback["rows"].([]any)
	if !ok || len(rows) != 1 {
		t.Fatalf("%s readback rows for %s = %#v", stream, requestCase.Name, readback["rows"])
	}
	row, ok := rows[0].(map[string]any)
	if !ok {
		t.Fatalf("%s readback row for %s = %#v", stream, requestCase.Name, rows[0])
	}
	if row["tenant_id"] != "tenant_swg_lab" {
		t.Fatalf("%s readback tenant for %s = %#v", stream, requestCase.Name, row["tenant_id"])
	}
	metadata, ok := row["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("%s readback metadata for %s = %#v", stream, requestCase.Name, row["metadata"])
	}
	if stream == "audit" {
		if row["event_type"] != edgeplane.EdgeSWGHTTPEgressRewriteEvent || row["target_type"] != "swg_http_egress_rewrite" || row["action"] != "rewrite" || row["result"] != "success" {
			t.Fatalf("audit row for %s = %#v, want SWG rewrite audit", requestCase.Name, row)
		}
		if _, ok := row["access_decision_id"].(string); !ok {
			t.Fatalf("audit row for %s lacks access_decision_id: %#v", requestCase.Name, row)
		}
		if _, ok := row["id"].(string); !ok {
			t.Fatalf("audit row for %s lacks id: %#v", requestCase.Name, row)
		}
		if metadata["swg_rewrite_audit_version"] != "v1" || metadata["swg_rewrite_metadata_recorded_scope"] != "non_secret" {
			t.Fatalf("audit metadata version/scope for %s = %#v", requestCase.Name, metadata)
		}
	} else {
		if row["content_type"] != "application/vnd.dsse.swg-rewrite-metadata+json" || row["finding_type"] != "saas_tenant_restriction_rewrite" || row["severity"] != "info" || row["payload_stored"] != false || row["masked"] != true {
			t.Fatalf("inspection row for %s = %#v, want SWG inspection event", requestCase.Name, row)
		}
		if _, ok := row["access_decision_id"].(string); !ok {
			t.Fatalf("inspection row for %s lacks access_decision_id: %#v", requestCase.Name, row)
		}
		if _, ok := row["id"].(string); !ok {
			t.Fatalf("inspection row for %s lacks id: %#v", requestCase.Name, row)
		}
		if metadata["swg_inspection_event_version"] != "swg_inspection.v1" || metadata["swg_inspection_metadata_recorded_scope"] != "non_secret" || metadata["source_audit_event_type"] != edgeplane.EdgeSWGHTTPEgressRewriteEvent {
			t.Fatalf("inspection metadata version/scope for %s = %#v", requestCase.Name, metadata)
		}
	}

	wantGoogle, wantMicrosoft, wantTLSSuppress := m1603InspectionOutcomes(requestCase)
	wantReadinessStatus := m1604ExpectedReadinessStatus(requestCase)
	for key, want := range map[string]any{
		"edge_http_egress_handler_path":                     edgeplane.EdgeSWGHTTPEgressPath,
		"edge_runtime_rewrite_path_observed":                true,
		"local_http_rewrite_harness_observation":            false,
		"policy_id":                                         requestCase.WantPolicyID,
		"saas_application_id":                               requestCase.WantSaaSApplicationID,
		"header_name":                                       m1604ExpectedHeaderName(requestCase),
		"operator_config_ref":                               m1603InspectionOperatorConfigRef(requestCase),
		"google_workspace_rewrite_outcome":                  wantGoogle,
		"microsoft_365_rewrite_outcome":                     wantMicrosoft,
		"tls_bypass_suppression_outcome":                    wantTLSSuppress,
		"header_rewrite_applied":                            requestCase.WantHeaderName != "" && !requestCase.WantCurrentTLSBypassApplied,
		"header_injection_suppressed_by_bypass":             requestCase.WantCurrentTLSBypassApplied,
		"tls_bypass_applied":                                requestCase.WantCurrentTLSBypassApplied,
		"tls_bypass_rule_id":                                requestCase.WantTLSBypassRuleID,
		"runtime_tls_decryption_observed":                   requestCase.WantDefaultTLSObserved,
		"runtime_header_injection_observed":                 false,
		"network_extension_runtime_used":                    false,
		"tls_readiness_precondition_checked":                true,
		"tls_readiness_precondition_status":                 wantReadinessStatus,
		"readiness_dependency":                              requestCase.WantReadinessDependency,
		"egress_forwarded":                                  requestCase.WantForwarded,
		"lab_mode":                                          false,
		"tls_readiness_status_path":                         swg.EdgeSWGTLSReadinessStatusPath,
		"tls_readiness_status_version":                      "swg_tls_readiness_status.v1",
		"default_tls_decryption_required":                   true,
		"default_tls_decryption_observed":                   requestCase.WantDefaultTLSObserved,
		"default_tls_decryption_status":                     swg.TlsReadinessRequiredObservedStatus(true, requestCase.WantDefaultTLSObserved),
		"mac_ca_trust_required":                             true,
		"mac_ca_trust_observed":                             requestCase.WantMacCATrustObserved,
		"mac_ca_trust_status":                               swg.MacCATrustRequiredStatus(true, requestCase.WantMacCATrustObserved),
		"tenant_header_rewrite_dependency_count":            float64(2),
		"per_destination_tls_bypass_required":               true,
		"tls_bypass_rule_count":                             float64(2),
		"current_request_tls_bypass_applied":                requestCase.WantCurrentTLSBypassApplied,
		"current_request_tls_bypass_rule_id":                requestCase.WantTLSBypassRuleID,
		"tls_readiness_dependency_suppressed_by_tls_bypass": requestCase.WantCurrentTLSBypassApplied,
		"header_value_material_logged":                      false,
		"operator_config_value_material_logged":             false,
		"real_tls_interception_runtime_executed":            false,
		"mac_ca_trust_mutated":                              false,
		"p4_packaging_mdm_signing_install_started":          false,
		"shipping_product_claimed":                          false,
		"production_scale_claimed":                          false,
		"mvp_pilot_success_claimed":                         false,
		"windows_work_started":                              false,
	} {
		if got := metadata[key]; got != want {
			t.Fatalf("%s metadata[%s] for %s = %#v, want %#v; metadata=%#v", stream, key, requestCase.Name, got, want, metadata)
		}
	}
	if stream == "audit" {
		for _, key := range []string{"header_value_material_in_audit", "header_value_material_in_api_readback", "header_value_material_in_report", "operator_config_value_material_in_audit", "operator_config_value_material_in_api_readback", "operator_config_value_material_in_report"} {
			if metadata[key] != false {
				t.Fatalf("audit metadata[%s] for %s = %#v, want false", key, requestCase.Name, metadata[key])
			}
		}
	} else {
		for _, key := range []string{"header_value_material_in_inspection_event", "header_value_material_in_api_readback", "header_value_material_in_report", "operator_config_value_material_in_inspection", "operator_config_value_material_in_api_readback", "operator_config_value_material_in_report"} {
			if metadata[key] != false {
				t.Fatalf("inspection metadata[%s] for %s = %#v, want false", key, requestCase.Name, metadata[key])
			}
		}
	}
}

func m1604ExpectedReadinessStatus(requestCase m1602EgressRequestCase) string {
	if requestCase.WantCurrentTLSBypassApplied {
		return "tls_bypass_exempted"
	}
	if requestCase.WantReadinessDependency != "none" {
		return "readiness_dependency"
	}
	if requestCase.WantMacCATrustObserved {
		return "mac_ca_trust_observed"
	}
	if requestCase.WantDefaultTLSObserved {
		return "tls_readiness_observed"
	}
	return "satisfied"
}

func m1604ExpectedHeaderName(requestCase m1602EgressRequestCase) string {
	if requestCase.WantCurrentTLSBypassApplied {
		return swghttprewrite.GoogleWorkspaceTenantRestrictionHeader
	}
	return requestCase.WantHeaderName
}

func m1604ProcessAuditInspectionLogReadbackAfterEgressReport(runtimeTLSMissing, tlsObservedMacCAMissing, bothSignalsObserved m1604ReadinessProcessCaseResult) map[string]any {
	tlsMissingGoogle := m1604RequestResultByName(runtimeTLSMissing, "google_workspace_tls_missing")
	tlsMissingBypass := m1604RequestResultByName(runtimeTLSMissing, "pinned_google_tls_bypass_with_missing_readiness")
	macCAMissingGoogle := m1604RequestResultByName(tlsObservedMacCAMissing, "google_workspace_mac_ca_missing")
	readyGoogle := m1604RequestResultByName(bothSignalsObserved, "google_workspace_ready")
	readyMicrosoft := m1604RequestResultByName(bothSignalsObserved, "microsoft_365_ready")

	return map[string]any{
		"schema_version":    "swg_edge_runtime_production_process_audit_inspection_log_readback_after_egress_smoke.v1",
		"status":            "passed",
		"depth_locked_unit": "swg_edge_runtime_production_process_audit_inspection_log_readback_after_egress_smoke_product_unit",
		"source_m1603_process_inspection_readback_after_egress_smoke_gate":              "accepted",
		"source_m1602_process_egress_readiness_matrix_smoke_gate":                       "accepted",
		"egress_readiness_matrix_replayed":                                              true,
		"log_readback_source":                                                           "cmd_edge_process_admin_logs_audit_inspection_events_after_http_egress",
		"cmd_edge_process_audit_inspection_log_readback_after_egress_smoke_gate":        "passed",
		"cmd_edge_process_started":                                                      true,
		"cmd_edge_process_launch_count":                                                 3,
		"cmd_edge_process_output_included":                                              false,
		"raw_command_output_included":                                                   false,
		"raw_process_output_included":                                                   false,
		"process_id_included":                                                           false,
		"process_listen_address_material_in_report":                                     false,
		"runtime_auth_material_in_report":                                               false,
		"admin_auth_material_in_report":                                                 false,
		"postgres_dsn_material_in_report":                                               false,
		"upstream_proxy_address_material_in_report":                                     false,
		"target_url_material_in_report":                                                 false,
		"target_fqdn_material_in_report":                                                false,
		"startup_flag_names_exercised":                                                  []string{"-admin-token", "-swg-tenant-restriction-operator-config", "-swg-runtime-tls-decryption-observed", "-swg-mac-ca-trust-observed"},
		"production_mode_lab_mode":                                                      false,
		"admin_log_readback_requires_admin_auth":                                        true,
		"admin_log_readback_auth_method":                                                "legacy_admin_token",
		"healthz_readback_observed":                                                     runtimeTLSMissing.Health["status"] == "ok" && tlsObservedMacCAMissing.Health["status"] == "ok" && bothSignalsObserved.Health["status"] == "ok",
		"healthz_status_code":                                                           http.StatusOK,
		"edge_http_egress_handler_path":                                                 edgeplane.EdgeSWGHTTPEgressPath,
		"admin_logs_audit_api_path":                                                     "/admin/logs/audit",
		"admin_logs_inspection_events_api_path":                                         "/admin/logs/inspection_events",
		"http_egress_case_count":                                                        5,
		"audit_log_readback_count":                                                      5,
		"inspection_log_readback_count":                                                 5,
		"audit_log_readback_after_egress_observed":                                      true,
		"inspection_log_readback_after_egress_observed":                                 true,
		"google_workspace_audit_log_readback_observed":                                  m1604LogReadbackObserved(tlsMissingGoogle.AuditReadback) && m1604LogReadbackObserved(macCAMissingGoogle.AuditReadback) && m1604LogReadbackObserved(readyGoogle.AuditReadback),
		"google_workspace_inspection_log_readback_observed":                             m1604LogReadbackObserved(tlsMissingGoogle.InspectionReadback) && m1604LogReadbackObserved(macCAMissingGoogle.InspectionReadback) && m1604LogReadbackObserved(readyGoogle.InspectionReadback),
		"microsoft_365_audit_log_readback_observed":                                     m1604LogReadbackObserved(readyMicrosoft.AuditReadback),
		"microsoft_365_inspection_log_readback_observed":                                m1604LogReadbackObserved(readyMicrosoft.InspectionReadback),
		"tls_bypass_audit_log_readback_observed":                                        m1604LogReadbackObserved(tlsMissingBypass.AuditReadback),
		"tls_bypass_inspection_log_readback_observed":                                   m1604LogReadbackObserved(tlsMissingBypass.InspectionReadback),
		"runtime_tls_missing_google_workspace_status_code":                              tlsMissingGoogle.Egress.StatusCode,
		"runtime_tls_missing_google_workspace_audit_total_matches":                      m1604TotalMatches(tlsMissingGoogle.AuditReadback),
		"runtime_tls_missing_google_workspace_inspection_total_matches":                 m1604TotalMatches(tlsMissingGoogle.InspectionReadback),
		"runtime_tls_missing_google_workspace_audit_rewrite_outcome":                    m1604LogMetadataValue(tlsMissingGoogle.AuditReadback, "google_workspace_rewrite_outcome"),
		"runtime_tls_missing_google_workspace_inspection_rewrite_outcome":               m1604LogMetadataValue(tlsMissingGoogle.InspectionReadback, "google_workspace_rewrite_outcome"),
		"runtime_tls_missing_google_workspace_audit_readiness_dependency":               m1604LogMetadataValue(tlsMissingGoogle.AuditReadback, "readiness_dependency"),
		"tls_bypass_with_missing_readiness_status_code":                                 tlsMissingBypass.Egress.StatusCode,
		"tls_bypass_with_missing_readiness_audit_total_matches":                         m1604TotalMatches(tlsMissingBypass.AuditReadback),
		"tls_bypass_with_missing_readiness_inspection_total_matches":                    m1604TotalMatches(tlsMissingBypass.InspectionReadback),
		"tls_bypass_with_missing_readiness_audit_google_workspace_rewrite_outcome":      m1604LogMetadataValue(tlsMissingBypass.AuditReadback, "google_workspace_rewrite_outcome"),
		"tls_bypass_with_missing_readiness_inspection_google_workspace_rewrite_outcome": m1604LogMetadataValue(tlsMissingBypass.InspectionReadback, "google_workspace_rewrite_outcome"),
		"tls_bypass_with_missing_readiness_audit_tls_bypass_suppression_outcome":        m1604LogMetadataValue(tlsMissingBypass.AuditReadback, "tls_bypass_suppression_outcome"),
		"tls_bypass_with_missing_readiness_inspection_tls_bypass_suppression_outcome":   m1604LogMetadataValue(tlsMissingBypass.InspectionReadback, "tls_bypass_suppression_outcome"),
		"tls_observed_mac_ca_missing_google_workspace_status_code":                      macCAMissingGoogle.Egress.StatusCode,
		"tls_observed_mac_ca_missing_google_workspace_audit_total_matches":              m1604TotalMatches(macCAMissingGoogle.AuditReadback),
		"tls_observed_mac_ca_missing_google_workspace_inspection_total_matches":         m1604TotalMatches(macCAMissingGoogle.InspectionReadback),
		"tls_observed_mac_ca_missing_google_workspace_audit_readiness_dependency":       m1604LogMetadataValue(macCAMissingGoogle.AuditReadback, "readiness_dependency"),
		"tls_observed_mac_ca_missing_google_workspace_audit_rewrite_outcome":            m1604LogMetadataValue(macCAMissingGoogle.AuditReadback, "google_workspace_rewrite_outcome"),
		"both_readiness_google_workspace_status_code":                                   readyGoogle.Egress.StatusCode,
		"both_readiness_google_workspace_audit_total_matches":                           m1604TotalMatches(readyGoogle.AuditReadback),
		"both_readiness_google_workspace_inspection_total_matches":                      m1604TotalMatches(readyGoogle.InspectionReadback),
		"both_readiness_google_workspace_audit_rewrite_outcome":                         m1604LogMetadataValue(readyGoogle.AuditReadback, "google_workspace_rewrite_outcome"),
		"both_readiness_google_workspace_inspection_rewrite_outcome":                    m1604LogMetadataValue(readyGoogle.InspectionReadback, "google_workspace_rewrite_outcome"),
		"both_readiness_microsoft_365_status_code":                                      readyMicrosoft.Egress.StatusCode,
		"both_readiness_microsoft_365_audit_total_matches":                              m1604TotalMatches(readyMicrosoft.AuditReadback),
		"both_readiness_microsoft_365_inspection_total_matches":                         m1604TotalMatches(readyMicrosoft.InspectionReadback),
		"both_readiness_microsoft_365_audit_rewrite_outcome":                            m1604LogMetadataValue(readyMicrosoft.AuditReadback, "microsoft_365_rewrite_outcome"),
		"both_readiness_microsoft_365_inspection_rewrite_outcome":                       m1604LogMetadataValue(readyMicrosoft.InspectionReadback, "microsoft_365_rewrite_outcome"),
		"external_saas_egress_attempted":                                                false,
		"local_capture_upstream_used":                                                   true,
		"header_values_forwarded_upstream_only":                                         true,
		"header_value_material_in_audit_log_readback":                                   false,
		"header_value_material_in_inspection_log_readback":                              false,
		"header_value_material_in_report":                                               false,
		"operator_config_value_material_in_audit_log_readback":                          false,
		"operator_config_value_material_in_inspection_log_readback":                     false,
		"operator_config_value_material_in_report":                                      false,
		"operator_config_path_material_in_report":                                       false,
		"operator_managed_tenant_header_config_loaded":                                  true,
		"tenant_header_rewrite_dependency_count":                                        float64(2),
		"operator_config_refs_visible":                                                  []string{"operator_config_ref:google_workspace_allowed_domains", "operator_config_ref:microsoft_365_allowed_tenants"},
		"header_names_visible":                                                          []string{"X-GoogApps-Allowed-Domains", "Restrict-Access-To-Tenants"},
		"per_destination_tls_bypass_required":                                           true,
		"tls_bypass_rule_count":                                                         float64(2),
		"audit_log_id_material_in_report":                                               false,
		"latest_inspection_event_id_material_in_report":                                 false,
		"latest_access_decision_id_material_in_report":                                  false,
		"swg_runtime_traffic_observed":                                                  false,
		"real_tls_interception_runtime_executed":                                        false,
		"tls_runtime_decryption_observed":                                               false,
		"header_injection_runtime_observed":                                             false,
		"mac_ca_trust_mutation_started":                                                 false,
		"mac_ca_trust_mutated":                                                          false,
		"network_extension_runtime_used":                                                false,
		"human_boundary_created":                                                        false,
		"gui_buildout_started":                                                          false,
		"presentation_only_ui_proxy_topology_started":                                   false,
		"p4_packaging_mdm_signing_install_started":                                      false,
		"shipping_product_claimed":                                                      false,
		"production_scale_claimed":                                                      false,
		"mvp_pilot_success_claimed":                                                     false,
		"windows_work_started":                                                          false,
		"productization_claims_made":                                                    false,
		"new_product_claims_made":                                                       false,
		"secret_leak_gate":                                                              "ok",
		"no_secret_attestation":                                                         true,
	}
}

func m1604RequestResultByName(result m1604ReadinessProcessCaseResult, name string) m1604EgressRequestResult {
	for _, request := range result.Requests {
		if request.Egress.Case.Name == name {
			return request
		}
	}
	return m1604EgressRequestResult{}
}

func m1604LogReadbackObserved(readback map[string]any) bool {
	return m1604TotalMatches(readback) == 1
}

func m1604TotalMatches(readback map[string]any) int {
	if readback == nil {
		return 0
	}
	value, _ := readback["total_matches"].(float64)
	return int(value)
}

func m1604LogMetadataValue(readback map[string]any, key string) string {
	rows, _ := readback["rows"].([]any)
	if len(rows) == 0 {
		return ""
	}
	row, _ := rows[0].(map[string]any)
	metadata, _ := row["metadata"].(map[string]any)
	value, _ := metadata[key].(string)
	return value
}
