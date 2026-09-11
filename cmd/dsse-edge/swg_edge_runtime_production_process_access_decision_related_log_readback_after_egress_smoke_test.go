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
	swg "github.com/lantern-networks/dsse-core/swg"

	"github.com/lantern-networks/dsse-core/swghttprewrite"
)

const (
	sWGEdgeRuntimeProductionProcessAccessDecisionRelatedLogReadbackAfterEgressSmokeReportEnv = "SWG_EDGE_RUNTIME_PRODUCTION_PROCESS_ACCESS_DECISION_RELATED_LOG_READBACK_AFTER_EGRESS_SMOKE_REPORT"
	sWGEdgeRuntimeProductionProcessAccessDecisionRelatedLogReadbackAfterEgressSmokeDSNEnv    = "SWG_EDGE_RUNTIME_PRODUCTION_PROCESS_ACCESS_DECISION_RELATED_LOG_READBACK_AFTER_EGRESS_SMOKE_POSTGRES_DSN"
)

func TestSWGEdgeSWGProductionProcessAccessDecisionRelatedLogReadbackAfterEgressSmoke(t *testing.T) {
	postgresDSN := strings.TrimSpace(os.Getenv(sWGEdgeRuntimeProductionProcessAccessDecisionRelatedLogReadbackAfterEgressSmokeDSNEnv))
	if postgresDSN == "" {
		t.Skipf("%s is required for production-mode cmd/edge process access-decision related log readback after egress smoke", sWGEdgeRuntimeProductionProcessAccessDecisionRelatedLogReadbackAfterEgressSmokeDSNEnv)
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

	binaryPath := filepath.Join(workDir, "edge-process-access-decision-related-log-readback-after-egress-smoke")
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

	runtimeTLSMissing := m1605RunProcessEgressAccessDecisionRelatedLogReadbackCase(t, common, m1602ReadinessProcessCase{
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

	tlsObservedMacCAMissing := m1605RunProcessEgressAccessDecisionRelatedLogReadbackCase(t, common, m1602ReadinessProcessCase{
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

	bothSignalsObserved := m1605RunProcessEgressAccessDecisionRelatedLogReadbackCase(t, common, m1602ReadinessProcessCase{
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

	report := m1605ProcessAccessDecisionRelatedLogReadbackAfterEgressReport(runtimeTLSMissing, tlsObservedMacCAMissing, bothSignalsObserved)
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
	for _, processCase := range []m1605ReadinessProcessCaseResult{runtimeTLSMissing, tlsObservedMacCAMissing, bothSignalsObserved} {
		for _, request := range processCase.Requests {
			m1600AssertNoForbiddenMaterial(t, request.Egress.Case.Name+" diagnostic", request.Egress.Diagnostic, forbidden[:7])
			m1600AssertNoForbiddenMaterial(t, request.Egress.Case.Name+" audit readback", request.AuditReadback, forbidden)
			m1600AssertNoForbiddenMaterial(t, request.Egress.Case.Name+" inspection readback", request.InspectionReadback, forbidden)
			m1600AssertNoForbiddenMaterial(t, request.Egress.Case.Name+" decision detail related audit/inspection", m1605AuditInspectionRelatedSubset(request.AccessDecisionReadback), forbidden)
		}
	}
	m1600AssertNoForbiddenMaterial(t, "report", report, forbidden)

	if path := strings.TrimSpace(os.Getenv(sWGEdgeRuntimeProductionProcessAccessDecisionRelatedLogReadbackAfterEgressSmokeReportEnv)); path != "" {
		writeSWGM1600JSON(t, path, report)
	}
}

type m1605ReadinessProcessCaseResult struct {
	Case             m1602ReadinessProcessCase
	Health           map[string]any
	HealthStatusCode int
	Requests         []m1605EgressRequestResult
}

type m1605EgressRequestResult struct {
	Egress                 m1602EgressRequestResult
	AuditReadback          map[string]any
	InspectionReadback     map[string]any
	AccessDecisionReadback map[string]any
}

func m1605RunProcessEgressAccessDecisionRelatedLogReadbackCase(t *testing.T, inputs m1602ProcessEgressInputs, processCase m1602ReadinessProcessCase) m1605ReadinessProcessCaseResult {
	t.Helper()
	listen := m1600FreeListenAddress(t)
	baseURL := "http://" + listen
	connectorAuthValue := "connector-auth-value-" + processCase.Name
	attestationAuthValue := "attestation-auth-value-" + processCase.Name
	adminAuthValue := "admin-auth-value-" + processCase.Name
	logDir := filepath.Join(inputs.WorkDir, "logs", "decision-log-readback", processCase.Name)

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
	results := make([]m1605EgressRequestResult, 0, len(processCase.Requests))
	for index, requestCase := range processCase.Requests {
		egress := m1602DoEgressRequest(t, client, baseURL, connectorAuthValue, inputs.Proxy, waitCh, &processErr, requestCase)
		audit := m1604GetAdminJSON(t, client, m1604AdminLogReadbackURL(baseURL, "audit", requestCase), adminAuthValue, waitCh, &processErr)
		inspection := m1604GetAdminJSON(t, client, m1604AdminLogReadbackURL(baseURL, "inspection_events", requestCase), adminAuthValue, waitCh, &processErr)
		m1604AssertLogReadbackAfterEgress(t, "audit", requestCase, audit)
		m1604AssertLogReadbackAfterEgress(t, "inspection_events", requestCase, inspection)
		decisionID := m1605AccessDecisionIDFromReadbacks(t, requestCase, audit, inspection)
		detail := m1605GetAccessDecisionDetail(t, client, baseURL, decisionID, adminAuthValue, waitCh, &processErr)
		m1605AssertAccessDecisionDetailRelatedLogs(t, requestCase, decisionID, detail)
		results = append(results, m1605EgressRequestResult{Egress: egress, AuditReadback: audit, InspectionReadback: inspection, AccessDecisionReadback: detail})
		if index+1 < len(processCase.Requests) {
			time.Sleep(1100 * time.Millisecond)
		}
	}
	return m1605ReadinessProcessCaseResult{
		Case:             processCase,
		Health:           health,
		HealthStatusCode: http.StatusOK,
		Requests:         results,
	}
}

func m1605GetAccessDecisionDetail(t *testing.T, client *http.Client, baseURL, decisionID, adminAuthValue string, waitCh chan error, processErr *bytes.Buffer) map[string]any {
	t.Helper()
	endpoint := baseURL + "/admin/access-decisions/" + url.PathEscape(decisionID)
	return m1604GetAdminJSON(t, client, endpoint, adminAuthValue, waitCh, processErr)
}

func m1605AccessDecisionIDFromReadbacks(t *testing.T, requestCase m1602EgressRequestCase, audit, inspection map[string]any) string {
	t.Helper()
	auditID := m1605SingleLogRowString(t, "audit", requestCase, audit, "access_decision_id")
	inspectionID := m1605SingleLogRowString(t, "inspection_events", requestCase, inspection, "access_decision_id")
	if auditID == "" || inspectionID == "" || auditID != inspectionID {
		t.Fatalf("access decision linkage for %s mismatch: audit=%q inspection=%q", requestCase.Name, auditID, inspectionID)
	}
	return auditID
}

func m1605SingleLogRowString(t *testing.T, stream string, requestCase m1602EgressRequestCase, readback map[string]any, key string) string {
	t.Helper()
	rows, ok := readback["rows"].([]any)
	if !ok || len(rows) != 1 {
		t.Fatalf("%s rows for %s = %#v", stream, requestCase.Name, readback["rows"])
	}
	row, ok := rows[0].(map[string]any)
	if !ok {
		t.Fatalf("%s row for %s = %#v", stream, requestCase.Name, rows[0])
	}
	value, _ := row[key].(string)
	return strings.TrimSpace(value)
}

func m1605AssertAccessDecisionDetailRelatedLogs(t *testing.T, requestCase m1602EgressRequestCase, decisionID string, detail map[string]any) {
	t.Helper()
	if detail["access_decision_id"] != decisionID {
		t.Fatalf("decision detail id for %s = %#v, want internal decision id", requestCase.Name, detail["access_decision_id"])
	}
	summary, ok := detail["summary"].(map[string]any)
	if !ok || summary["has_runtime_decision"] != true {
		t.Fatalf("decision detail summary for %s = %#v, want runtime decision", requestCase.Name, detail["summary"])
	}
	if rows, _ := summary["related_log_rows"].(float64); rows < 3 {
		t.Fatalf("decision detail related rows for %s = %#v, want access plus audit/inspection linkage", requestCase.Name, summary["related_log_rows"])
	}
	audit := m1605SingleRelatedLogRow(t, "audit", requestCase, decisionID, detail)
	inspection := m1605SingleRelatedLogRow(t, "inspection_events", requestCase, decisionID, detail)
	if audit["event_type"] != edgeplane.EdgeSWGHTTPEgressRewriteEvent || audit["target_type"] != "swg_http_egress_rewrite" || audit["action"] != "rewrite" || audit["result"] != "success" {
		t.Fatalf("related audit row for %s = %#v, want SWG rewrite audit", requestCase.Name, audit)
	}
	if inspection["content_type"] != "application/vnd.dsse.swg-rewrite-metadata+json" || inspection["finding_type"] != "saas_tenant_restriction_rewrite" || inspection["severity"] != "info" || inspection["payload_stored"] != false || inspection["masked"] != true {
		t.Fatalf("related inspection row for %s = %#v, want SWG inspection event", requestCase.Name, inspection)
	}
	m1605AssertRelatedMetadata(t, "audit", requestCase, audit)
	m1605AssertRelatedMetadata(t, "inspection_events", requestCase, inspection)
}

func m1605SingleRelatedLogRow(t *testing.T, stream string, requestCase m1602EgressRequestCase, decisionID string, detail map[string]any) map[string]any {
	t.Helper()
	related, ok := detail["related_logs"].(map[string]any)
	if !ok {
		t.Fatalf("decision detail related_logs for %s = %#v", requestCase.Name, detail["related_logs"])
	}
	rows, ok := related[stream].([]any)
	if !ok || len(rows) != 1 {
		t.Fatalf("decision detail %s related rows for %s = %#v", stream, requestCase.Name, related[stream])
	}
	row, ok := rows[0].(map[string]any)
	if !ok {
		t.Fatalf("decision detail %s related row for %s = %#v", stream, requestCase.Name, rows[0])
	}
	if row["tenant_id"] != "tenant_swg_lab" || row["access_decision_id"] != decisionID {
		t.Fatalf("decision detail %s related row for %s = %#v, want tenant and access decision linkage", stream, requestCase.Name, row)
	}
	if _, ok := row["id"].(string); !ok {
		t.Fatalf("decision detail %s related row for %s lacks id: %#v", stream, requestCase.Name, row)
	}
	return row
}

func m1605AssertRelatedMetadata(t *testing.T, stream string, requestCase m1602EgressRequestCase, row map[string]any) {
	t.Helper()
	metadata, ok := row["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("%s related metadata for %s = %#v", stream, requestCase.Name, row["metadata"])
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
			t.Fatalf("%s related metadata[%s] for %s = %#v, want %#v; metadata=%#v", stream, key, requestCase.Name, got, want, metadata)
		}
	}
	if stream == "audit" {
		if metadata["swg_rewrite_audit_version"] != "v1" || metadata["swg_rewrite_metadata_recorded_scope"] != "non_secret" {
			t.Fatalf("audit related metadata version/scope for %s = %#v", requestCase.Name, metadata)
		}
		for _, key := range []string{"header_value_material_in_audit", "header_value_material_in_api_readback", "header_value_material_in_report", "operator_config_value_material_in_audit", "operator_config_value_material_in_api_readback", "operator_config_value_material_in_report"} {
			if metadata[key] != false {
				t.Fatalf("audit related metadata[%s] for %s = %#v, want false", key, requestCase.Name, metadata[key])
			}
		}
		return
	}
	if metadata["swg_inspection_event_version"] != "swg_inspection.v1" || metadata["swg_inspection_metadata_recorded_scope"] != "non_secret" || metadata["source_audit_event_type"] != edgeplane.EdgeSWGHTTPEgressRewriteEvent {
		t.Fatalf("inspection related metadata version/scope for %s = %#v", requestCase.Name, metadata)
	}
	for _, key := range []string{"header_value_material_in_inspection_event", "header_value_material_in_api_readback", "header_value_material_in_report", "operator_config_value_material_in_inspection", "operator_config_value_material_in_api_readback", "operator_config_value_material_in_report"} {
		if metadata[key] != false {
			t.Fatalf("inspection related metadata[%s] for %s = %#v, want false", key, requestCase.Name, metadata[key])
		}
	}
}

func m1605AuditInspectionRelatedSubset(detail map[string]any) map[string]any {
	related, _ := detail["related_logs"].(map[string]any)
	return map[string]any{
		"related_logs": map[string]any{
			"audit":             related["audit"],
			"inspection_events": related["inspection_events"],
		},
	}
}

func m1605ProcessAccessDecisionRelatedLogReadbackAfterEgressReport(runtimeTLSMissing, tlsObservedMacCAMissing, bothSignalsObserved m1605ReadinessProcessCaseResult) map[string]any {
	tlsMissingGoogle := m1605RequestResultByName(runtimeTLSMissing, "google_workspace_tls_missing")
	tlsMissingBypass := m1605RequestResultByName(runtimeTLSMissing, "pinned_google_tls_bypass_with_missing_readiness")
	macCAMissingGoogle := m1605RequestResultByName(tlsObservedMacCAMissing, "google_workspace_mac_ca_missing")
	readyGoogle := m1605RequestResultByName(bothSignalsObserved, "google_workspace_ready")
	readyMicrosoft := m1605RequestResultByName(bothSignalsObserved, "microsoft_365_ready")

	return map[string]any{
		"schema_version":    "swg_edge_runtime_production_process_access_decision_related_log_readback_after_egress_smoke.v1",
		"status":            "passed",
		"depth_locked_unit": "swg_edge_runtime_production_process_access_decision_related_log_readback_after_egress_smoke_product_unit",
		"source_m1604_process_audit_inspection_log_readback_after_egress_smoke_gate":            "accepted",
		"source_m1603_process_inspection_readback_after_egress_smoke_gate":                      "accepted",
		"source_m1602_process_egress_readiness_matrix_smoke_gate":                               "accepted",
		"egress_readiness_matrix_replayed":                                                      true,
		"access_decision_related_log_readback_source":                                           "cmd_edge_process_admin_access_decisions_detail_after_http_egress",
		"cmd_edge_process_access_decision_related_log_readback_after_egress_smoke_gate":         "passed",
		"cmd_edge_process_started":                                                              true,
		"cmd_edge_process_launch_count":                                                         3,
		"cmd_edge_process_output_included":                                                      false,
		"raw_command_output_included":                                                           false,
		"raw_process_output_included":                                                           false,
		"process_id_included":                                                                   false,
		"process_listen_address_material_in_report":                                             false,
		"runtime_auth_material_in_report":                                                       false,
		"admin_auth_material_in_report":                                                         false,
		"postgres_dsn_material_in_report":                                                       false,
		"upstream_proxy_address_material_in_report":                                             false,
		"target_url_material_in_report":                                                         false,
		"target_fqdn_material_in_report":                                                        false,
		"access_decision_detail_target_material_in_report":                                      false,
		"startup_flag_names_exercised":                                                          []string{"-admin-token", "-swg-tenant-restriction-operator-config", "-swg-runtime-tls-decryption-observed", "-swg-mac-ca-trust-observed"},
		"production_mode_lab_mode":                                                              false,
		"admin_access_decision_readback_requires_admin_auth":                                    true,
		"admin_access_decision_readback_auth_method":                                            "legacy_admin_token",
		"healthz_readback_observed":                                                             runtimeTLSMissing.Health["status"] == "ok" && tlsObservedMacCAMissing.Health["status"] == "ok" && bothSignalsObserved.Health["status"] == "ok",
		"healthz_status_code":                                                                   http.StatusOK,
		"edge_http_egress_handler_path":                                                         edgeplane.EdgeSWGHTTPEgressPath,
		"admin_access_decisions_detail_api_path":                                                "/admin/access-decisions/{decision_id}",
		"admin_logs_audit_api_path":                                                             "/admin/logs/audit",
		"admin_logs_inspection_events_api_path":                                                 "/admin/logs/inspection_events",
		"http_egress_case_count":                                                                5,
		"access_decision_related_log_readback_count":                                            5,
		"related_audit_log_readback_count":                                                      5,
		"related_inspection_log_readback_count":                                                 5,
		"access_decision_related_log_readback_after_egress_observed":                            true,
		"related_audit_log_linkage_after_egress_observed":                                       true,
		"related_inspection_log_linkage_after_egress_observed":                                  true,
		"google_workspace_access_decision_related_audit_log_observed":                           m1605RelatedLogObserved(tlsMissingGoogle.AccessDecisionReadback, "audit") && m1605RelatedLogObserved(macCAMissingGoogle.AccessDecisionReadback, "audit") && m1605RelatedLogObserved(readyGoogle.AccessDecisionReadback, "audit"),
		"google_workspace_access_decision_related_inspection_log_observed":                      m1605RelatedLogObserved(tlsMissingGoogle.AccessDecisionReadback, "inspection_events") && m1605RelatedLogObserved(macCAMissingGoogle.AccessDecisionReadback, "inspection_events") && m1605RelatedLogObserved(readyGoogle.AccessDecisionReadback, "inspection_events"),
		"microsoft_365_access_decision_related_audit_log_observed":                              m1605RelatedLogObserved(readyMicrosoft.AccessDecisionReadback, "audit"),
		"microsoft_365_access_decision_related_inspection_log_observed":                         m1605RelatedLogObserved(readyMicrosoft.AccessDecisionReadback, "inspection_events"),
		"tls_bypass_access_decision_related_audit_log_observed":                                 m1605RelatedLogObserved(tlsMissingBypass.AccessDecisionReadback, "audit"),
		"tls_bypass_access_decision_related_inspection_log_observed":                            m1605RelatedLogObserved(tlsMissingBypass.AccessDecisionReadback, "inspection_events"),
		"runtime_tls_missing_google_workspace_status_code":                                      tlsMissingGoogle.Egress.StatusCode,
		"runtime_tls_missing_google_workspace_related_audit_total_matches":                      m1605RelatedLogTotalMatches(tlsMissingGoogle.AccessDecisionReadback, "audit"),
		"runtime_tls_missing_google_workspace_related_inspection_total_matches":                 m1605RelatedLogTotalMatches(tlsMissingGoogle.AccessDecisionReadback, "inspection_events"),
		"runtime_tls_missing_google_workspace_related_audit_rewrite_outcome":                    m1605RelatedLogMetadataValue(tlsMissingGoogle.AccessDecisionReadback, "audit", "google_workspace_rewrite_outcome"),
		"runtime_tls_missing_google_workspace_related_inspection_rewrite_outcome":               m1605RelatedLogMetadataValue(tlsMissingGoogle.AccessDecisionReadback, "inspection_events", "google_workspace_rewrite_outcome"),
		"runtime_tls_missing_google_workspace_related_audit_readiness_dependency":               m1605RelatedLogMetadataValue(tlsMissingGoogle.AccessDecisionReadback, "audit", "readiness_dependency"),
		"tls_bypass_with_missing_readiness_status_code":                                         tlsMissingBypass.Egress.StatusCode,
		"tls_bypass_with_missing_readiness_related_audit_total_matches":                         m1605RelatedLogTotalMatches(tlsMissingBypass.AccessDecisionReadback, "audit"),
		"tls_bypass_with_missing_readiness_related_inspection_total_matches":                    m1605RelatedLogTotalMatches(tlsMissingBypass.AccessDecisionReadback, "inspection_events"),
		"tls_bypass_with_missing_readiness_related_audit_google_workspace_rewrite_outcome":      m1605RelatedLogMetadataValue(tlsMissingBypass.AccessDecisionReadback, "audit", "google_workspace_rewrite_outcome"),
		"tls_bypass_with_missing_readiness_related_inspection_google_workspace_rewrite_outcome": m1605RelatedLogMetadataValue(tlsMissingBypass.AccessDecisionReadback, "inspection_events", "google_workspace_rewrite_outcome"),
		"tls_bypass_with_missing_readiness_related_audit_tls_bypass_suppression_outcome":        m1605RelatedLogMetadataValue(tlsMissingBypass.AccessDecisionReadback, "audit", "tls_bypass_suppression_outcome"),
		"tls_bypass_with_missing_readiness_related_inspection_tls_bypass_suppression_outcome":   m1605RelatedLogMetadataValue(tlsMissingBypass.AccessDecisionReadback, "inspection_events", "tls_bypass_suppression_outcome"),
		"tls_observed_mac_ca_missing_google_workspace_status_code":                              macCAMissingGoogle.Egress.StatusCode,
		"tls_observed_mac_ca_missing_google_workspace_related_audit_total_matches":              m1605RelatedLogTotalMatches(macCAMissingGoogle.AccessDecisionReadback, "audit"),
		"tls_observed_mac_ca_missing_google_workspace_related_inspection_total_matches":         m1605RelatedLogTotalMatches(macCAMissingGoogle.AccessDecisionReadback, "inspection_events"),
		"tls_observed_mac_ca_missing_google_workspace_related_audit_readiness_dependency":       m1605RelatedLogMetadataValue(macCAMissingGoogle.AccessDecisionReadback, "audit", "readiness_dependency"),
		"tls_observed_mac_ca_missing_google_workspace_related_audit_rewrite_outcome":            m1605RelatedLogMetadataValue(macCAMissingGoogle.AccessDecisionReadback, "audit", "google_workspace_rewrite_outcome"),
		"both_readiness_google_workspace_status_code":                                           readyGoogle.Egress.StatusCode,
		"both_readiness_google_workspace_related_audit_total_matches":                           m1605RelatedLogTotalMatches(readyGoogle.AccessDecisionReadback, "audit"),
		"both_readiness_google_workspace_related_inspection_total_matches":                      m1605RelatedLogTotalMatches(readyGoogle.AccessDecisionReadback, "inspection_events"),
		"both_readiness_google_workspace_related_audit_rewrite_outcome":                         m1605RelatedLogMetadataValue(readyGoogle.AccessDecisionReadback, "audit", "google_workspace_rewrite_outcome"),
		"both_readiness_google_workspace_related_inspection_rewrite_outcome":                    m1605RelatedLogMetadataValue(readyGoogle.AccessDecisionReadback, "inspection_events", "google_workspace_rewrite_outcome"),
		"both_readiness_microsoft_365_status_code":                                              readyMicrosoft.Egress.StatusCode,
		"both_readiness_microsoft_365_related_audit_total_matches":                              m1605RelatedLogTotalMatches(readyMicrosoft.AccessDecisionReadback, "audit"),
		"both_readiness_microsoft_365_related_inspection_total_matches":                         m1605RelatedLogTotalMatches(readyMicrosoft.AccessDecisionReadback, "inspection_events"),
		"both_readiness_microsoft_365_related_audit_rewrite_outcome":                            m1605RelatedLogMetadataValue(readyMicrosoft.AccessDecisionReadback, "audit", "microsoft_365_rewrite_outcome"),
		"both_readiness_microsoft_365_related_inspection_rewrite_outcome":                       m1605RelatedLogMetadataValue(readyMicrosoft.AccessDecisionReadback, "inspection_events", "microsoft_365_rewrite_outcome"),
		"external_saas_egress_attempted":                                                        false,
		"local_capture_upstream_used":                                                           true,
		"header_values_forwarded_upstream_only":                                                 true,
		"header_value_material_in_related_audit_log_readback":                                   false,
		"header_value_material_in_related_inspection_log_readback":                              false,
		"header_value_material_in_report":                                                       false,
		"operator_config_value_material_in_related_audit_log_readback":                          false,
		"operator_config_value_material_in_related_inspection_log_readback":                     false,
		"operator_config_value_material_in_report":                                              false,
		"operator_config_path_material_in_report":                                               false,
		"operator_managed_tenant_header_config_loaded":                                          true,
		"tenant_header_rewrite_dependency_count":                                                float64(2),
		"operator_config_refs_visible":                                                          []string{"operator_config_ref:google_workspace_allowed_domains", "operator_config_ref:microsoft_365_allowed_tenants"},
		"header_names_visible":                                                                  []string{"X-GoogApps-Allowed-Domains", "Restrict-Access-To-Tenants"},
		"per_destination_tls_bypass_required":                                                   true,
		"tls_bypass_rule_count":                                                                 float64(2),
		"related_audit_log_id_material_in_report":                                               false,
		"related_inspection_event_id_material_in_report":                                        false,
		"latest_access_decision_id_material_in_report":                                          false,
		"access_decision_id_material_in_report":                                                 false,
		"swg_runtime_traffic_observed":                                                          false,
		"real_tls_interception_runtime_executed":                                                false,
		"tls_runtime_decryption_observed":                                                       false,
		"header_injection_runtime_observed":                                                     false,
		"mac_ca_trust_mutation_started":                                                         false,
		"mac_ca_trust_mutated":                                                                  false,
		"network_extension_runtime_used":                                                        false,
		"human_boundary_created":                                                                false,
		"gui_buildout_started":                                                                  false,
		"presentation_only_ui_proxy_topology_started":                                           false,
		"p4_packaging_mdm_signing_install_started":                                              false,
		"shipping_product_claimed":                                                              false,
		"production_scale_claimed":                                                              false,
		"mvp_pilot_success_claimed":                                                             false,
		"windows_work_started":                                                                  false,
		"productization_claims_made":                                                            false,
		"new_product_claims_made":                                                               false,
		"secret_leak_gate":                                                                      "ok",
		"no_secret_attestation":                                                                 true,
	}
}

func m1605RequestResultByName(result m1605ReadinessProcessCaseResult, name string) m1605EgressRequestResult {
	for _, request := range result.Requests {
		if request.Egress.Case.Name == name {
			return request
		}
	}
	return m1605EgressRequestResult{}
}

func m1605RelatedLogObserved(detail map[string]any, stream string) bool {
	return m1605RelatedLogTotalMatches(detail, stream) == 1
}

func m1605RelatedLogTotalMatches(detail map[string]any, stream string) int {
	related, _ := detail["related_logs"].(map[string]any)
	rows, _ := related[stream].([]any)
	return len(rows)
}

func m1605RelatedLogMetadataValue(detail map[string]any, stream, key string) string {
	related, _ := detail["related_logs"].(map[string]any)
	rows, _ := related[stream].([]any)
	if len(rows) == 0 {
		return ""
	}
	row, _ := rows[0].(map[string]any)
	metadata, _ := row["metadata"].(map[string]any)
	value, _ := metadata[key].(string)
	return value
}
