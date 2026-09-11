package main

import (
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/edgeplane"
	swg "github.com/lantern-networks/dsse-core/swg"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/swghttprewrite"
)

const sWGEdgeRuntimeProductionConfigSmokeReportEnv = "SWG_EDGE_RUNTIME_PRODUCTION_CONFIG_SMOKE_REPORT"

type sWGStartupSmokeResult struct {
	StatusCode         int
	Diagnostic         map[string]any
	UpstreamRequest    *http.Request
	Decision           model.AccessDecision
	AuditMetadata      map[string]any
	InspectionMetadata map[string]any
	Handler            http.Handler
	InspectionEventID  string
}

func TestSWGEdgeSWGStartupProductionConfigSmoke(t *testing.T) {
	relaxConnectorMTLSPresentationForTest(t)
	harnessConfig, err := swghttprewrite.LoadHarnessConfig(filepath.Join("..", "..", "swghttprewrite", "testdata", "swg_saas_tenant_enforcement_preflight.json"))
	if err != nil {
		t.Fatalf("load harness config: %v", err)
	}

	runtimeMissing := sWGStartupRuntimeConfigFromFlags(t, harnessConfig.PolicyBundle, false, false)
	runtimeTLSOnly := sWGStartupRuntimeConfigFromFlags(t, harnessConfig.PolicyBundle, true, false)
	runtimeReady := sWGStartupRuntimeConfigFromFlags(t, harnessConfig.PolicyBundle, true, true)
	report := sWGStartupSmokeBaseReport(runtimeReady)

	tlsMissing := sWGStartupSmokeEgress(t, harnessConfig, runtimeMissing, "https://mail.google.com/lab/product-egress")
	if tlsMissing.StatusCode != http.StatusPreconditionRequired ||
		tlsMissing.UpstreamRequest != nil ||
		tlsMissing.Diagnostic["readiness_dependency"] != edgeplane.EdgeSWGHTTPEgressReadinessReason ||
		tlsMissing.Diagnostic["egress_forwarded"] != false ||
		tlsMissing.Diagnostic["default_tls_decryption_observed"] != false ||
		tlsMissing.Diagnostic["mac_ca_trust_observed"] != false {
		t.Fatalf("TLS missing case = status %d upstream=%v diagnostic=%#v", tlsMissing.StatusCode, tlsMissing.UpstreamRequest != nil, tlsMissing.Diagnostic)
	}
	assertSWGSWGRewriteAuditNoHeaderValues(t, runtimeMissing, tlsMissing.Diagnostic)
	assertSWGSWGRewriteAuditNoHeaderValues(t, runtimeMissing, tlsMissing.AuditMetadata)
	assertSWGSWGRewriteAuditNoHeaderValues(t, runtimeMissing, tlsMissing.InspectionMetadata)
	report["production_mode_tls_missing_blocks_google_workspace"] = true
	report["production_mode_tls_missing_status_code"] = tlsMissing.StatusCode
	report["production_mode_tls_missing_readiness_dependency"] = edgeplane.EdgeSWGHTTPEgressReadinessReason
	report["production_mode_tls_missing_egress_forwarded"] = false

	macCAMissing := sWGStartupSmokeEgress(t, harnessConfig, runtimeTLSOnly, "https://mail.google.com/lab/product-egress")
	if macCAMissing.StatusCode != http.StatusPreconditionRequired ||
		macCAMissing.UpstreamRequest != nil ||
		macCAMissing.Diagnostic["readiness_dependency"] != edgeplane.EdgeSWGHTTPEgressMacCAReason ||
		macCAMissing.Diagnostic["egress_forwarded"] != false ||
		macCAMissing.Diagnostic["default_tls_decryption_observed"] != true ||
		macCAMissing.Diagnostic["mac_ca_trust_observed"] != false {
		t.Fatalf("Mac CA missing case = status %d upstream=%v diagnostic=%#v", macCAMissing.StatusCode, macCAMissing.UpstreamRequest != nil, macCAMissing.Diagnostic)
	}
	assertSWGSWGRewriteAuditNoHeaderValues(t, runtimeTLSOnly, macCAMissing.Diagnostic)
	assertSWGSWGRewriteAuditNoHeaderValues(t, runtimeTLSOnly, macCAMissing.AuditMetadata)
	assertSWGSWGRewriteAuditNoHeaderValues(t, runtimeTLSOnly, macCAMissing.InspectionMetadata)
	report["production_mode_tls_observed_mac_ca_missing_blocks_google_workspace"] = true
	report["production_mode_tls_observed_mac_ca_missing_status_code"] = macCAMissing.StatusCode
	report["production_mode_tls_observed_mac_ca_missing_readiness_dependency"] = edgeplane.EdgeSWGHTTPEgressMacCAReason
	report["production_mode_tls_observed_mac_ca_missing_egress_forwarded"] = false

	google := sWGStartupSmokeEgress(t, harnessConfig, runtimeReady, "https://mail.google.com/lab/product-egress")
	assertSWGSWGStartupSmokeForwarded(t, runtimeReady, google, "pol_google_workspace_swg_allow_001", "saas_google_workspace", swghttprewrite.GoogleWorkspaceTenantRestrictionHeader, "operator_config_ref:google_workspace_allowed_domains", "rewritten_by_operator_config_ref", "not_applicable")
	report["production_mode_tls_and_mac_ca_observed_forwards_google_workspace"] = true
	report["production_mode_google_workspace_status_code"] = google.StatusCode
	report["production_mode_google_workspace_readiness_dependency"] = "none"

	microsoft := sWGStartupSmokeEgress(t, harnessConfig, runtimeReady, "https://www.office.com/lab/product-egress")
	assertSWGSWGStartupSmokeForwarded(t, runtimeReady, microsoft, "pol_microsoft_365_swg_allow_001", "saas_microsoft_365", swghttprewrite.Microsoft365TenantRestrictionHeader, "operator_config_ref:microsoft_365_allowed_tenants", "not_applicable", "rewritten_by_operator_config_ref")
	report["production_mode_tls_and_mac_ca_observed_forwards_microsoft_365"] = true
	report["production_mode_microsoft_365_status_code"] = microsoft.StatusCode
	report["production_mode_microsoft_365_readiness_dependency"] = "none"

	bypass := sWGStartupSmokeEgress(t, harnessConfig, runtimeMissing, "https://pinned-client.google.com/lab/product-egress")
	if bypass.StatusCode != http.StatusNoContent ||
		bypass.UpstreamRequest == nil ||
		bypass.UpstreamRequest.Header.Get(swghttprewrite.GoogleWorkspaceTenantRestrictionHeader) != "" ||
		bypass.UpstreamRequest.Header.Get(swghttprewrite.Microsoft365TenantRestrictionHeader) != "" ||
		bypass.AuditMetadata["tls_readiness_precondition_status"] != "tls_bypass_exempted" ||
		bypass.AuditMetadata["readiness_dependency"] != "none" ||
		bypass.AuditMetadata["tls_bypass_rule_id"] != "swg_tls_bypass_pinned_google_exact" ||
		bypass.AuditMetadata["egress_forwarded"] != true {
		t.Fatalf("TLS bypass case status=%d upstream=%v audit=%#v", bypass.StatusCode, bypass.UpstreamRequest != nil, bypass.AuditMetadata)
	}
	assertSWGSWGRewriteAuditNoHeaderValues(t, runtimeMissing, bypass.AuditMetadata)
	assertSWGSWGRewriteAuditNoHeaderValues(t, runtimeMissing, bypass.InspectionMetadata)
	report["production_mode_tls_bypass_destinations_remain_exempt"] = true
	report["production_mode_tls_bypass_status_code"] = bypass.StatusCode
	report["production_mode_tls_bypass_readiness_dependency"] = "none"
	report["production_mode_tls_bypass_precondition_status"] = "tls_bypass_exempted"
	report["production_mode_tls_bypass_header_injection_suppressed"] = true

	status := sWGStartupSmokeTLSReadinessStatus(t, google.Handler, google.Decision, google.InspectionEventID)
	for key, want := range map[string]any{
		"schema_version":                           "swg_tls_readiness_status.v1",
		"status":                                   "readiness_visible_runtime_observed",
		"readback_path":                            swg.EdgeSWGTLSReadinessStatusPath,
		"edge_http_egress_handler_path":            edgeplane.EdgeSWGHTTPEgressPath,
		"default_tls_decryption_required":          true,
		"default_tls_decryption_observed":          true,
		"default_tls_decryption_status":            "required_observed",
		"mac_ca_trust_required":                    true,
		"mac_ca_trust_observed":                    true,
		"mac_ca_trust_mutated":                     false,
		"mac_ca_trust_status":                      "required_observed",
		"tenant_header_rewrite_dependency_count":   float64(2),
		"per_destination_tls_bypass_required":      true,
		"tls_bypass_rule_count":                    float64(2),
		"runtime_tls_decryption_observed":          true,
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
			t.Fatalf("TLS readiness status[%s] = %#v, want %#v; status=%#v", key, got, want, status)
		}
	}
	assertSWGSWGRewriteAuditNoHeaderValues(t, runtimeReady, status)
	report["tls_readiness_status_api_readback_observed"] = true
	report["tls_readiness_status_runtime_tls_decryption_observed"] = true
	report["tls_readiness_status_mac_ca_trust_observed"] = true
	report["tls_readiness_status_header_value_material_in_status"] = false
	report["tls_readiness_status_operator_config_value_material_in_status"] = false
	report["inspection_metadata_readback_observed"] = true
	report["inspection_metadata_latest_access_decision_id_present"] = strings.TrimSpace(google.Decision.ID) != ""
	report["inspection_metadata_latest_inspection_event_id_present"] = strings.TrimSpace(google.InspectionEventID) != ""

	assertSWGSWGRewriteAuditNoHeaderValues(t, runtimeReady, report)
	if path := strings.TrimSpace(os.Getenv(sWGEdgeRuntimeProductionConfigSmokeReportEnv)); path != "" {
		writeSWGSWGStartupSmokeReport(t, path, report)
	}
}

func sWGStartupRuntimeConfigFromFlags(t *testing.T, bundle model.PolicyBundle, tlsObserved, macCAObserved bool) swg.RuntimeConfig {
	t.Helper()
	flagSet := flag.NewFlagSet("swg-edge-runtime-production-config-smoke", flag.ContinueOnError)
	flagSet.SetOutput(io.Discard)
	operatorConfig := flagSet.String("swg-tenant-restriction-operator-config", "", "")
	runtimeTLS := flagSet.Bool("swg-runtime-tls-decryption-observed", false, "")
	macCA := flagSet.Bool("swg-mac-ca-trust-observed", false, "")
	args := []string{
		"-swg-tenant-restriction-operator-config",
		filepath.Join("..", "..", "swghttprewrite", "testdata", "swg_tenant_restriction_operator_config.json"),
	}
	if tlsObserved {
		args = append(args, "-swg-runtime-tls-decryption-observed")
	}
	if macCAObserved {
		args = append(args, "-swg-mac-ca-trust-observed")
	}
	if err := flagSet.Parse(args); err != nil {
		t.Fatalf("parse startup SWG flags: %v", err)
	}
	runtimeConfig, err := swg.LoadRuntimeConfig(swg.RuntimeConfigInput{
		TenantRestrictionOperatorConfigPath: *operatorConfig,
		PolicyBundle:                        bundle,
		RuntimeTLSDecryptionObserved:        *runtimeTLS,
		MacCATrustObserved:                  *macCA,
	})
	if err != nil {
		t.Fatalf("load SWG runtime config from startup flags: %v", err)
	}
	if runtimeConfig.RuntimeTLSDecryptionObserved != tlsObserved || runtimeConfig.MacCATrustObserved != macCAObserved {
		t.Fatalf("runtime readiness flags = tls:%v mac_ca:%v, want tls:%v mac_ca:%v", runtimeConfig.RuntimeTLSDecryptionObserved, runtimeConfig.MacCATrustObserved, tlsObserved, macCAObserved)
	}
	return runtimeConfig
}

func sWGStartupSmokeBaseReport(runtimeConfig swg.RuntimeConfig) map[string]any {
	return map[string]any{
		"schema_version":                                 "swg_edge_runtime_production_config_smoke.v1",
		"status":                                         "passed",
		"depth_locked_unit":                              "swg_edge_runtime_production_config_smoke_product_unit",
		"edge_startup_smoke_gate":                        "passed",
		"startup_flag_parse_gate":                        "passed",
		"startup_flag_names_exercised":                   []string{"-swg-tenant-restriction-operator-config", "-swg-runtime-tls-decryption-observed", "-swg-mac-ca-trust-observed"},
		"edge_http_egress_handler_path":                  edgeplane.EdgeSWGHTTPEgressPath,
		"tls_readiness_status_api_path":                  swg.EdgeSWGTLSReadinessStatusPath,
		"production_mode_lab_mode":                       false,
		"operator_managed_tenant_header_config_loaded":   runtimeConfig.TenantRestrictionResolverConfigured,
		"operator_config_refs_visible":                   append([]string{}, runtimeConfig.TenantRestrictionOperatorConfigRefs...),
		"header_names_visible":                           []string{swghttprewrite.GoogleWorkspaceTenantRestrictionHeader, swghttprewrite.Microsoft365TenantRestrictionHeader},
		"runtime_tls_decryption_observed_flag_input":     true,
		"mac_ca_trust_observed_flag_input":               true,
		"header_values_forwarded_upstream_only":          true,
		"operator_config_path_material_in_report":        false,
		"header_value_material_in_report":                false,
		"operator_config_value_material_in_report":       false,
		"header_value_material_in_inspection_event":      false,
		"header_value_material_in_api_readback":          false,
		"operator_config_value_material_in_inspection":   false,
		"operator_config_value_material_in_api_readback": false,
		"swg_runtime_traffic_observed":                   false,
		"real_tls_interception_runtime_executed":         false,
		"tls_runtime_decryption_observed":                false,
		"header_injection_runtime_observed":              false,
		"mac_ca_trust_mutation_started":                  false,
		"mac_ca_trust_mutated":                           false,
		"network_extension_runtime_used":                 false,
		"human_boundary_created":                         false,
		"gui_buildout_started":                           false,
		"p4_packaging_mdm_signing_install_started":       false,
		"shipping_product_claimed":                       false,
		"production_scale_claimed":                       false,
		"mvp_pilot_success_claimed":                      false,
		"windows_work_started":                           false,
		"productization_claims_made":                     false,
		"new_product_claims_made":                        false,
		"secret_leak_gate":                               "ok",
		"no_secret_attestation":                          true,
	}
}

func sWGStartupSmokeEgress(t *testing.T, harnessConfig swghttprewrite.HarnessConfig, runtimeConfig swg.RuntimeConfig, targetURL string) sWGStartupSmokeResult {
	t.Helper()
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}
	captured := make(chan *http.Request, 1)
	decisions := newAccessDecisionStore()
	evaluator := decision.Evaluator{
		Policies:      harnessConfig.Policies,
		PolicyBundle:  harnessConfig.PolicyBundle,
		EdgeRegionID:  "local",
		EdgeClusterID: "local-edge-a",
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: evaluator,
		Writer:    writer,
		ProxyClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			clone := req.Clone(req.Context())
			clone.Header = req.Header.Clone()
			captured <- clone
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("")),
				Request:    req,
			}, nil
		})},
		SWGRuntime:    runtimeConfig,
		DecisionStore: decisions,
		LabMode:       boolPtr(false),
	})

	req := httptest.NewRequest(http.MethodGet, edgeplane.EdgeSWGHTTPEgressPath, nil)
	req.Header.Set(edgeplane.EdgeSWGHTTPEgressTargetURLHeader, targetURL)
	req.Header.Set(connectorSecretHeader, defaultConnectorSecret)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var diagnostic map[string]any
	if rec.Code == http.StatusPreconditionRequired {
		if err := json.NewDecoder(rec.Body).Decode(&diagnostic); err != nil {
			t.Fatalf("decode readiness dependency diagnostic: %v", err)
		}
	}
	var upstream *http.Request
	select {
	case upstream = <-captured:
	default:
	}
	dec, ok := decisions.LatestForApplication(harnessConfig.PolicyBundle.TenantID, edgeplane.EdgeSWGEgressApplicationID)
	if !ok {
		t.Fatalf("no SWG edge egress decision recorded for target %s", targetURL)
	}
	// The rewrite is recorded once now (the audit twin was removed,): AuditMetadata mirrors the inspection
	// event's metadata so the harness's non-secret / readiness assertions run against the surviving record.
	inspectionMetadata := sWGStartupSmokeSingleMetadataRow(t, writer, "inspection_events.log.jsonl")
	auditMetadata := inspectionMetadata
	inspectionRows, err := writer.ReadJSONL("inspection_events.log.jsonl")
	if err != nil {
		t.Fatalf("read inspection rows: %v", err)
	}
	inspectionID, _ := inspectionRows[0]["id"].(string)
	return sWGStartupSmokeResult{
		StatusCode:         rec.Code,
		Diagnostic:         diagnostic,
		UpstreamRequest:    upstream,
		Decision:           dec,
		AuditMetadata:      auditMetadata,
		InspectionMetadata: inspectionMetadata,
		Handler:            handler,
		InspectionEventID:  inspectionID,
	}
}

func assertSWGSWGStartupSmokeForwarded(t *testing.T, runtimeConfig swg.RuntimeConfig, result sWGStartupSmokeResult, wantPolicyID, wantSaaS, wantHeader, wantRef, wantGoogle, wantMicrosoft string) {
	t.Helper()
	if result.StatusCode != http.StatusNoContent || result.UpstreamRequest == nil {
		t.Fatalf("forwarded case status=%d upstream=%v", result.StatusCode, result.UpstreamRequest != nil)
	}
	if result.Decision.PolicyID != wantPolicyID || result.Decision.Decision != "allow" || result.Decision.SaaSContext == nil || result.Decision.SaaSContext.SaaSApplicationID != wantSaaS {
		t.Fatalf("decision = %#v, want allow policy %s SaaS %s", result.Decision, wantPolicyID, wantSaaS)
	}
	wantValue, ok := runtimeConfig.TenantRestrictionResolver.ResolveHeaderValue(wantRef)
	if !ok || strings.TrimSpace(wantValue) == "" {
		t.Fatalf("runtime resolver did not resolve %s", wantRef)
	}
	if got := result.UpstreamRequest.Header.Get(wantHeader); got != wantValue {
		t.Fatalf("upstream header %s = %q, want configured value", wantHeader, got)
	}
	if result.UpstreamRequest.Header.Get(connectorSecretHeader) != "" || result.UpstreamRequest.Header.Get(edgeplane.EdgeSWGHTTPEgressTargetURLHeader) != "" {
		t.Fatalf("edge runtime control headers were forwarded upstream")
	}
	for key, want := range map[string]any{
		"runtime_tls_decryption_observed":              true,
		"runtime_header_injection_observed":            false,
		"network_extension_runtime_used":               false,
		"google_workspace_rewrite_outcome":             wantGoogle,
		"microsoft_365_rewrite_outcome":                wantMicrosoft,
		"tls_bypass_suppression_outcome":               "not_applied",
		"tls_readiness_precondition_status":            "mac_ca_trust_observed",
		"readiness_dependency":                         "none",
		"egress_forwarded":                             true,
		"default_tls_decryption_observed":              true,
		"mac_ca_trust_observed":                        true,
		"real_tls_interception_runtime_executed":       false,
		"mac_ca_trust_mutated":                         false,
		"p4_packaging_mdm_signing_install_started":     false,
		"shipping_product_claimed":                     false,
		"production_scale_claimed":                     false,
		"mvp_pilot_success_claimed":                    false,
		"windows_work_started":                         false,
		"header_value_material_in_inspection_event":    false,
		"operator_config_value_material_in_inspection": false,
		"header_value_material_in_diagnostic":          false,
		"operator_config_value_material_in_diagnostic": false,
	} {
		if got := result.AuditMetadata[key]; got != want {
			t.Fatalf("audit metadata[%s] = %#v, want %#v; metadata=%#v", key, got, want, result.AuditMetadata)
		}
	}
	for key, want := range map[string]any{
		"runtime_tls_decryption_observed":              true,
		"runtime_header_injection_observed":            false,
		"network_extension_runtime_used":               false,
		"google_workspace_rewrite_outcome":             wantGoogle,
		"microsoft_365_rewrite_outcome":                wantMicrosoft,
		"tls_bypass_suppression_outcome":               "not_applied",
		"tls_readiness_precondition_status":            "mac_ca_trust_observed",
		"readiness_dependency":                         "none",
		"egress_forwarded":                             true,
		"default_tls_decryption_observed":              true,
		"mac_ca_trust_observed":                        true,
		"real_tls_interception_runtime_executed":       false,
		"mac_ca_trust_mutated":                         false,
		"header_value_material_in_inspection_event":    false,
		"operator_config_value_material_in_inspection": false,
	} {
		if got := result.InspectionMetadata[key]; got != want {
			t.Fatalf("inspection metadata[%s] = %#v, want %#v; metadata=%#v", key, got, want, result.InspectionMetadata)
		}
	}
	assertSWGSWGRewriteAuditNoHeaderValues(t, runtimeConfig, result.AuditMetadata)
	assertSWGSWGRewriteAuditNoHeaderValues(t, runtimeConfig, result.InspectionMetadata)
}

func sWGStartupSmokeSingleMetadataRow(t *testing.T, writer *logs.Writer, stream string) map[string]any {
	t.Helper()
	rows, err := writer.ReadJSONL(stream)
	if err != nil {
		t.Fatalf("read %s: %v", stream, err)
	}
	if len(rows) != 1 {
		t.Fatalf("%s rows = %#v, want one row", stream, rows)
	}
	metadata, ok := rows[0]["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("%s metadata = %#v", stream, rows[0]["metadata"])
	}
	return metadata
}

func sWGStartupSmokeTLSReadinessStatus(t *testing.T, handler http.Handler, dec model.AccessDecision, inspectionEventID string) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, swg.EdgeSWGTLSReadinessStatusPath, nil)
	req.Header.Set(connectorSecretHeader, defaultConnectorSecret)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("TLS readiness status code = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var status map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&status); err != nil {
		t.Fatalf("decode TLS readiness status: %v", err)
	}
	if status["latest_access_decision_id"] != dec.ID || status["latest_inspection_event_id"] != inspectionEventID {
		t.Fatalf("TLS status latest ids = %v/%v, want %s/%s", status["latest_access_decision_id"], status["latest_inspection_event_id"], dec.ID, inspectionEventID)
	}
	return status
}

func writeSWGSWGStartupSmokeReport(t *testing.T, path string, report map[string]any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create report dir: %v", err)
	}
	body, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("marshal startup smoke report: %v", err)
	}
	body = append(body, '\n')
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write startup smoke report: %v", err)
	}
}
