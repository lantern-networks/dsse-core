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
	swg "github.com/lantern-networks/dsse-core/swg"
)

const (
	sWGEdgeRuntimeProductionProcessReadinessNegativeStatusSmokeReportEnv = "SWG_EDGE_RUNTIME_PRODUCTION_PROCESS_READINESS_NEGATIVE_STATUS_SMOKE_REPORT"
	sWGEdgeRuntimeProductionProcessReadinessNegativeStatusSmokeDSNEnv    = "SWG_EDGE_RUNTIME_PRODUCTION_PROCESS_READINESS_NEGATIVE_STATUS_SMOKE_POSTGRES_DSN"
)

func TestSWGEdgeSWGProductionProcessReadinessNegativeStatusSmoke(t *testing.T) {
	postgresDSN := strings.TrimSpace(os.Getenv(sWGEdgeRuntimeProductionProcessReadinessNegativeStatusSmokeDSNEnv))
	if postgresDSN == "" {
		t.Skipf("%s is required for production-mode cmd/edge process readiness negative status smoke", sWGEdgeRuntimeProductionProcessReadinessNegativeStatusSmokeDSNEnv)
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
	policyPaths, bundlePath := m1600WriteHarnessRuntimeInputs(t, filepath.Join(moduleRoot, "swghttprewrite", "testdata", "swg_saas_tenant_enforcement_preflight.json"), workDir)

	binaryPath := filepath.Join(workDir, "edge-process-readiness-negative-status-smoke")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	build.Dir = filepath.Join(moduleRoot, "cmd", "edge")
	build.Env = os.Environ()
	build.Stdout = io.Discard
	var buildErr bytes.Buffer
	build.Stderr = &buildErr
	if err := build.Run(); err != nil {
		t.Fatalf("build cmd/edge failed: %v; stderr redacted=%s", err, m1600RedactedLine(buildErr.String()))
	}

	operatorConfigPath := filepath.Join(moduleRoot, "swghttprewrite", "testdata", "swg_tenant_restriction_operator_config.json")
	common := m1601ProcessCaseInputs{
		ModuleRoot:         moduleRoot,
		RepoRoot:           repoRoot,
		WorkDir:            workDir,
		BinaryPath:         binaryPath,
		PolicyPaths:        policyPaths,
		BundlePath:         bundlePath,
		OperatorConfigPath: operatorConfigPath,
		PostgresDSN:        postgresDSN,
	}

	runtimeTLSMissing := m1601RunProcessReadinessCase(t, common, m1601ReadinessCase{
		Name:                        "runtime_tls_missing",
		RuntimeTLSObservedFlagInput: false,
		MacCATrustObservedFlagInput: false,
	})
	m1601AssertReadinessStatus(t, runtimeTLSMissing.Status, "readiness_visible_not_runtime_observed", false, "required_not_observed", false, "required_not_mutated")

	tlsObservedMacCAMissing := m1601RunProcessReadinessCase(t, common, m1601ReadinessCase{
		Name:                        "tls_observed_mac_ca_missing",
		RuntimeTLSObservedFlagInput: true,
		MacCATrustObservedFlagInput: false,
	})
	m1601AssertReadinessStatus(t, tlsObservedMacCAMissing.Status, "readiness_visible_runtime_observed", true, "required_observed", false, "required_not_mutated")

	report := m1601ProcessReadinessNegativeStatusReport(runtimeTLSMissing, tlsObservedMacCAMissing)
	forbidden := []string{
		"google-workspace.lab.example",
		"microsoft-365-tenant.lab.example",
		"swg_tenant_restriction_operator_config.json",
		"connector-auth-value",
		"attestation-auth-value",
		postgresDSN,
	}
	m1600AssertNoForbiddenMaterial(t, "runtime TLS missing status", runtimeTLSMissing.Status, forbidden)
	m1600AssertNoForbiddenMaterial(t, "TLS observed Mac CA missing status", tlsObservedMacCAMissing.Status, forbidden)
	m1600AssertNoForbiddenMaterial(t, "report", report, forbidden)

	if path := strings.TrimSpace(os.Getenv(sWGEdgeRuntimeProductionProcessReadinessNegativeStatusSmokeReportEnv)); path != "" {
		writeSWGM1600JSON(t, path, report)
	}
}

type m1601ProcessCaseInputs struct {
	ModuleRoot         string
	RepoRoot           string
	WorkDir            string
	BinaryPath         string
	PolicyPaths        []string
	BundlePath         string
	OperatorConfigPath string
	PostgresDSN        string
}

type m1601ReadinessCase struct {
	Name                        string
	RuntimeTLSObservedFlagInput bool
	MacCATrustObservedFlagInput bool
}

type m1601ReadinessCaseResult struct {
	Case                        m1601ReadinessCase
	Health                      map[string]any
	Status                      map[string]any
	HealthStatusCode            int
	TLSReadinessStatusCode      int
	OperatorConfigRefsVisible   []string
	HeaderNamesVisible          []string
	DependenciesResolved        bool
	TLSBypassRuleCount          int
	TenantHeaderDependencyCount int
}

func m1601RunProcessReadinessCase(t *testing.T, inputs m1601ProcessCaseInputs, readinessCase m1601ReadinessCase) m1601ReadinessCaseResult {
	t.Helper()
	listen := m1600FreeListenAddress(t)
	baseURL := "http://" + listen
	connectorAuthValue := "connector-auth-value-" + readinessCase.Name
	attestationAuthValue := "attestation-auth-value-" + readinessCase.Name
	logDir := filepath.Join(inputs.WorkDir, "logs", readinessCase.Name)

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
	if readinessCase.RuntimeTLSObservedFlagInput {
		args = append(args, "-swg-runtime-tls-decryption-observed")
	}
	if readinessCase.MacCATrustObservedFlagInput {
		args = append(args, "-swg-mac-ca-trust-observed")
	}

	cmd := exec.CommandContext(context.Background(), inputs.BinaryPath, args...)
	cmd.Dir = inputs.ModuleRoot
	cmd.Stdout = io.Discard
	var processErr bytes.Buffer
	cmd.Stderr = &processErr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start cmd/edge process for %s: %v", readinessCase.Name, err)
	}
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()
	defer m1600StopProcess(t, cmd, waitCh)

	client := &http.Client{Timeout: 2 * time.Second}
	health := m1600WaitForHealthz(t, client, baseURL, waitCh, &processErr)
	status := m1600GetJSON(t, client, baseURL+swg.EdgeSWGTLSReadinessStatusPath, connectorAuthValue, waitCh, &processErr)
	refs, names, depsResolved, depCount := m1601DependencyVisibility(status)

	return m1601ReadinessCaseResult{
		Case:                        readinessCase,
		Health:                      health,
		Status:                      status,
		HealthStatusCode:            http.StatusOK,
		TLSReadinessStatusCode:      http.StatusOK,
		OperatorConfigRefsVisible:   refs,
		HeaderNamesVisible:          names,
		DependenciesResolved:        depsResolved,
		TLSBypassRuleCount:          len(m1601JSONArray(status["tls_bypass_rules"])),
		TenantHeaderDependencyCount: depCount,
	}
}

func m1601AssertReadinessStatus(t *testing.T, status map[string]any, visibility string, tlsObserved bool, tlsStatus string, macCAObserved bool, macCAStatus string) {
	t.Helper()
	for key, want := range map[string]any{
		"schema_version":                           "swg_tls_readiness_status.v1",
		"status":                                   visibility,
		"tenant_id":                                "tenant_swg_lab",
		"policy_bundle_id":                         "pb_swg_preflight_m1583",
		"policy_bundle_version":                    "swg-saas-tenant-preflight",
		"readback_path":                            swg.EdgeSWGTLSReadinessStatusPath,
		"edge_http_egress_handler_path":            edgeplane.EdgeSWGHTTPEgressPath,
		"default_tls_decryption_required":          true,
		"default_tls_decryption_observed":          tlsObserved,
		"default_tls_decryption_status":            tlsStatus,
		"tenant_header_rewrite_dependency_count":   float64(2),
		"per_destination_tls_bypass_required":      true,
		"tls_bypass_rule_count":                    float64(2),
		"mac_ca_trust_required":                    true,
		"mac_ca_trust_observed":                    macCAObserved,
		"mac_ca_trust_mutated":                     false,
		"mac_ca_trust_status":                      macCAStatus,
		"inspection_metadata_readback_observed":    false,
		"inspection_event_count":                   float64(0),
		"runtime_tls_decryption_observed":          tlsObserved,
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
			t.Fatalf("status[%s] = %#v, want %#v; status=%#v", key, got, want, status)
		}
	}
	if !m1600StringArrayEquals(status["required_inspection_profile_ids"], []string{"ip_swg_default_tls_decrypt"}) {
		t.Fatalf("required inspection profile ids = %#v", status["required_inspection_profile_ids"])
	}
	if !m1600StringArrayEquals(status["mac_trust_profile_ids"], []string{"tp_swg_mac_trust"}) {
		t.Fatalf("mac trust profile ids = %#v", status["mac_trust_profile_ids"])
	}
	if !m1600StringArrayEquals(status["tenant_root_ca_ids"], []string{"trca_swg_lab"}) {
		t.Fatalf("tenant root CA ids = %#v", status["tenant_root_ca_ids"])
	}
	deps, ok := status["tenant_header_rewrite_dependencies"].([]any)
	if !ok || len(deps) != 2 {
		t.Fatalf("tenant header rewrite dependencies = %#v", status["tenant_header_rewrite_dependencies"])
	}
	m1600AssertDependency(t, deps, "X-GoogApps-Allowed-Domains", "operator_config_ref:google_workspace_allowed_domains")
	m1600AssertDependency(t, deps, "Restrict-Access-To-Tenants", "operator_config_ref:microsoft_365_allowed_tenants")
	bypassRules, ok := status["tls_bypass_rules"].([]any)
	if !ok || len(bypassRules) != 2 ||
		!m1600RulePresent(bypassRules, "swg_tls_bypass_banking_category") ||
		!m1600RulePresent(bypassRules, "swg_tls_bypass_pinned_google_exact") {
		t.Fatalf("tls bypass rules = %#v", status["tls_bypass_rules"])
	}
}

func m1601ProcessReadinessNegativeStatusReport(runtimeTLSMissing, tlsObservedMacCAMissing m1601ReadinessCaseResult) map[string]any {
	return map[string]any{
		"schema_version":    "swg_edge_runtime_production_process_readiness_negative_status_smoke.v1",
		"status":            "passed",
		"depth_locked_unit": "swg_edge_runtime_production_process_readiness_negative_status_smoke_product_unit",
		"source_m1599_handler_product_path_smoke_gate":                 "passed",
		"egress_forwarding_coverage_source":                            "m1599_handler_product_path_smoke",
		"cmd_edge_process_readiness_negative_status_smoke_gate":        "passed",
		"cmd_edge_process_started":                                     true,
		"cmd_edge_process_launch_count":                                2,
		"cmd_edge_process_output_included":                             false,
		"raw_command_output_included":                                  false,
		"raw_process_output_included":                                  false,
		"process_id_included":                                          false,
		"process_listen_address_material_in_report":                    false,
		"runtime_auth_material_in_report":                              false,
		"postgres_dsn_material_in_report":                              false,
		"startup_flag_names_exercised":                                 []string{"-swg-tenant-restriction-operator-config", "-swg-runtime-tls-decryption-observed", "-swg-mac-ca-trust-observed"},
		"production_mode_lab_mode":                                     false,
		"healthz_readback_observed":                                    runtimeTLSMissing.Health["status"] == "ok" && tlsObservedMacCAMissing.Health["status"] == "ok",
		"healthz_status_code":                                          http.StatusOK,
		"tls_readiness_status_api_path":                                swg.EdgeSWGTLSReadinessStatusPath,
		"tls_readiness_status_api_readback_observed":                   true,
		"tls_readiness_status_code":                                    http.StatusOK,
		"tls_readiness_status_schema_version":                          runtimeTLSMissing.Status["schema_version"],
		"edge_http_egress_handler_path":                                runtimeTLSMissing.Status["edge_http_egress_handler_path"],
		"negative_readiness_case_count":                                2,
		"runtime_tls_missing_case_observed":                            true,
		"runtime_tls_missing_tls_readiness_status_visibility":          runtimeTLSMissing.Status["status"],
		"runtime_tls_missing_default_tls_decryption_required":          runtimeTLSMissing.Status["default_tls_decryption_required"],
		"runtime_tls_missing_default_tls_decryption_observed":          runtimeTLSMissing.Status["default_tls_decryption_observed"],
		"runtime_tls_missing_default_tls_decryption_status":            runtimeTLSMissing.Status["default_tls_decryption_status"],
		"runtime_tls_missing_flag_input":                               runtimeTLSMissing.Case.RuntimeTLSObservedFlagInput,
		"runtime_tls_missing_mac_ca_trust_required":                    runtimeTLSMissing.Status["mac_ca_trust_required"],
		"runtime_tls_missing_mac_ca_trust_observed":                    runtimeTLSMissing.Status["mac_ca_trust_observed"],
		"runtime_tls_missing_mac_ca_trust_observed_flag_input":         runtimeTLSMissing.Case.MacCATrustObservedFlagInput,
		"runtime_tls_missing_mac_ca_trust_mutated":                     runtimeTLSMissing.Status["mac_ca_trust_mutated"],
		"runtime_tls_missing_mac_ca_trust_status":                      runtimeTLSMissing.Status["mac_ca_trust_status"],
		"tls_observed_mac_ca_missing_case_observed":                    true,
		"tls_observed_mac_ca_missing_tls_readiness_status_visibility":  tlsObservedMacCAMissing.Status["status"],
		"tls_observed_mac_ca_missing_default_tls_decryption_required":  tlsObservedMacCAMissing.Status["default_tls_decryption_required"],
		"tls_observed_mac_ca_missing_default_tls_decryption_observed":  tlsObservedMacCAMissing.Status["default_tls_decryption_observed"],
		"tls_observed_mac_ca_missing_default_tls_decryption_status":    tlsObservedMacCAMissing.Status["default_tls_decryption_status"],
		"tls_observed_mac_ca_missing_runtime_tls_flag_input":           tlsObservedMacCAMissing.Case.RuntimeTLSObservedFlagInput,
		"tls_observed_mac_ca_missing_mac_ca_trust_required":            tlsObservedMacCAMissing.Status["mac_ca_trust_required"],
		"tls_observed_mac_ca_missing_mac_ca_trust_observed":            tlsObservedMacCAMissing.Status["mac_ca_trust_observed"],
		"tls_observed_mac_ca_missing_mac_ca_trust_observed_flag_input": tlsObservedMacCAMissing.Case.MacCATrustObservedFlagInput,
		"tls_observed_mac_ca_missing_mac_ca_trust_mutated":             tlsObservedMacCAMissing.Status["mac_ca_trust_mutated"],
		"tls_observed_mac_ca_missing_mac_ca_trust_status":              tlsObservedMacCAMissing.Status["mac_ca_trust_status"],
		"operator_managed_tenant_header_config_loaded":                 runtimeTLSMissing.DependenciesResolved && tlsObservedMacCAMissing.DependenciesResolved,
		"tenant_header_rewrite_dependency_count":                       runtimeTLSMissing.TenantHeaderDependencyCount,
		"operator_config_refs_visible":                                 runtimeTLSMissing.OperatorConfigRefsVisible,
		"header_names_visible":                                         runtimeTLSMissing.HeaderNamesVisible,
		"per_destination_tls_bypass_required":                          runtimeTLSMissing.Status["per_destination_tls_bypass_required"],
		"tls_bypass_rule_count":                                        runtimeTLSMissing.TLSBypassRuleCount,
		"inspection_metadata_readback_observed":                        runtimeTLSMissing.Status["inspection_metadata_readback_observed"],
		"inspection_event_count":                                       runtimeTLSMissing.Status["inspection_event_count"],
		"header_value_material_in_status":                              runtimeTLSMissing.Status["header_value_material_in_status"],
		"operator_config_value_material_in_status":                     runtimeTLSMissing.Status["operator_config_value_material_in_status"],
		"header_value_material_in_report":                              false,
		"operator_config_value_material_in_report":                     false,
		"operator_config_path_material_in_report":                      false,
		"swg_runtime_traffic_observed":                                 false,
		"real_tls_interception_runtime_executed":                       false,
		"tls_runtime_decryption_observed":                              false,
		"header_injection_runtime_observed":                            false,
		"mac_ca_trust_mutation_started":                                false,
		"mac_ca_trust_mutated":                                         false,
		"network_extension_runtime_used":                               false,
		"human_boundary_created":                                       false,
		"gui_buildout_started":                                         false,
		"presentation_only_ui_proxy_topology_started":                  false,
		"p4_packaging_mdm_signing_install_started":                     false,
		"shipping_product_claimed":                                     false,
		"production_scale_claimed":                                     false,
		"mvp_pilot_success_claimed":                                    false,
		"windows_work_started":                                         false,
		"productization_claims_made":                                   false,
		"new_product_claims_made":                                      false,
		"secret_leak_gate":                                             "ok",
		"no_secret_attestation":                                        true,
	}
}

func m1601DependencyVisibility(status map[string]any) ([]string, []string, bool, int) {
	refs := []string{}
	names := []string{}
	resolved := true
	deps := m1601JSONArray(status["tenant_header_rewrite_dependencies"])
	for _, raw := range deps {
		dep, ok := raw.(map[string]any)
		if !ok {
			resolved = false
			continue
		}
		if ref, ok := dep["operator_config_ref"].(string); ok && ref != "" {
			refs = append(refs, ref)
		}
		if name, ok := dep["header_name"].(string); ok && name != "" {
			names = append(names, name)
		}
		if dep["operator_config_ref_resolved"] != true {
			resolved = false
		}
	}
	return refs, names, resolved, len(deps)
}

func m1601JSONArray(raw any) []any {
	values, ok := raw.([]any)
	if !ok {
		return []any{}
	}
	return values
}
