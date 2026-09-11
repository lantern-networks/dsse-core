package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
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
	sWGEdgeRuntimeProductionProcessStatusSmokeReportEnv = "SWG_EDGE_RUNTIME_PRODUCTION_PROCESS_STATUS_SMOKE_REPORT"
	sWGEdgeRuntimeProductionProcessStatusSmokeDSNEnv    = "SWG_EDGE_RUNTIME_PRODUCTION_PROCESS_STATUS_SMOKE_POSTGRES_DSN"
)

func TestSWGEdgeSWGProductionProcessStatusSmoke(t *testing.T) {
	postgresDSN := strings.TrimSpace(os.Getenv(sWGEdgeRuntimeProductionProcessStatusSmokeDSNEnv))
	if postgresDSN == "" {
		t.Skipf("%s is required for production-mode cmd/edge process status smoke", sWGEdgeRuntimeProductionProcessStatusSmokeDSNEnv)
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

	binaryPath := filepath.Join(workDir, "edge-process-status-smoke")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	build.Dir = filepath.Join(moduleRoot, "cmd", "edge")
	build.Env = os.Environ()
	build.Stdout = io.Discard
	var buildErr bytes.Buffer
	build.Stderr = &buildErr
	if err := build.Run(); err != nil {
		t.Fatalf("build cmd/edge failed: %v; stderr redacted=%s", err, m1600RedactedLine(buildErr.String()))
	}

	listen := m1600FreeListenAddress(t)
	baseURL := "http://" + listen
	connectorAuthValue := "connector-auth-value-0001"
	attestationAuthValue := "attestation-auth-value-0001"
	operatorConfigPath := filepath.Join(moduleRoot, "swghttprewrite", "testdata", "swg_tenant_restriction_operator_config.json")
	logDir := filepath.Join(workDir, "logs")

	cmd := exec.CommandContext(context.Background(), binaryPath,
		// Single-process smoke: not a deployment, so it declares that explicitly (see requireControlPlaneOrExit).
		"-no-control-plane",
		"-mode", "edge",
		"-listen", listen,
		"-policy", strings.Join(policyPaths, ","),
		"-bundle", bundlePath,
		"-schema-dir", filepath.Join(repoRoot, "schemas"),
		"-migration-dir", filepath.Join(moduleRoot, "migrations"),
		"-log-dir", logDir,
		"-lab-mode=false",
		"-connector-secret", connectorAuthValue,
		"-workload-attestation-secret", attestationAuthValue,
		"-workload-attestation-nonce-store", "postgres",
		"-workload-attestation-nonce-postgres-dsn", postgresDSN,
		"-swg-tenant-restriction-operator-config", operatorConfigPath,
		"-swg-runtime-tls-decryption-observed",
		"-swg-mac-ca-trust-observed",
	)
	cmd.Dir = moduleRoot
	cmd.Stdout = io.Discard
	var processErr bytes.Buffer
	cmd.Stderr = &processErr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start cmd/edge process: %v", err)
	}
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()
	defer m1600StopProcess(t, cmd, waitCh)

	client := &http.Client{Timeout: 2 * time.Second}
	health := m1600WaitForHealthz(t, client, baseURL, waitCh, &processErr)
	status := m1600GetJSON(t, client, baseURL+swg.EdgeSWGTLSReadinessStatusPath, connectorAuthValue, waitCh, &processErr)
	m1600AssertReadinessStatus(t, status)

	report := m1600ProcessStatusReport(status, health)
	forbidden := []string{
		"google-workspace.lab.example",
		"microsoft-365-tenant.lab.example",
		"swg_tenant_restriction_operator_config.json",
		connectorAuthValue,
		attestationAuthValue,
		postgresDSN,
	}
	m1600AssertNoForbiddenMaterial(t, "status", status, forbidden)
	m1600AssertNoForbiddenMaterial(t, "report", report, forbidden)

	if path := strings.TrimSpace(os.Getenv(sWGEdgeRuntimeProductionProcessStatusSmokeReportEnv)); path != "" {
		writeSWGM1600JSON(t, path, report)
	}
}

type m1600RawHarnessConfig struct {
	PolicyBundle json.RawMessage   `json:"policy_bundle"`
	Policies     []json.RawMessage `json:"policies"`
}

func m1600WriteHarnessRuntimeInputs(t *testing.T, harnessPath, workDir string) ([]string, string) {
	t.Helper()
	data, err := os.ReadFile(harnessPath)
	if err != nil {
		t.Fatalf("read harness config: %v", err)
	}
	var config m1600RawHarnessConfig
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatalf("decode harness config: %v", err)
	}
	if len(config.PolicyBundle) == 0 || len(config.Policies) == 0 {
		t.Fatalf("harness config missing policy bundle or policies")
	}
	policyPaths := make([]string, 0, len(config.Policies))
	policyIDs := make([]string, 0, len(config.Policies))
	for index, policy := range config.Policies {
		policyPath := filepath.Join(workDir, "policies", "swg_policy_"+string(rune('a'+index))+".json")
		if err := writeSWGM1600RawJSONFile(policyPath, policy); err != nil {
			t.Fatalf("write policy file: %v", err)
		}
		var policyDoc map[string]any
		if err := json.Unmarshal(policy, &policyDoc); err != nil {
			t.Fatalf("decode policy %d: %v", index, err)
		}
		if id, _ := policyDoc["id"].(string); strings.TrimSpace(id) != "" {
			policyIDs = append(policyIDs, id)
		}
		policyPaths = append(policyPaths, policyPath)
	}
	bundlePath := filepath.Join(workDir, "swg_policy_bundle.json")
	bundle := m1600RuntimeBundle(t, config.PolicyBundle, policyIDs, policyPaths)
	if err := writeSWGM1600JSONFile(bundlePath, bundle); err != nil {
		t.Fatalf("write bundle file: %v", err)
	}
	return policyPaths, bundlePath
}

func m1600RuntimeBundle(t *testing.T, raw json.RawMessage, policyIDs, policyPaths []string) map[string]any {
	t.Helper()
	var bundle map[string]any
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatalf("decode policy bundle: %v", err)
	}
	if _, ok := bundle["checksum"]; !ok {
		bundle["checksum"] = "sha256:mock-checksum"
	}
	if _, ok := bundle["signature"]; !ok {
		bundle["signature"] = "mock-signature"
	}
	if _, ok := bundle["signing_key_id"]; !ok {
		bundle["signing_key_id"] = "mock-local-signing-key"
	}
	if _, ok := bundle["target_scope"]; !ok {
		bundle["target_scope"] = map[string]any{
			"target_type":        "local_edge",
			"edge_region_id":     "local",
			"edge_cluster_id":    "local-edge-a",
			"device_group_id":    nil,
			"connector_group_id": nil,
		}
	}
	if _, ok := bundle["policy_ids"]; !ok {
		bundle["policy_ids"] = policyIDs
	}
	if _, ok := bundle["compiled_policy_ref"]; !ok {
		bundle["compiled_policy_ref"] = strings.Join(policyPaths, ",")
	}
	if _, ok := bundle["bundle_type"]; !ok {
		bundle["bundle_type"] = "standard"
	}
	if _, ok := bundle["expires_at"]; !ok {
		bundle["expires_at"] = "2030-01-01T00:00:00Z"
	}
	if _, ok := bundle["created_at"]; !ok {
		bundle["created_at"] = "2026-06-11T00:00:00Z"
	}
	return bundle
}

func writeSWGM1600JSONFile(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	return os.WriteFile(path, body, 0o644)
}

func writeSWGM1600RawJSONFile(path string, raw json.RawMessage) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, raw, "", "  "); err != nil {
		return err
	}
	pretty.WriteByte('\n')
	return os.WriteFile(path, pretty.Bytes(), 0o644)
}

func writeSWGM1600JSON(t *testing.T, path string, value any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create %s dir: %v", path, err)
	}
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("marshal %s: %v", path, err)
	}
	body = append(body, '\n')
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func m1600FreeListenAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve listen address: %v", err)
	}
	defer listener.Close()
	return listener.Addr().String()
}

func m1600StopProcess(t *testing.T, cmd *exec.Cmd, waitCh chan error) {
	t.Helper()
	if cmd.Process != nil {
		_ = cmd.Process.Signal(os.Interrupt)
	}
	select {
	case <-waitCh:
	case <-time.After(3 * time.Second):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		<-waitCh
	}
}

func m1600WaitForHealthz(t *testing.T, client *http.Client, baseURL string, waitCh chan error, processErr *bytes.Buffer) map[string]any {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		select {
		case err := <-waitCh:
			waitCh <- err
			t.Fatalf("cmd/edge exited before /healthz became ready: %v; stderr redacted=%s", err, m1600RedactedLine(processErr.String()))
		default:
		}
		health, err := m1600FetchJSON(client, baseURL+"/healthz", "")
		if err == nil && health["status"] == "ok" {
			return health
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("/healthz did not become ready: %v", lastErr)
	return nil
}

func m1600GetJSON(t *testing.T, client *http.Client, url, connectorAuthValue string, waitCh chan error, processErr *bytes.Buffer) map[string]any {
	t.Helper()
	select {
	case err := <-waitCh:
		waitCh <- err
		t.Fatalf("cmd/edge exited before status readback: %v; stderr redacted=%s", err, m1600RedactedLine(processErr.String()))
	default:
	}
	result, err := m1600FetchJSON(client, url, connectorAuthValue)
	if err != nil {
		t.Fatalf("GET %s failed: %v", swg.EdgeSWGTLSReadinessStatusPath, err)
	}
	return result
}

func m1600FetchJSON(client *http.Client, url, connectorAuthValue string) (map[string]any, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(connectorAuthValue) != "" {
		req.Header.Set(connectorSecretHeader, connectorAuthValue)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &m1600HTTPStatusError{StatusCode: resp.StatusCode}
	}
	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

type m1600HTTPStatusError struct {
	StatusCode int
}

func (err *m1600HTTPStatusError) Error() string {
	return "unexpected HTTP status"
}

func m1600AssertReadinessStatus(t *testing.T, status map[string]any) {
	t.Helper()
	for key, want := range map[string]any{
		"schema_version":                           "swg_tls_readiness_status.v1",
		"status":                                   "readiness_visible_runtime_observed",
		"tenant_id":                                "tenant_swg_lab",
		"policy_bundle_id":                         "pb_swg_preflight_m1583",
		"policy_bundle_version":                    "swg-saas-tenant-preflight",
		"readback_path":                            swg.EdgeSWGTLSReadinessStatusPath,
		"edge_http_egress_handler_path":            edgeplane.EdgeSWGHTTPEgressPath,
		"default_tls_decryption_required":          true,
		"default_tls_decryption_observed":          true,
		"default_tls_decryption_status":            "required_observed",
		"tenant_header_rewrite_dependency_count":   float64(2),
		"per_destination_tls_bypass_required":      true,
		"tls_bypass_rule_count":                    float64(2),
		"mac_ca_trust_required":                    true,
		"mac_ca_trust_observed":                    true,
		"mac_ca_trust_mutated":                     false,
		"mac_ca_trust_status":                      "required_observed",
		"inspection_metadata_readback_observed":    false,
		"inspection_event_count":                   float64(0),
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
	m1600AssertDependency(t, deps, swghttprewrite.GoogleWorkspaceTenantRestrictionHeader, "operator_config_ref:google_workspace_allowed_domains")
	m1600AssertDependency(t, deps, swghttprewrite.Microsoft365TenantRestrictionHeader, "operator_config_ref:microsoft_365_allowed_tenants")
	bypassRules, ok := status["tls_bypass_rules"].([]any)
	if !ok || len(bypassRules) != 2 ||
		!m1600RulePresent(bypassRules, "swg_tls_bypass_banking_category") ||
		!m1600RulePresent(bypassRules, "swg_tls_bypass_pinned_google_exact") {
		t.Fatalf("tls bypass rules = %#v", status["tls_bypass_rules"])
	}
	metadata, ok := status["inspection_metadata"].(map[string]any)
	if !ok {
		t.Fatalf("inspection metadata = %#v", status["inspection_metadata"])
	}
	for key, want := range map[string]any{
		"google_workspace_rewrite_outcome":               "not_observed",
		"microsoft_365_rewrite_outcome":                  "not_observed",
		"tls_bypass_suppression_outcome":                 "not_observed",
		"header_value_material_in_inspection_event":      false,
		"header_value_material_in_api_readback":          false,
		"operator_config_value_material_in_inspection":   false,
		"operator_config_value_material_in_api_readback": false,
	} {
		if got := metadata[key]; got != want {
			t.Fatalf("inspection metadata[%s] = %#v, want %#v; metadata=%#v", key, got, want, metadata)
		}
	}
	if !m1600StringArrayEquals(metadata["header_names_visible"], []string{}) ||
		!m1600StringArrayEquals(metadata["operator_config_refs_visible"], []string{}) {
		t.Fatalf("inspection metadata visible material = %#v", metadata)
	}
}

func m1600AssertDependency(t *testing.T, deps []any, headerName, operatorConfigRef string) {
	t.Helper()
	for _, raw := range deps {
		dep, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if dep["header_name"] != headerName {
			continue
		}
		for key, want := range map[string]any{
			"operator_config_ref":               operatorConfigRef,
			"header_value_kind":                 "configured_allowed_domains",
			"operator_config_ref_resolved":      true,
			"rewrite_dependency":                "default_tls_decryption_required",
			"header_value_material_in_status":   false,
			"header_value_material_in_decision": false,
		} {
			if headerName == swghttprewrite.Microsoft365TenantRestrictionHeader && key == "header_value_kind" {
				want = "configured_allowed_tenant_ids"
			}
			if got := dep[key]; got != want {
				t.Fatalf("dependency %s[%s] = %#v, want %#v; dep=%#v", headerName, key, got, want, dep)
			}
		}
		return
	}
	t.Fatalf("dependency for header %s absent: %#v", headerName, deps)
}

func m1600RulePresent(rules []any, id string) bool {
	for _, raw := range rules {
		rule, ok := raw.(map[string]any)
		if ok && rule["rule_id"] == id {
			return true
		}
	}
	return false
}

func m1600StringArrayEquals(raw any, want []string) bool {
	values, ok := raw.([]any)
	if !ok || len(values) != len(want) {
		return false
	}
	for index, expected := range want {
		if values[index] != expected {
			return false
		}
	}
	return true
}

func m1600ProcessStatusReport(status, health map[string]any) map[string]any {
	deps, _ := status["tenant_header_rewrite_dependencies"].([]any)
	headerNames := []string{}
	refs := []string{}
	for _, raw := range deps {
		dep, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if headerName, ok := dep["header_name"].(string); ok && headerName != "" {
			headerNames = append(headerNames, headerName)
		}
		if ref, ok := dep["operator_config_ref"].(string); ok && ref != "" {
			refs = append(refs, ref)
		}
	}
	return map[string]any{
		"schema_version":    "swg_edge_runtime_production_process_status_smoke.v1",
		"status":            "passed",
		"depth_locked_unit": "swg_edge_runtime_production_process_status_smoke_product_unit",
		"source_m1599_handler_product_path_smoke_gate": "passed",
		"egress_forwarding_coverage_source":            "m1599_handler_product_path_smoke",
		"cmd_edge_process_startup_status_smoke_gate":   "passed",
		"cmd_edge_process_started":                     true,
		"cmd_edge_process_output_included":             false,
		"raw_command_output_included":                  false,
		"raw_process_output_included":                  false,
		"process_id_included":                          false,
		"process_listen_address_material_in_report":    false,
		"runtime_auth_material_in_report":              false,
		"postgres_dsn_material_in_report":              false,
		"startup_flag_names_exercised":                 []string{"-swg-tenant-restriction-operator-config", "-swg-runtime-tls-decryption-observed", "-swg-mac-ca-trust-observed"},
		"production_mode_lab_mode":                     false,
		"healthz_readback_observed":                    health["status"] == "ok",
		"healthz_status":                               health["status"],
		"healthz_status_code":                          http.StatusOK,
		"tls_readiness_status_api_path":                swg.EdgeSWGTLSReadinessStatusPath,
		"tls_readiness_status_api_readback_observed":   true,
		"tls_readiness_status_code":                    http.StatusOK,
		"tls_readiness_status_schema_version":          status["schema_version"],
		"tls_readiness_status_visibility":              status["status"],
		"edge_http_egress_handler_path":                status["edge_http_egress_handler_path"],
		"default_tls_decryption_required":              status["default_tls_decryption_required"],
		"default_tls_decryption_observed":              status["default_tls_decryption_observed"],
		"default_tls_decryption_status":                status["default_tls_decryption_status"],
		"runtime_tls_decryption_observed_flag_input":   true,
		"mac_ca_trust_required":                        status["mac_ca_trust_required"],
		"mac_ca_trust_observed":                        status["mac_ca_trust_observed"],
		"mac_ca_trust_observed_flag_input":             true,
		"mac_ca_trust_mutated":                         status["mac_ca_trust_mutated"],
		"mac_ca_trust_status":                          status["mac_ca_trust_status"],
		"operator_managed_tenant_header_config_loaded": true,
		"tenant_header_rewrite_dependency_count":       status["tenant_header_rewrite_dependency_count"],
		"operator_config_refs_visible":                 refs,
		"header_names_visible":                         headerNames,
		"per_destination_tls_bypass_required":          status["per_destination_tls_bypass_required"],
		"tls_bypass_rule_count":                        status["tls_bypass_rule_count"],
		"inspection_metadata_readback_observed":        status["inspection_metadata_readback_observed"],
		"inspection_event_count":                       status["inspection_event_count"],
		"header_value_material_in_status":              status["header_value_material_in_status"],
		"operator_config_value_material_in_status":     status["operator_config_value_material_in_status"],
		"header_value_material_in_report":              false,
		"operator_config_value_material_in_report":     false,
		"operator_config_path_material_in_report":      false,
		"swg_runtime_traffic_observed":                 status["swg_runtime_traffic_observed"],
		"real_tls_interception_runtime_executed":       status["real_tls_interception_runtime_executed"],
		"tls_runtime_decryption_observed":              false,
		"header_injection_runtime_observed":            false,
		"mac_ca_trust_mutation_started":                status["mac_ca_trust_mutation_started"],
		"network_extension_runtime_used":               status["network_extension_runtime_used"],
		"human_boundary_created":                       false,
		"gui_buildout_started":                         false,
		"presentation_only_ui_proxy_topology_started":  false,
		"p4_packaging_mdm_signing_install_started":     status["p4_packaging_mdm_signing_install_started"],
		"shipping_product_claimed":                     status["shipping_product_claimed"],
		"production_scale_claimed":                     status["production_scale_claimed"],
		"mvp_pilot_success_claimed":                    status["mvp_pilot_success_claimed"],
		"windows_work_started":                         status["windows_work_started"],
		"productization_claims_made":                   status["productization_claims_made"],
		"new_product_claims_made":                      status["new_product_claims_made"],
		"secret_leak_gate":                             status["secret_leak_gate"],
		"no_secret_attestation":                        status["no_secret_attestation"],
	}
}

func m1600AssertNoForbiddenMaterial(t *testing.T, label string, value any, forbidden []string) {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal %s for forbidden-material scan: %v", label, err)
	}
	serialized := string(body)
	for _, material := range forbidden {
		material = strings.TrimSpace(material)
		if material == "" {
			continue
		}
		if strings.Contains(serialized, material) {
			t.Fatalf("%s contains forbidden operator/header/auth material", label)
		}
	}
}

func m1600RedactedLine(text string) string {
	line := strings.TrimSpace(text)
	if line == "" {
		return ""
	}
	if index := strings.IndexByte(line, '\n'); index >= 0 {
		line = line[:index]
	}
	if len(line) > 600 {
		line = line[:600] + "..."
	}
	for _, fragment := range []string{"postgres://", "password=", "localpass"} {
		if strings.Contains(strings.ToLower(line), fragment) {
			return "redacted"
		}
	}
	return line
}
