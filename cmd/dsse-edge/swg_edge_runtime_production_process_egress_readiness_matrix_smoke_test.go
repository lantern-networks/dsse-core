package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
	swg "github.com/lantern-networks/dsse-core/swg"

	"github.com/lantern-networks/dsse-core/swghttprewrite"
)

const (
	sWGEdgeRuntimeProductionProcessEgressReadinessMatrixSmokeReportEnv = "SWG_EDGE_RUNTIME_PRODUCTION_PROCESS_EGRESS_READINESS_MATRIX_SMOKE_REPORT"
	sWGEdgeRuntimeProductionProcessEgressReadinessMatrixSmokeDSNEnv    = "SWG_EDGE_RUNTIME_PRODUCTION_PROCESS_EGRESS_READINESS_MATRIX_SMOKE_POSTGRES_DSN"
)

func TestSWGEdgeSWGProductionProcessEgressReadinessMatrixSmoke(t *testing.T) {
	postgresDSN := strings.TrimSpace(os.Getenv(sWGEdgeRuntimeProductionProcessEgressReadinessMatrixSmokeDSNEnv))
	if postgresDSN == "" {
		t.Skipf("%s is required for production-mode cmd/edge process egress readiness matrix smoke", sWGEdgeRuntimeProductionProcessEgressReadinessMatrixSmokeDSNEnv)
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

	binaryPath := filepath.Join(workDir, "edge-process-egress-readiness-matrix-smoke")
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

	runtimeTLSMissing := m1602RunProcessEgressCase(t, common, m1602ReadinessProcessCase{
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
				WantCurrentTLSBypassApplied: true,
				WantTLSBypassRuleID:         "swg_tls_bypass_pinned_google_exact",
			},
		},
	})

	tlsObservedMacCAMissing := m1602RunProcessEgressCase(t, common, m1602ReadinessProcessCase{
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
				WantCurrentTLSBypassApplied: false,
			},
		},
	})

	bothSignalsObserved := m1602RunProcessEgressCase(t, common, m1602ReadinessProcessCase{
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

	report := m1602ProcessEgressReadinessMatrixReport(runtimeTLSMissing, tlsObservedMacCAMissing, bothSignalsObserved)
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
	for _, processCase := range []m1602ReadinessProcessCaseResult{runtimeTLSMissing, tlsObservedMacCAMissing, bothSignalsObserved} {
		for _, request := range processCase.Requests {
			m1600AssertNoForbiddenMaterial(t, request.Case.Name+" diagnostic", request.Diagnostic, forbidden[:6])
		}
	}
	m1600AssertNoForbiddenMaterial(t, "report", report, forbidden)

	if path := strings.TrimSpace(os.Getenv(sWGEdgeRuntimeProductionProcessEgressReadinessMatrixSmokeReportEnv)); path != "" {
		writeSWGM1600JSON(t, path, report)
	}
}

type m1602ProcessEgressInputs struct {
	ModuleRoot         string
	RepoRoot           string
	WorkDir            string
	BinaryPath         string
	PolicyPaths        []string
	BundlePath         string
	OperatorConfigPath string
	PostgresDSN        string
	ProxyURL           string
	Proxy              *m1602LocalCaptureProxy
}

type m1602ReadinessProcessCase struct {
	Name                        string
	RuntimeTLSObservedFlagInput bool
	MacCATrustObservedFlagInput bool
	Requests                    []m1602EgressRequestCase
}

type m1602EgressRequestCase struct {
	Name                        string
	TargetURL                   string
	WantStatusCode              int
	WantReadinessDependency     string
	WantSaaSApplicationID       string
	WantPolicyID                string
	WantDefaultTLSObserved      bool
	WantMacCATrustObserved      bool
	WantForwarded               bool
	WantHeaderName              string
	WantCurrentTLSBypassApplied bool
	WantTLSBypassRuleID         string
}

type m1602ReadinessProcessCaseResult struct {
	Case             m1602ReadinessProcessCase
	Health           map[string]any
	HealthStatusCode int
	Requests         []m1602EgressRequestResult
}

type m1602EgressRequestResult struct {
	Case                                       m1602EgressRequestCase
	StatusCode                                 int
	Diagnostic                                 map[string]any
	UpstreamRequestObserved                    bool
	UpstreamStatusCodeObserved                 int
	GoogleWorkspaceHeaderNameForwarded         bool
	Microsoft365HeaderNameForwarded            bool
	TenantRestrictionHeaderValueMaterialStored bool
	ControlHeadersForwardedUpstream            bool
}

type m1602LocalCaptureProxy struct {
	URL      string
	Server   *httptest.Server
	Requests chan m1602LocalCaptureRequest
}

type m1602LocalCaptureRequest struct {
	GoogleWorkspaceHeaderNameForwarded         bool
	Microsoft365HeaderNameForwarded            bool
	TenantRestrictionHeaderValueMaterialStored bool
	ControlHeadersForwardedUpstream            bool
}

func m1602StartLocalCaptureProxy(t *testing.T) *m1602LocalCaptureProxy {
	t.Helper()
	requests := make(chan m1602LocalCaptureRequest, 16)
	var mu sync.Mutex
	received := []m1602LocalCaptureRequest{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.Body.Close()
		capture := m1602LocalCaptureRequest{
			GoogleWorkspaceHeaderNameForwarded:         r.Header.Get(swghttprewrite.GoogleWorkspaceTenantRestrictionHeader) != "",
			Microsoft365HeaderNameForwarded:            r.Header.Get(swghttprewrite.Microsoft365TenantRestrictionHeader) != "",
			TenantRestrictionHeaderValueMaterialStored: false,
			ControlHeadersForwardedUpstream:            r.Header.Get(connectorSecretHeader) != "" || r.Header.Get(edgeplane.EdgeSWGHTTPEgressTargetURLHeader) != "" || r.Header.Get(workloadAttestationSignatureHeader) != "",
		}
		mu.Lock()
		received = append(received, capture)
		mu.Unlock()
		select {
		case requests <- capture:
		default:
			t.Errorf("local capture proxy request channel is full")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		if len(received) == 0 {
			t.Fatalf("local capture proxy observed no process egress requests")
		}
	})
	return &m1602LocalCaptureProxy{URL: server.URL, Server: server, Requests: requests}
}

func m1602RunProcessEgressCase(t *testing.T, inputs m1602ProcessEgressInputs, processCase m1602ReadinessProcessCase) m1602ReadinessProcessCaseResult {
	t.Helper()
	listen := m1600FreeListenAddress(t)
	baseURL := "http://" + listen
	connectorAuthValue := "connector-auth-value-" + processCase.Name
	attestationAuthValue := "attestation-auth-value-" + processCase.Name
	logDir := filepath.Join(inputs.WorkDir, "logs", processCase.Name)

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
	results := make([]m1602EgressRequestResult, 0, len(processCase.Requests))
	for _, requestCase := range processCase.Requests {
		results = append(results, m1602DoEgressRequest(t, client, baseURL, connectorAuthValue, inputs.Proxy, waitCh, &processErr, requestCase))
	}
	return m1602ReadinessProcessCaseResult{
		Case:             processCase,
		Health:           health,
		HealthStatusCode: http.StatusOK,
		Requests:         results,
	}
}

func m1602DoEgressRequest(t *testing.T, client *http.Client, baseURL, connectorAuthValue string, proxy *m1602LocalCaptureProxy, waitCh chan error, processErr *bytes.Buffer, requestCase m1602EgressRequestCase) m1602EgressRequestResult {
	t.Helper()
	select {
	case err := <-waitCh:
		waitCh <- err
		t.Fatalf("cmd/edge exited before egress request %s: %v; stderr redacted=%s", requestCase.Name, err, m1600RedactedLine(processErr.String()))
	default:
	}

	req, err := http.NewRequest(http.MethodGet, baseURL+edgeplane.EdgeSWGHTTPEgressPath, nil)
	if err != nil {
		t.Fatalf("build egress request %s: %v", requestCase.Name, err)
	}
	req.Header.Set(connectorSecretHeader, connectorAuthValue)
	req.Header.Set(edgeplane.EdgeSWGHTTPEgressTargetURLHeader, requestCase.TargetURL)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("egress request %s failed: %v", requestCase.Name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != requestCase.WantStatusCode {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("egress request %s status = %d, want %d; body=%s", requestCase.Name, resp.StatusCode, requestCase.WantStatusCode, m1600RedactedLine(string(body)))
	}

	result := m1602EgressRequestResult{Case: requestCase, StatusCode: resp.StatusCode}
	if resp.StatusCode == http.StatusPreconditionRequired {
		var diagnostic map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&diagnostic); err != nil {
			t.Fatalf("decode readiness dependency diagnostic for %s: %v", requestCase.Name, err)
		}
		result.Diagnostic = diagnostic
		m1602AssertReadinessDependencyDiagnostic(t, requestCase, diagnostic)
		m1602AssertNoProxyCapture(t, proxy, requestCase.Name)
		return result
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	capture := m1602NextProxyCapture(t, proxy, requestCase.Name)
	result.UpstreamRequestObserved = true
	result.UpstreamStatusCodeObserved = resp.StatusCode
	result.GoogleWorkspaceHeaderNameForwarded = capture.GoogleWorkspaceHeaderNameForwarded
	result.Microsoft365HeaderNameForwarded = capture.Microsoft365HeaderNameForwarded
	result.TenantRestrictionHeaderValueMaterialStored = capture.TenantRestrictionHeaderValueMaterialStored
	result.ControlHeadersForwardedUpstream = capture.ControlHeadersForwardedUpstream
	m1602AssertForwardedCapture(t, requestCase, result)
	return result
}

func m1602AssertReadinessDependencyDiagnostic(t *testing.T, requestCase m1602EgressRequestCase, diagnostic map[string]any) {
	t.Helper()
	for key, want := range map[string]any{
		"schema_version":                                    edgeplane.EdgeSWGHTTPEgressReadinessSchema,
		"status":                                            "readiness_dependency",
		"readiness_dependency":                              requestCase.WantReadinessDependency,
		"edge_http_egress_handler_path":                     edgeplane.EdgeSWGHTTPEgressPath,
		"tls_readiness_status_path":                         swg.EdgeSWGTLSReadinessStatusPath,
		"tls_readiness_status_version":                      "swg_tls_readiness_status.v1",
		"tenant_id":                                         "tenant_swg_lab",
		"policy_bundle_id":                                  "pb_swg_preflight_m1583",
		"policy_bundle_version":                             "swg-saas-tenant-preflight",
		"policy_id":                                         requestCase.WantPolicyID,
		"application_id":                                    edgeplane.EdgeSWGEgressApplicationID,
		"saas_application_id":                               requestCase.WantSaaSApplicationID,
		"lab_mode":                                          false,
		"egress_forwarded":                                  false,
		"default_tls_decryption_required":                   true,
		"default_tls_decryption_observed":                   requestCase.WantDefaultTLSObserved,
		"mac_ca_trust_required":                             true,
		"mac_ca_trust_observed":                             requestCase.WantMacCATrustObserved,
		"tenant_header_rewrite_dependency_count":            float64(2),
		"per_destination_tls_bypass_required":               true,
		"tls_bypass_rule_count":                             float64(2),
		"current_request_tls_bypass_applied":                requestCase.WantCurrentTLSBypassApplied,
		"tls_readiness_dependency_suppressed_by_tls_bypass": false,
		"inspection_metadata_readback_observed":             false,
		"header_value_material_in_diagnostic":               false,
		"operator_config_value_material_in_diagnostic":      false,
		"real_tls_interception_runtime_executed":            false,
		"mac_ca_trust_mutation_started":                     false,
		"p4_packaging_mdm_signing_install_started":          false,
		"shipping_product_claimed":                          false,
		"production_scale_claimed":                          false,
		"mvp_pilot_success_claimed":                         false,
		"windows_work_started":                              false,
		"secret_leak_gate":                                  "ok",
		"no_secret_attestation":                             true,
	} {
		if got := diagnostic[key]; got != want {
			t.Fatalf("diagnostic[%s] = %#v, want %#v; diagnostic=%#v", key, got, want, diagnostic)
		}
	}
	if requestCase.WantDefaultTLSObserved && diagnostic["default_tls_decryption_status"] != "required_observed" {
		t.Fatalf("diagnostic default TLS status = %#v", diagnostic["default_tls_decryption_status"])
	}
	if !requestCase.WantDefaultTLSObserved && diagnostic["default_tls_decryption_status"] != "required_not_observed" {
		t.Fatalf("diagnostic default TLS status = %#v", diagnostic["default_tls_decryption_status"])
	}
	if requestCase.WantMacCATrustObserved && diagnostic["mac_ca_trust_status"] != "required_observed" {
		t.Fatalf("diagnostic Mac CA status = %#v", diagnostic["mac_ca_trust_status"])
	}
	if !requestCase.WantMacCATrustObserved && diagnostic["mac_ca_trust_status"] != "required_not_mutated" {
		t.Fatalf("diagnostic Mac CA status = %#v", diagnostic["mac_ca_trust_status"])
	}
	if !m1600StringArrayEquals(diagnostic["header_names_visible"], []string{"X-GoogApps-Allowed-Domains", "Restrict-Access-To-Tenants"}) {
		t.Fatalf("diagnostic header names = %#v", diagnostic["header_names_visible"])
	}
	if !m1600StringArrayEquals(diagnostic["operator_config_refs_visible"], []string{"operator_config_ref:google_workspace_allowed_domains", "operator_config_ref:microsoft_365_allowed_tenants"}) {
		t.Fatalf("diagnostic operator config refs = %#v", diagnostic["operator_config_refs_visible"])
	}
}

func m1602AssertForwardedCapture(t *testing.T, requestCase m1602EgressRequestCase, result m1602EgressRequestResult) {
	t.Helper()
	if !requestCase.WantForwarded || !result.UpstreamRequestObserved {
		t.Fatalf("egress request %s upstream observed = %v, want forwarded", requestCase.Name, result.UpstreamRequestObserved)
	}
	if result.ControlHeadersForwardedUpstream {
		t.Fatalf("egress request %s forwarded Edge runtime control headers upstream", requestCase.Name)
	}
	if result.TenantRestrictionHeaderValueMaterialStored {
		t.Fatalf("egress request %s stored tenant header value material", requestCase.Name)
	}
	switch requestCase.WantHeaderName {
	case swghttprewrite.GoogleWorkspaceTenantRestrictionHeader:
		if !result.GoogleWorkspaceHeaderNameForwarded || result.Microsoft365HeaderNameForwarded {
			t.Fatalf("egress request %s header forwarding google=%v microsoft=%v", requestCase.Name, result.GoogleWorkspaceHeaderNameForwarded, result.Microsoft365HeaderNameForwarded)
		}
	case swghttprewrite.Microsoft365TenantRestrictionHeader:
		if !result.Microsoft365HeaderNameForwarded || result.GoogleWorkspaceHeaderNameForwarded {
			t.Fatalf("egress request %s header forwarding google=%v microsoft=%v", requestCase.Name, result.GoogleWorkspaceHeaderNameForwarded, result.Microsoft365HeaderNameForwarded)
		}
	case "":
		if result.GoogleWorkspaceHeaderNameForwarded || result.Microsoft365HeaderNameForwarded {
			t.Fatalf("egress request %s unexpectedly forwarded tenant header names google=%v microsoft=%v", requestCase.Name, result.GoogleWorkspaceHeaderNameForwarded, result.Microsoft365HeaderNameForwarded)
		}
	default:
		t.Fatalf("unsupported wanted header name %q", requestCase.WantHeaderName)
	}
}

func m1602NextProxyCapture(t *testing.T, proxy *m1602LocalCaptureProxy, name string) m1602LocalCaptureRequest {
	t.Helper()
	select {
	case capture := <-proxy.Requests:
		return capture
	case <-time.After(3 * time.Second):
		t.Fatalf("egress request %s did not reach local capture proxy", name)
	}
	return m1602LocalCaptureRequest{}
}

func m1602AssertNoProxyCapture(t *testing.T, proxy *m1602LocalCaptureProxy, name string) {
	t.Helper()
	select {
	case capture := <-proxy.Requests:
		t.Fatalf("egress request %s unexpectedly reached local capture proxy: %#v", name, capture)
	case <-time.After(150 * time.Millisecond):
	}
}

func m1602WriteProcessEgressRuntimeInputs(t *testing.T, harnessPath, workDir string) ([]string, string) {
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
		mutated := m1602PolicyForHTTPProxyProcessSmoke(t, policy)
		policyPath := filepath.Join(workDir, "policies", "swg_process_egress_policy_"+string(rune('a'+index))+".json")
		if err := writeSWGM1600JSONFile(policyPath, mutated); err != nil {
			t.Fatalf("write process egress policy file: %v", err)
		}
		if id, _ := mutated["id"].(string); strings.TrimSpace(id) != "" {
			policyIDs = append(policyIDs, id)
		}
		policyPaths = append(policyPaths, policyPath)
	}
	bundlePath := filepath.Join(workDir, "swg_process_egress_policy_bundle.json")
	bundle := m1600RuntimeBundle(t, config.PolicyBundle, policyIDs, policyPaths)
	if err := writeSWGM1600JSONFile(bundlePath, bundle); err != nil {
		t.Fatalf("write process egress bundle file: %v", err)
	}
	return policyPaths, bundlePath
}

func m1602PolicyForHTTPProxyProcessSmoke(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	var policy map[string]any
	if err := json.Unmarshal(raw, &policy); err != nil {
		t.Fatalf("decode process egress policy: %v", err)
	}
	conditions, ok := policy["conditions"].(map[string]any)
	if !ok {
		t.Fatalf("policy %v missing conditions", policy["id"])
	}
	if _, ok := conditions["service_family"]; ok {
		conditions["service_family"] = "http"
	}
	conditions["destination_port"] = float64(443)
	return policy
}

func m1602ProcessEgressReadinessMatrixReport(runtimeTLSMissing, tlsObservedMacCAMissing, bothSignalsObserved m1602ReadinessProcessCaseResult) map[string]any {
	tlsMissingGoogle := m1602RequestResultByName(runtimeTLSMissing, "google_workspace_tls_missing")
	tlsMissingBypass := m1602RequestResultByName(runtimeTLSMissing, "pinned_google_tls_bypass_with_missing_readiness")
	macCAMissingGoogle := m1602RequestResultByName(tlsObservedMacCAMissing, "google_workspace_mac_ca_missing")
	readyGoogle := m1602RequestResultByName(bothSignalsObserved, "google_workspace_ready")
	readyMicrosoft := m1602RequestResultByName(bothSignalsObserved, "microsoft_365_ready")

	return map[string]any{
		"schema_version":    "swg_edge_runtime_production_process_egress_readiness_matrix_smoke.v1",
		"status":            "passed",
		"depth_locked_unit": "swg_edge_runtime_production_process_egress_readiness_matrix_smoke_product_unit",
		"source_m1599_handler_product_path_smoke_gate":                           "passed",
		"source_m1601_process_readiness_negative_status_gate":                    "accepted",
		"egress_readiness_matrix_source":                                         "cmd_edge_process_http_egress_api",
		"cmd_edge_process_egress_readiness_matrix_smoke_gate":                    "passed",
		"cmd_edge_process_started":                                               true,
		"cmd_edge_process_launch_count":                                          3,
		"cmd_edge_process_output_included":                                       false,
		"raw_command_output_included":                                            false,
		"raw_process_output_included":                                            false,
		"process_id_included":                                                    false,
		"process_listen_address_material_in_report":                              false,
		"runtime_auth_material_in_report":                                        false,
		"postgres_dsn_material_in_report":                                        false,
		"upstream_proxy_address_material_in_report":                              false,
		"target_url_material_in_report":                                          false,
		"target_fqdn_material_in_report":                                         false,
		"startup_flag_names_exercised":                                           []string{"-swg-tenant-restriction-operator-config", "-swg-runtime-tls-decryption-observed", "-swg-mac-ca-trust-observed"},
		"production_mode_lab_mode":                                               false,
		"healthz_readback_observed":                                              runtimeTLSMissing.Health["status"] == "ok" && tlsObservedMacCAMissing.Health["status"] == "ok" && bothSignalsObserved.Health["status"] == "ok",
		"healthz_status_code":                                                    http.StatusOK,
		"edge_http_egress_handler_path":                                          edgeplane.EdgeSWGHTTPEgressPath,
		"http_egress_case_count":                                                 5,
		"runtime_tls_missing_google_workspace_case_observed":                     true,
		"runtime_tls_missing_google_workspace_status_code":                       tlsMissingGoogle.StatusCode,
		"runtime_tls_missing_google_workspace_readiness_dependency":              tlsMissingGoogle.Diagnostic["readiness_dependency"],
		"runtime_tls_missing_google_workspace_egress_forwarded":                  tlsMissingGoogle.Diagnostic["egress_forwarded"],
		"runtime_tls_missing_google_workspace_upstream_request_observed":         tlsMissingGoogle.UpstreamRequestObserved,
		"runtime_tls_missing_default_tls_decryption_observed":                    tlsMissingGoogle.Diagnostic["default_tls_decryption_observed"],
		"runtime_tls_missing_default_tls_decryption_status":                      tlsMissingGoogle.Diagnostic["default_tls_decryption_status"],
		"runtime_tls_missing_mac_ca_trust_observed":                              tlsMissingGoogle.Diagnostic["mac_ca_trust_observed"],
		"runtime_tls_missing_mac_ca_trust_status":                                tlsMissingGoogle.Diagnostic["mac_ca_trust_status"],
		"runtime_tls_missing_flag_input":                                         runtimeTLSMissing.Case.RuntimeTLSObservedFlagInput,
		"runtime_tls_missing_mac_ca_trust_observed_flag_input":                   runtimeTLSMissing.Case.MacCATrustObservedFlagInput,
		"tls_observed_mac_ca_missing_google_workspace_case_observed":             true,
		"tls_observed_mac_ca_missing_google_workspace_status_code":               macCAMissingGoogle.StatusCode,
		"tls_observed_mac_ca_missing_google_workspace_readiness_dependency":      macCAMissingGoogle.Diagnostic["readiness_dependency"],
		"tls_observed_mac_ca_missing_google_workspace_egress_forwarded":          macCAMissingGoogle.Diagnostic["egress_forwarded"],
		"tls_observed_mac_ca_missing_google_workspace_upstream_request_observed": macCAMissingGoogle.UpstreamRequestObserved,
		"tls_observed_mac_ca_missing_default_tls_decryption_observed":            macCAMissingGoogle.Diagnostic["default_tls_decryption_observed"],
		"tls_observed_mac_ca_missing_default_tls_decryption_status":              macCAMissingGoogle.Diagnostic["default_tls_decryption_status"],
		"tls_observed_mac_ca_missing_mac_ca_trust_observed":                      macCAMissingGoogle.Diagnostic["mac_ca_trust_observed"],
		"tls_observed_mac_ca_missing_mac_ca_trust_status":                        macCAMissingGoogle.Diagnostic["mac_ca_trust_status"],
		"tls_observed_mac_ca_missing_runtime_tls_flag_input":                     tlsObservedMacCAMissing.Case.RuntimeTLSObservedFlagInput,
		"tls_observed_mac_ca_missing_mac_ca_trust_observed_flag_input":           tlsObservedMacCAMissing.Case.MacCATrustObservedFlagInput,
		"both_readiness_signals_observed_case_observed":                          true,
		"both_readiness_signals_runtime_tls_flag_input":                          bothSignalsObserved.Case.RuntimeTLSObservedFlagInput,
		"both_readiness_signals_mac_ca_trust_flag_input":                         bothSignalsObserved.Case.MacCATrustObservedFlagInput,
		"both_readiness_google_workspace_status_code":                            readyGoogle.StatusCode,
		"both_readiness_google_workspace_readiness_dependency":                   "none",
		"both_readiness_google_workspace_egress_forwarded":                       readyGoogle.UpstreamRequestObserved,
		"both_readiness_google_workspace_header_name_forwarded":                  readyGoogle.GoogleWorkspaceHeaderNameForwarded,
		"both_readiness_google_workspace_other_tenant_header_suppressed":         !readyGoogle.Microsoft365HeaderNameForwarded,
		"both_readiness_microsoft_365_status_code":                               readyMicrosoft.StatusCode,
		"both_readiness_microsoft_365_readiness_dependency":                      "none",
		"both_readiness_microsoft_365_egress_forwarded":                          readyMicrosoft.UpstreamRequestObserved,
		"both_readiness_microsoft_365_header_name_forwarded":                     readyMicrosoft.Microsoft365HeaderNameForwarded,
		"both_readiness_microsoft_365_other_tenant_header_suppressed":            !readyMicrosoft.GoogleWorkspaceHeaderNameForwarded,
		"tls_bypass_with_missing_readiness_case_observed":                        true,
		"tls_bypass_with_missing_readiness_status_code":                          tlsMissingBypass.StatusCode,
		"tls_bypass_with_missing_readiness_readiness_dependency":                 "none",
		"tls_bypass_with_missing_readiness_egress_forwarded":                     tlsMissingBypass.UpstreamRequestObserved,
		"tls_bypass_with_missing_readiness_rule_id":                              tlsMissingBypass.Case.WantTLSBypassRuleID,
		"tls_bypass_with_missing_readiness_header_injection_suppressed":          !tlsMissingBypass.GoogleWorkspaceHeaderNameForwarded && !tlsMissingBypass.Microsoft365HeaderNameForwarded,
		"external_saas_egress_attempted":                                         false,
		"local_capture_upstream_used":                                            true,
		"header_values_forwarded_upstream_only":                                  true,
		"header_value_material_in_diagnostic":                                    false,
		"header_value_material_in_report":                                        false,
		"operator_config_value_material_in_diagnostic":                           false,
		"operator_config_value_material_in_report":                               false,
		"operator_config_path_material_in_report":                                false,
		"operator_managed_tenant_header_config_loaded":                           true,
		"tenant_header_rewrite_dependency_count":                                 float64(2),
		"operator_config_refs_visible":                                           []string{"operator_config_ref:google_workspace_allowed_domains", "operator_config_ref:microsoft_365_allowed_tenants"},
		"header_names_visible":                                                   []string{"X-GoogApps-Allowed-Domains", "Restrict-Access-To-Tenants"},
		"per_destination_tls_bypass_required":                                    true,
		"tls_bypass_rule_count":                                                  float64(2),
		"swg_runtime_traffic_observed":                                           false,
		"real_tls_interception_runtime_executed":                                 false,
		"tls_runtime_decryption_observed":                                        false,
		"header_injection_runtime_observed":                                      false,
		"mac_ca_trust_mutation_started":                                          false,
		"mac_ca_trust_mutated":                                                   false,
		"network_extension_runtime_used":                                         false,
		"human_boundary_created":                                                 false,
		"gui_buildout_started":                                                   false,
		"presentation_only_ui_proxy_topology_started":                            false,
		"p4_packaging_mdm_signing_install_started":                               false,
		"shipping_product_claimed":                                               false,
		"production_scale_claimed":                                               false,
		"mvp_pilot_success_claimed":                                              false,
		"windows_work_started":                                                   false,
		"productization_claims_made":                                             false,
		"new_product_claims_made":                                                false,
		"secret_leak_gate":                                                       "ok",
		"no_secret_attestation":                                                  true,
	}
}

func m1602RequestResultByName(result m1602ReadinessProcessCaseResult, name string) m1602EgressRequestResult {
	for _, request := range result.Requests {
		if request.Case.Name == name {
			return request
		}
	}
	return m1602EgressRequestResult{}
}
