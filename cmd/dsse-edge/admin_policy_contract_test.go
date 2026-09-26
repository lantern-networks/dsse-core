package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/policy"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/steering"
)

func TestAdminPolicyOpenAPIContract(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "openapi", "admin_api.yaml"))
	if err != nil {
		t.Fatalf("read admin OpenAPI contract: %v", err)
	}
	contract := string(data)
	for _, want := range []string{
		"    Policy:",
		"    PolicyList:",
		"  /admin/policies:",
		"  /admin/policies/{policy_id}:",
		"admin.policy.read",
		"admin.policy.write",
		`$ref: "#/components/schemas/PolicyList"`,
		`$ref: "#/components/schemas/Policy"`,
	} {
		if !strings.Contains(contract, want) {
			t.Fatalf("admin OpenAPI contract missing %q", want)
		}
	}
}

func TestAdminPolicyAPIListsSeededPolicies(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Writer:    writer,
		Registry:  connector.NewRegistry(),
		AdminAuth: newAdminAuthStore(),
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/policies?limit=10", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var result policy.ListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode policy list: %v", err)
	}
	if result.Count != 1 || result.Limit != 10 || len(result.Policies) != 1 {
		t.Fatalf("policy list = %#v, want one seeded policy", result)
	}
	if got := result.Policies[0]; got.ID != "pol_lab_https_allow_001" || got.TenantID != "tenant_lab_001" || got.Action.Decision != "allow" {
		t.Fatalf("seeded policy = %#v, want tenant-scoped allow policy", got)
	}
}

func TestAdminPolicyAPIUpsertThenDetailRead(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	outbox := &recordingAdminAuditOutboxDeadReader{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		Registry:         connector.NewRegistry(),
		AdminAuth:        newAdminAuthStore(),
		AdminAuditOutbox: outbox,
	})
	body := `{
		"id":"pol_lab_ssh_deny_001",
		"tenant_id":"tenant_lab_001",
		"name":"SSH deny",
		"priority":50,
		"conditions":{"service_family":"ssh"},
		"action":{"decision":"deny"},
		"status":"active",
		"metadata":{"source":"controlplane_contract_test"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/admin/policies", strings.NewReader(body))
	req.Header.Set("content-type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var created model.Policy
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created policy: %v", err)
	}
	if created.ID != "pol_lab_ssh_deny_001" || created.TenantID != "tenant_lab_001" || created.Action.Decision != "deny" || created.UpdatedAt == nil {
		t.Fatalf("created policy = %#v, want normalized tenant policy", created)
	}

	detailReq := httptest.NewRequest(http.MethodGet, "/admin/policies/pol_lab_ssh_deny_001", nil)
	detailRec := httptest.NewRecorder()
	handler.ServeHTTP(detailRec, detailReq)
	if detailRec.Code != http.StatusOK {
		t.Fatalf("detail status = %d, want %d, body=%s", detailRec.Code, http.StatusOK, detailRec.Body.String())
	}
	var detail model.Policy
	if err := json.Unmarshal(detailRec.Body.Bytes(), &detail); err != nil {
		t.Fatalf("decode policy detail: %v", err)
	}
	if detail.ID != created.ID || detail.TenantID != created.TenantID {
		t.Fatalf("detail policy = %#v, want created policy id/tenant", detail)
	}
	if len(outbox.insertedAudits) != 1 || outbox.insertedAudits[0].EventType != "admin_policy_upserted" {
		t.Fatalf("outbox inserted audits = %#v, want admin_policy_upserted", outbox.insertedAudits)
	}
	if outbox.insertedAudits[0].SourceIP != nil || outbox.insertedAudits[0].ActorUserID == nil || *outbox.insertedAudits[0].ActorUserID == "" {
		t.Fatalf("policy audit must identify the acting administrator without copying raw source fields: %#v", outbox.insertedAudits[0])
	}
}

func TestAdminPolicyAPIUpsertReadbackPreservesSWGFields(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Writer:    writer,
		Registry:  connector.NewRegistry(),
		AdminAuth: newAdminAuthStore(),
	})
	body := `{
		"id":"pol_google_workspace_admin_ui_001",
		"tenant_id":"tenant_lab_001",
		"name":"Google Workspace SWG",
		"priority":25,
		"service_family":"https",
		"conditions":{
			"actor_type":"human",
			"service_family":"https",
			"saas_application_id":"saas_google_workspace",
			"destination_port":443,
			"steering_mode":"network_extension"
		},
		"inspection_profile_id":"ip_swg_default_tls_decrypt",
		"action":{"decision":"allow"},
		"status":"active",
		"metadata":{"source":"admin_console_policy_editor"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/admin/policies", strings.NewReader(body))
	req.Header.Set("content-type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	detailReq := httptest.NewRequest(http.MethodGet, "/admin/policies/pol_google_workspace_admin_ui_001", nil)
	detailRec := httptest.NewRecorder()
	handler.ServeHTTP(detailRec, detailReq)
	if detailRec.Code != http.StatusOK {
		t.Fatalf("detail status = %d, want %d, body=%s", detailRec.Code, http.StatusOK, detailRec.Body.String())
	}
	var detail model.Policy
	if err := json.Unmarshal(detailRec.Body.Bytes(), &detail); err != nil {
		t.Fatalf("decode policy detail: %v", err)
	}
	if detail.ServiceFamily == nil || *detail.ServiceFamily != "https" {
		t.Fatalf("service_family = %#v, want https", detail.ServiceFamily)
	}
	if detail.InspectionProfileID == nil || *detail.InspectionProfileID != "ip_swg_default_tls_decrypt" {
		t.Fatalf("inspection_profile_id = %#v", detail.InspectionProfileID)
	}
	if detail.Conditions["saas_application_id"] != "saas_google_workspace" ||
		detail.Conditions["steering_mode"] != "network_extension" ||
		detail.Conditions["destination_port"] != float64(443) {
		t.Fatalf("SWG conditions = %#v", detail.Conditions)
	}
	if _, leaked := detail.Metadata["header_value"]; leaked {
		t.Fatalf("policy metadata leaked header value material: %#v", detail.Metadata)
	}
}

func TestAdminPolicyAPIUpsertPublishesDefaultTunnelNetworkExtensionSnapshot(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	outputDir := t.TempDir()
	defaultPassthroughDomainsEnabled := true
	publisher, err := newLocalNetworkExtensionSnapshotPublisher(localNetworkExtensionSnapshotPublisherConfig{
		OutputDir:                 outputDir,
		EdgeURL:                   "https://edge.reviewed.example.test:443",
		RuntimeCopyTransportScope: networkExtensionSnapshotDefaultTransportScope,
		EdgeConnectorRealness:     networkExtensionSnapshotDefaultConnectorRealness,
		PassthroughResolvedIPs:    []string{"198.51.100.44"},
		RuntimeCopyDownstreamPassthroughSourceAppSigningIdentifiers: []string{"a.out"},
		RuntimeCopyDownstreamPassthroughDefaultTunnelEnabled:        true,
		PassthroughDomains:                       []string{"*.example.invalid"},
		DefaultPassthroughDomainsEnabled:         &defaultPassthroughDomainsEnabled,
		SelfExclusionSourceAppSigningIdentifiers: []string{"com.apple.Safari"},
		InterceptOnlyDomains:                     []string{"accounts.google.com", "login.microsoftonline.com"},
	})
	if err != nil {
		t.Fatalf("newLocalNetworkExtensionSnapshotPublisher returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:                 testEvaluator(),
		Writer:                    writer,
		Registry:                  connector.NewRegistry(),
		AdminAuth:                 newAdminAuthStore(),
		NetworkExtensionPublisher: publisher,
	})
	body := `{
		"id":"pol_google_workspace_ne_snapshot_001",
		"tenant_id":"tenant_lab_001",
		"name":"Google Workspace SWG NE snapshot",
		"priority":25,
		"service_family":"https",
		"conditions":{
			"actor_type":"human",
			"service_family":"https",
			"saas_application_id":"saas_google_workspace",
			"destination_port":443,
			"steering_mode":"network_extension"
		},
		"inspection_profile_id":"ip_swg_default_tls_decrypt",
		"action":{"decision":"allow"},
		"status":"active",
		"metadata":{"source":"admin_console_policy_editor"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/admin/policies", strings.NewReader(body))
	req.Header.Set("content-type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var rules steering.NetworkExtensionRules
	rulesBody, err := os.ReadFile(filepath.Join(outputDir, networkExtensionSnapshotRulesRef))
	if err != nil {
		t.Fatalf("read rules snapshot: %v", err)
	}
	if err := json.Unmarshal(rulesBody, &rules); err != nil {
		t.Fatalf("decode rules snapshot: %v", err)
	}
	if rules.DefaultAction != steering.NetworkExtensionActionTunnel || len(rules.Rules) != 0 {
		t.Fatalf("rules snapshot default_action=%q rules=%d, want tunnel with no exact rules", rules.DefaultAction, len(rules.Rules))
	}
	if got := rules.Metadata["default_tunnel_all_tcp"]; got != true {
		t.Fatalf("rules metadata default_tunnel_all_tcp = %#v", got)
	}
	policyIDs, ok := rules.Metadata["active_network_extension_policy_ids"].([]any)
	if !ok || len(policyIDs) != 1 || policyIDs[0] != "pol_google_workspace_ne_snapshot_001" {
		t.Fatalf("active_network_extension_policy_ids = %#v", rules.Metadata["active_network_extension_policy_ids"])
	}

	var agentConfig map[string]any
	agentBody, err := os.ReadFile(filepath.Join(outputDir, networkExtensionSnapshotAgentConfigRef))
	if err != nil {
		t.Fatalf("read agent config snapshot: %v", err)
	}
	if err := json.Unmarshal(agentBody, &agentConfig); err != nil {
		t.Fatalf("decode agent config snapshot: %v", err)
	}
	for key, want := range map[string]any{
		"edge_url":                    "https://edge.reviewed.example.test:443",
		"network_extension_rules_ref": networkExtensionSnapshotRulesRef,
		"network_extension_runtime_copy_endpoint_path":                                 networkExtensionSnapshotDefaultEndpointPath,
		"network_extension_runtime_copy_session_endpoint_path":                         networkExtensionSnapshotDefaultSessionEndpointPath,
		"network_extension_runtime_copy_transport_scope":                               "real_edge",
		"network_extension_runtime_copy_edge_connector_realness":                       "over_the_wire_local",
		"network_extension_runtime_copy_downstream_passthrough_default_tunnel_enabled": true,
		"network_extension_runtime_copy_tunnel_enabled":                                true,
		"network_extension_default_passthrough_domains_enabled":                        true,
	} {
		if got := agentConfig[key]; got != want {
			t.Fatalf("agent_config[%s] = %#v, want %#v", key, got, want)
		}
	}
	sourceIDs, ok := agentConfig["network_extension_runtime_copy_downstream_passthrough_source_app_signing_identifiers"].([]any)
	if !ok || len(sourceIDs) != 1 || sourceIDs[0] != "a.out" {
		t.Fatalf("downstream source app signing identifiers = %#v", agentConfig["network_extension_runtime_copy_downstream_passthrough_source_app_signing_identifiers"])
	}
	// The signing identifiers for the agent's own exclusion travel in the agent_config the control plane
	// publishes; they are not settings a device's user edits.
	selfExclusionIDs, ok := agentConfig["network_extension_self_exclusion_source_app_signing_identifiers"].([]any)
	if !ok || len(selfExclusionIDs) != 1 || selfExclusionIDs[0] != "com.apple.Safari" {
		t.Fatalf("self-exclusion source app signing identifiers = %#v", agentConfig["network_extension_self_exclusion_source_app_signing_identifiers"])
	}
	// The intercept allowlist, which fixed blank SaaS pages and was lost and restored once: the network
	// extension takes over only the hosts on it and lets the rest pass straight through, avoiding the
	// half-duplex relay.
	interceptOnly, ok := agentConfig["network_extension_intercept_only_domains"].([]any)
	if !ok || len(interceptOnly) != 2 || interceptOnly[0] != "accounts.google.com" || interceptOnly[1] != "login.microsoftonline.com" {
		t.Fatalf("network_extension_intercept_only_domains = %#v", agentConfig["network_extension_intercept_only_domains"])
	}
	if _, leaked := agentConfig["header_value"]; leaked {
		t.Fatalf("agent config leaked header value material: %#v", agentConfig)
	}
	if _, err := os.Stat(filepath.Join(outputDir, networkExtensionSnapshotRuntimeDiagnosticRef)); err != nil {
		t.Fatalf("runtime diagnostic placeholder missing: %v", err)
	}
}

func TestNetworkExtensionSnapshotPublisherRejectsLoopbackRealEdgeURL(t *testing.T) {
	if _, err := newLocalNetworkExtensionSnapshotPublisher(localNetworkExtensionSnapshotPublisherConfig{
		OutputDir:                 t.TempDir(),
		EdgeURL:                   "http://127.0.0.1:18090",
		RuntimeCopyTransportScope: networkExtensionSnapshotDefaultTransportScope,
		EdgeConnectorRealness:     networkExtensionSnapshotDefaultConnectorRealness,
	}); err == nil || !strings.Contains(err.Error(), "non-loopback") {
		t.Fatalf("newLocalNetworkExtensionSnapshotPublisher error = %v, want non-loopback rejection", err)
	}
}

func TestAdminPolicyAPIUpsertReachesRuntimeDecisionEvaluator(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{
		ID:             "conn_lab_runtime_001",
		TenantID:       "tenant_lab_001",
		ApplicationIDs: []string{"app_dummy_https"},
		PrivateBaseURL: "http://connector.local",
		Status:         "healthy",
	}, time.Now().UTC()); err != nil {
		t.Fatalf("Register connector returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Writer:    writer,
		Registry:  registry,
		AdminAuth: newAdminAuthStore(),
	})
	body := `{
		"id":"pol_api_runtime_https_deny_001",
		"tenant_id":"tenant_lab_001",
		"name":"API runtime HTTPS deny",
		"priority":1,
		"conditions":{"service_family":"https"},
		"action":{"decision":"deny"},
		"status":"active",
		"metadata":{"source":"api_first_runtime_enforcement_e2e"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/admin/policies", strings.NewReader(body))
	req.Header.Set("content-type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("policy upsert status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	decisionBody := `{
		"tenant_id":"tenant_lab_001",
		"user_id":"user_lab_001",
		"device_id":"dev_lab_001",
		"application_id":"app_dummy_https",
		"source_ip":"127.0.0.1",
		"source_port":50100,
		"destination":"dummy-private-app.local",
		"destination_ip":"127.0.0.1",
		"destination_port":8443,
		"protocol":"tcp",
		"fqdn":"dummy-private-app.local",
		"sni":"dummy-private-app.local",
		"service_family":"https",
		"connection_initiator":"client",
		"source_role":"managed_endpoint",
		"destination_role":"private_app"
	}`
	decisionReq := httptest.NewRequest(http.MethodPost, "/decisions/evaluate", strings.NewReader(decisionBody))
	decisionReq.Header.Set("content-type", "application/json")
	decisionRec := httptest.NewRecorder()
	handler.ServeHTTP(decisionRec, decisionReq)
	if decisionRec.Code != http.StatusOK {
		t.Fatalf("decision status = %d, want %d, body=%s", decisionRec.Code, http.StatusOK, decisionRec.Body.String())
	}
	var dec model.AccessDecision
	if err := json.Unmarshal(decisionRec.Body.Bytes(), &dec); err != nil {
		t.Fatalf("decode decision: %v", err)
	}
	if dec.Decision != "deny" || dec.PolicyID != "pol_api_runtime_https_deny_001" {
		t.Fatalf("decision = %s policy=%s, want deny from API-upserted runtime policy", dec.Decision, dec.PolicyID)
	}

	routeReq := httptest.NewRequest(http.MethodGet, "/apps/app_dummy_https?connector_id=conn_lab_runtime_001", nil)
	routeRec := httptest.NewRecorder()
	handler.ServeHTTP(routeRec, routeReq)
	if routeRec.Code != http.StatusForbidden {
		t.Fatalf("connector route status = %d, want %d, body=%s", routeRec.Code, http.StatusForbidden, routeRec.Body.String())
	}
	var routeDecision model.AccessDecision
	if err := json.Unmarshal(routeRec.Body.Bytes(), &routeDecision); err != nil {
		t.Fatalf("decode connector route decision: %v", err)
	}
	if routeDecision.Decision != "deny" || routeDecision.PolicyID != "pol_api_runtime_https_deny_001" {
		t.Fatalf("connector route decision = %s policy=%s, want deny from API-upserted runtime policy", routeDecision.Decision, routeDecision.PolicyID)
	}
}

func TestAdminPolicyAPIPreservesCandidateHandoffMetadataOnUpsertReadback(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	outbox := &recordingAdminAuditOutboxDeadReader{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		Registry:         connector.NewRegistry(),
		AdminAuth:        newAdminAuthStore(),
		AdminAuditOutbox: outbox,
	})
	body := `{
		"id":"pol_candidate_pc_ssh_allow_001",
		"tenant_id":"tenant_lab_001",
		"name":"Candidate pc_ssh_allow_001",
		"priority":100,
		"conditions":{"service_family":"ssh","application_id":"app_private_ssh"},
		"action":{"decision":"allow"},
		"status":"draft",
		"metadata":{
			"source":"admin_console_policy_candidate_handoff",
			"policy_candidate_id":"pc_ssh_allow_001",
			"policy_candidate_type":"private_app",
			"proposed_action":"allow",
			"application_id":"app_private_ssh",
			"review_reason_code":"least_privilege_exception"
		}
	}`
	req := httptest.NewRequest(http.MethodPost, "/admin/policies", strings.NewReader(body))
	req.Header.Set("content-type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var created model.Policy
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode candidate handoff policy: %v", err)
	}
	if created.Status != "draft" || created.Action.Decision != "allow" {
		t.Fatalf("created candidate handoff policy = %#v, want draft allow policy", created)
	}

	detailReq := httptest.NewRequest(http.MethodGet, "/admin/policies/pol_candidate_pc_ssh_allow_001", nil)
	detailRec := httptest.NewRecorder()
	handler.ServeHTTP(detailRec, detailReq)
	if detailRec.Code != http.StatusOK {
		t.Fatalf("detail status = %d, want %d, body=%s", detailRec.Code, http.StatusOK, detailRec.Body.String())
	}
	var detail model.Policy
	if err := json.Unmarshal(detailRec.Body.Bytes(), &detail); err != nil {
		t.Fatalf("decode candidate handoff policy detail: %v", err)
	}
	wantMetadata := map[string]string{
		"source":                "admin_console_policy_candidate_handoff",
		"policy_candidate_id":   "pc_ssh_allow_001",
		"policy_candidate_type": "private_app",
		"proposed_action":       "allow",
		"application_id":        "app_private_ssh",
		"review_reason_code":    "least_privilege_exception",
	}
	for key, want := range wantMetadata {
		if got, _ := detail.Metadata[key].(string); got != want {
			t.Fatalf("detail metadata[%s] = %#v, want %q in candidate-derived policy readback", key, detail.Metadata[key], want)
		}
	}
	if detail.Metadata["runtime_materialized"] != nil || detail.Metadata["policy_bundle_compiled"] != nil {
		t.Fatalf("candidate metadata readback included runtime materialization fields: %#v", detail.Metadata)
	}
	if len(outbox.insertedAudits) != 1 || outbox.insertedAudits[0].EventType != "admin_policy_upserted" {
		t.Fatalf("outbox inserted audits = %#v, want one admin_policy_upserted", outbox.insertedAudits)
	}
	if outbox.insertedAudits[0].Metadata["policy_metadata_recorded_scope"] != "candidate_handoff_nonsecret_trace" ||
		outbox.insertedAudits[0].Metadata["policy_candidate_handoff_source"] != "admin_console_policy_candidate_handoff" ||
		outbox.insertedAudits[0].Metadata["policy_candidate_handoff_metadata_key_count"] != 6 ||
		outbox.insertedAudits[0].Metadata["policy_candidate_id_present"] != true ||
		outbox.insertedAudits[0].Metadata["application_id_present"] != true ||
		outbox.insertedAudits[0].Metadata["review_reason_code_present"] != true {
		t.Fatalf("policy audit metadata = %#v, want candidate handoff non-secret audit trace", outbox.insertedAudits[0].Metadata)
	}
}

func TestAdminPolicyAPICandidateHandoffAuditTraceVisibleThroughAdminAuditSurface(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	outbox := &recordingAdminAuditOutboxDeadReader{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		Registry:         connector.NewRegistry(),
		AdminAuth:        newAdminAuthStore(),
		AdminAuditOutbox: outbox,
	})
	body := `{
		"id":"pol_candidate_trace_001",
		"tenant_id":"tenant_lab_001",
		"name":"Candidate audit trace",
		"priority":80,
		"conditions":{"service_family":"ssh","application_id":"app_private_ssh_trace_raw"},
		"action":{"decision":"allow"},
		"status":"draft",
		"metadata":{
			"source":"admin_console_policy_candidate_handoff",
			"policy_candidate_id":"pc_raw_candidate_trace_001",
			"policy_candidate_type":"private_app",
			"proposed_action":"allow",
			"application_id":"app_private_ssh_trace_raw",
			"review_reason_code":"least_privilege_exception_raw"
		}
	}`
	req := httptest.NewRequest(http.MethodPost, "/admin/policies", strings.NewReader(body))
	req.Header.Set("content-type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if len(outbox.insertedAudits) != 1 {
		t.Fatalf("outbox inserted audits = %#v, want one policy audit trace", outbox.insertedAudits)
	}
	audit := outbox.insertedAudits[0]
	if audit.EventType != "admin_policy_upserted" || audit.Metadata["policy_metadata_recorded_scope"] != "candidate_handoff_nonsecret_trace" {
		t.Fatalf("outbox policy audit = %#v, want candidate handoff audit trace", audit)
	}
	wantMetadata := map[string]any{
		"policy_candidate_handoff_source":             "admin_console_policy_candidate_handoff",
		"policy_candidate_handoff_metadata_key_count": 6,
		"policy_candidate_id_present":                 true,
		"policy_candidate_type":                       "private_app",
		"proposed_action":                             "allow",
		"application_id_present":                      true,
		"review_reason_code_present":                  true,
		"runtime_policy_materialization_claimed":      false,
		"policy_bundle_compilation_claimed":           false,
	}
	for key, want := range wantMetadata {
		if got := audit.Metadata[key]; got != want {
			t.Fatalf("audit metadata[%s] = %#v, want %#v in candidate handoff audit trace; metadata=%#v", key, got, want, audit.Metadata)
		}
	}

	auditRows, err := readAuditRowsExcludingWrapper(writer)
	if err != nil {
		t.Fatalf("ReadJSONL audit surface returned error: %v", err)
	}
	if len(auditRows) != 1 {
		t.Fatalf("audit rows = %#v, want one admin_policy_upserted row", auditRows)
	}
	rowBytes, err := json.Marshal(auditRows[0])
	if err != nil {
		t.Fatalf("marshal audit row: %v", err)
	}
	row := string(rowBytes)
	for _, forbidden := range []string{
		"pc_raw_candidate_trace_001",
		"app_private_ssh_trace_raw",
		"least_privilege_exception_raw",
	} {
		if strings.Contains(row, forbidden) {
			t.Fatalf("candidate audit trace leaked raw metadata value %q in %s", forbidden, row)
		}
	}
	for _, want := range []string{
		"admin_policy_upserted",
		"candidate_handoff_nonsecret_trace",
		"admin_console_policy_candidate_handoff",
		"policy_candidate_id_present",
		"application_id_present",
		"review_reason_code_present",
	} {
		if !strings.Contains(row, want) {
			t.Fatalf("candidate audit surface row %s missing %q", row, want)
		}
	}
}

func TestAdminPolicyAPICandidateHandoffAuditTraceSearchableThroughAdminLogUIQuery(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Writer:    writer,
		Registry:  connector.NewRegistry(),
		AdminAuth: newAdminAuthStore(),
	})
	body := `{
		"id":"pol_candidate_search_001",
		"tenant_id":"tenant_lab_001",
		"name":"Candidate audit search",
		"priority":85,
		"conditions":{"service_family":"ssh","application_id":"app_private_ssh_search_raw"},
		"action":{"decision":"allow"},
		"status":"draft",
		"metadata":{
			"source":"admin_console_policy_candidate_handoff",
			"policy_candidate_id":"pc_raw_candidate_search_001",
			"policy_candidate_type":"private_app",
			"proposed_action":"allow",
			"application_id":"app_private_ssh_search_raw",
			"review_reason_code":"least_privilege_exception_search_raw"
		}
	}`
	req := httptest.NewRequest(http.MethodPost, "/admin/policies", strings.NewReader(body))
	req.Header.Set("content-type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	searchReq := httptest.NewRequest(http.MethodGet, "/admin/logs/audit?event_type=admin_policy_upserted&q=candidate_handoff_nonsecret_trace&limit=10", nil)
	searchRec := httptest.NewRecorder()
	handler.ServeHTTP(searchRec, searchReq)
	if searchRec.Code != http.StatusOK {
		t.Fatalf("search status = %d, want %d, body=%s", searchRec.Code, http.StatusOK, searchRec.Body.String())
	}
	var result struct {
		Stream       string            `json:"stream"`
		Filters      map[string]string `json:"filters"`
		Query        string            `json:"query"`
		TotalMatches int               `json:"total_matches"`
		Rows         []map[string]any  `json:"rows"`
	}
	if err := json.Unmarshal(searchRec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode log search result: %v", err)
	}
	if result.Stream != "audit" || result.Filters["event_type"] != "admin_policy_upserted" || result.Query != "candidate_handoff_nonsecret_trace" {
		t.Fatalf("search result header = %#v, want audit candidate trace search", result)
	}
	if result.TotalMatches != 1 || len(result.Rows) != 1 {
		t.Fatalf("search result = %#v, want one candidate handoff audit trace", result)
	}
	rowBytes, err := json.Marshal(result.Rows[0])
	if err != nil {
		t.Fatalf("marshal log search row: %v", err)
	}
	row := string(rowBytes)
	for _, want := range []string{
		"admin_policy_upserted",
		"candidate_handoff_nonsecret_trace",
		"policy_candidate_id_present",
		"application_id_present",
		"review_reason_code_present",
	} {
		if !strings.Contains(row, want) {
			t.Fatalf("candidate audit search row %s missing %q", row, want)
		}
	}
	for _, forbidden := range []string{
		"pc_raw_candidate_search_001",
		"app_private_ssh_search_raw",
		"least_privilege_exception_search_raw",
	} {
		if strings.Contains(row, forbidden) {
			t.Fatalf("candidate audit search leaked raw metadata value %q in %s", forbidden, row)
		}
	}
}

func TestAdminPolicyAPICandidateAuditSearchResultLinksToPolicyDetailReadback(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Writer:    writer,
		Registry:  connector.NewRegistry(),
		AdminAuth: newAdminAuthStore(),
	})
	body := `{
		"id":"pol_candidate_detail_link_001",
		"tenant_id":"tenant_lab_001",
		"name":"Candidate audit detail link",
		"priority":82,
		"conditions":{"service_family":"ssh","application_id":"app_private_ssh_detail_link_raw"},
		"action":{"decision":"allow"},
		"status":"draft",
		"metadata":{
			"source":"admin_console_policy_candidate_handoff",
			"policy_candidate_id":"pc_raw_candidate_detail_link_001",
			"policy_candidate_type":"private_app",
			"proposed_action":"allow",
			"application_id":"app_private_ssh_detail_link_raw",
			"review_reason_code":"least_privilege_exception_detail_link_raw"
		}
	}`
	req := httptest.NewRequest(http.MethodPost, "/admin/policies", strings.NewReader(body))
	req.Header.Set("content-type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	searchReq := httptest.NewRequest(http.MethodGet, "/admin/logs/audit?event_type=admin_policy_upserted&q=candidate_handoff_nonsecret_trace&limit=10", nil)
	searchRec := httptest.NewRecorder()
	handler.ServeHTTP(searchRec, searchReq)
	if searchRec.Code != http.StatusOK {
		t.Fatalf("search status = %d, want %d, body=%s", searchRec.Code, http.StatusOK, searchRec.Body.String())
	}
	var result struct {
		TotalMatches int              `json:"total_matches"`
		Rows         []map[string]any `json:"rows"`
	}
	if err := json.Unmarshal(searchRec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode log search result: %v", err)
	}
	if result.TotalMatches != 1 || len(result.Rows) != 1 {
		t.Fatalf("search result = %#v, want one candidate handoff audit trace", result)
	}
	policyID, _ := result.Rows[0]["policy_id"].(string)
	if policyID != "pol_candidate_detail_link_001" {
		t.Fatalf("candidate audit search policy_id = %#v, want policy detail link id", result.Rows[0]["policy_id"])
	}
	if targetID, _ := result.Rows[0]["target_id"].(string); targetID != policyID {
		t.Fatalf("candidate audit search target_id = %#v, want %q", result.Rows[0]["target_id"], policyID)
	}
	rowBytes, err := json.Marshal(result.Rows[0])
	if err != nil {
		t.Fatalf("marshal log search row: %v", err)
	}
	row := string(rowBytes)
	for _, forbidden := range []string{
		"pc_raw_candidate_detail_link_001",
		"app_private_ssh_detail_link_raw",
		"least_privilege_exception_detail_link_raw",
	} {
		if strings.Contains(row, forbidden) {
			t.Fatalf("candidate audit detail link search leaked raw metadata value %q in %s", forbidden, row)
		}
	}

	detailReq := httptest.NewRequest(http.MethodGet, "/admin/policies/"+policyID, nil)
	detailRec := httptest.NewRecorder()
	handler.ServeHTTP(detailRec, detailReq)
	if detailRec.Code != http.StatusOK {
		t.Fatalf("detail status = %d, want %d, body=%s", detailRec.Code, http.StatusOK, detailRec.Body.String())
	}
	var detail model.Policy
	if err := json.Unmarshal(detailRec.Body.Bytes(), &detail); err != nil {
		t.Fatalf("decode policy detail readback: %v", err)
	}
	if detail.ID != policyID || detail.Status != "draft" || detail.Action.Decision != "allow" {
		t.Fatalf("detail policy = %#v, want candidate-derived draft allow policy", detail)
	}
	if got, _ := detail.Metadata["source"].(string); got != "admin_console_policy_candidate_handoff" {
		t.Fatalf("detail metadata source = %#v, want candidate handoff source", detail.Metadata["source"])
	}
	if detail.Metadata["runtime_materialized"] != nil || detail.Metadata["policy_bundle_compiled"] != nil {
		t.Fatalf("candidate detail readback included runtime materialization fields: %#v", detail.Metadata)
	}
}

func TestAdminPolicyAPIRejectsTenantMismatch(t *testing.T) {
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		AdminAuth: newAdminAuthStore(),
	})
	body := `{"id":"pol_other_001","tenant_id":"tenant_other_001","name":"Other tenant","conditions":{"service_family":"ssh"},"action":{"decision":"deny"},"status":"active"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/policies", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "tenant_id") {
		t.Fatalf("status = %d body=%s, want tenant mismatch bad request", rec.Code, rec.Body.String())
	}
}

func TestAdminPolicyAPIRequiresWriteScopeForAPIToken(t *testing.T) {
	adminAuth := newAdminAuthStore()
	adminAuth.UpsertPrincipal(adminPrincipal{
		ID:        "admin_policy_reader_001",
		TenantID:  "tenant_lab_001",
		Subject:   "sub_policy_reader_001",
		Email:     "policy-reader@example.test",
		Roles:     []string{"admin"},
		IDPID:     "keycloak_lab",
		Status:    "active",
		CreatedAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
	})
	adminAuth.UpsertAPIToken(adminAPIToken{
		ID:                        "admin_token_policy_reader_001",
		TenantID:                  "tenant_lab_001",
		Name:                      "policy-reader-token",
		TokenHash:                 adminTokenHash("raw-policy-reader-token"),
		Roles:                     []string{"admin"},
		Scopes:                    []string{"admin.policy.read"},
		CreatedByAdminPrincipalID: "admin_policy_reader_001",
		CreatedAt:                 time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt:                 time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		Status:                    "active",
	})
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Registry:  connector.NewRegistry(),
		AdminAuth: adminAuth,
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/policies", strings.NewReader(`{"id":"pol_scope_denied_001","conditions":{"service_family":"ssh"},"action":{"decision":"deny"}}`))
	req.Header.Set("authorization", "Bearer raw-policy-reader-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "admin api token scope admin.policy.write is required") {
		t.Fatalf("status = %d body=%s, want write scope denial", rec.Code, rec.Body.String())
	}
}
