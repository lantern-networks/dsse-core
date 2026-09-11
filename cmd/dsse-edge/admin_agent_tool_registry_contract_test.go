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

	agenttool "github.com/lantern-networks/dsse-core/agenttool"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

func TestAdminAgentToolRegistryOpenAPIContract(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "openapi", "admin_api.yaml"))
	if err != nil {
		t.Fatalf("read admin OpenAPI contract: %v", err)
	}
	contract := string(data)
	for _, want := range []string{
		"    AgentTool:",
		"    AgentToolList:",
		"  /admin/agent-tools:",
		"  /admin/agent-tools/{tool_id}:",
		"admin.agent_tools.read",
		"admin.agent_tools.write",
		`$ref: "#/components/schemas/AgentToolList"`,
		`$ref: "#/components/schemas/AgentTool"`,
	} {
		if !strings.Contains(contract, want) {
			t.Fatalf("admin OpenAPI contract missing %q", want)
		}
	}
}

func TestAdminAgentToolRegistryAPIListsSeededPolicyTools(t *testing.T) {
	handler := newServerWithConfig(serverConfig{
		Evaluator: testAgentToolRegistryEvaluator(),
		Registry:  connector.NewRegistry(),
		AdminAuth: newAdminAuthStore(),
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/agent-tools?limit=10", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var result agenttool.ListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode agent tool list: %v", err)
	}
	if result.Count != 2 || result.Limit != 10 || len(result.Tools) != 2 {
		t.Fatalf("agent tool list = %#v, want seeded policy tools", result)
	}
	byID := map[string]agenttool.Tool{}
	for _, tool := range result.Tools {
		byID[tool.ToolID] = tool
	}
	if got := byID["tool_ticket_create_001"]; got.TenantID != "tenant_lab_001" || got.ActionType != "ticket:create" || got.Status != "active" || got.SignatureState != "unknown" {
		t.Fatalf("seeded ticket tool = %#v, want sanitized active policy tool", got)
	}
	if got := byID["tool_chat_notify_001"]; got.TenantID != "tenant_lab_001" || got.ActionType != "ticket:create" {
		t.Fatalf("seeded notify tool = %#v, want policy-derived action type", got)
	}
}

func TestAdminAgentToolRegistryAPIUpsertListAndDetailRead(t *testing.T) {
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
		"tool_id":"tool_admin_ticket_create_001",
		"tenant_id":"tenant_lab_001",
		"name":"Ticket Create",
		"description":"Metadata-only ticket creation tool",
		"publisher":"ops-platform",
		"version":"v1.2.3",
		"signature_state":"verified",
		"permission_profile":"ticket-write",
		"action_type":"ticket:create",
		"mcp_server_id":"mcp_service_desk",
		"allowed_application_ids":["app_catalog_custom_001"],
		"allowed_data_classifications":["internal","restricted"],
		"human_approval_required":true,
		"runtime_environment_id":"runtime_hosted_tooling",
		"metadata_key_count":3,
		"status":"active"
	}`
	createReq := httptest.NewRequest(http.MethodPost, "/admin/agent-tools", strings.NewReader(body))
	createReq.Header.Set("content-type", "application/json")
	createRec := httptest.NewRecorder()

	handler.ServeHTTP(createRec, createReq)

	if createRec.Code != http.StatusOK {
		t.Fatalf("create status = %d, want %d, body=%s", createRec.Code, http.StatusOK, createRec.Body.String())
	}
	var created agenttool.Tool
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created agent tool: %v", err)
	}
	if created.ToolID != "tool_admin_ticket_create_001" || created.TenantID != "tenant_lab_001" || created.ActionType != "ticket:create" || created.UpdatedAt == nil {
		t.Fatalf("created agent tool = %#v, want normalized tenant tool", created)
	}
	if created.SignatureState != "verified" || !created.HumanApprovalRequired || len(created.AllowedApplicationIDs) != 1 || len(created.AllowedDataClassifications) != 2 {
		t.Fatalf("created agent tool = %#v, want metadata-only registry fields preserved", created)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/admin/agent-tools?status=active&action_type=ticket:create&limit=10", nil)
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want %d, body=%s", listRec.Code, http.StatusOK, listRec.Body.String())
	}
	var list agenttool.ListResponse
	if err := json.Unmarshal(listRec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode agent tool list: %v", err)
	}
	if list.Count != 1 || len(list.Tools) != 1 || list.Tools[0].ToolID != created.ToolID {
		t.Fatalf("agent tool list = %#v, want created active ticket tool", list)
	}

	detailReq := httptest.NewRequest(http.MethodGet, "/admin/agent-tools/tool_admin_ticket_create_001", nil)
	detailRec := httptest.NewRecorder()
	handler.ServeHTTP(detailRec, detailReq)
	if detailRec.Code != http.StatusOK {
		t.Fatalf("detail status = %d, want %d, body=%s", detailRec.Code, http.StatusOK, detailRec.Body.String())
	}
	var detail agenttool.Tool
	if err := json.Unmarshal(detailRec.Body.Bytes(), &detail); err != nil {
		t.Fatalf("decode agent tool detail: %v", err)
	}
	if detail.ToolID != created.ToolID || detail.TenantID != created.TenantID || detail.MCPServerID != "mcp_service_desk" {
		t.Fatalf("detail agent tool = %#v, want created tool id/tenant/mcp metadata", detail)
	}
	if len(outbox.insertedAudits) != 1 || outbox.insertedAudits[0].EventType != "admin_agent_tool_upserted" {
		t.Fatalf("outbox inserted audits = %#v, want admin_agent_tool_upserted", outbox.insertedAudits)
	}
	audit := outbox.insertedAudits[0]
	if audit.SourceIP != nil || audit.ActorUserID != nil {
		t.Fatalf("agent tool audit included raw source/user fields: %#v", audit)
	}
	if audit.Metadata["tool_metadata_recorded_scope"] != "none" || audit.Metadata["tool_payload_recorded"] != false || audit.Metadata["tool_secret_recorded"] != false || audit.Metadata["tool_credentials_recorded"] != false {
		t.Fatalf("agent tool audit metadata = %#v, want non-secret metadata boundary", audit.Metadata)
	}
}

func TestAdminAgentToolRegistryAPIRejectsTenantMismatch(t *testing.T) {
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		AdminAuth: newAdminAuthStore(),
	})
	body := `{"tool_id":"tool_other_001","tenant_id":"tenant_other_001","name":"Other","action_type":"ticket:create","status":"active"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/agent-tools", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "tenant_id") {
		t.Fatalf("status = %d body=%s, want tenant mismatch bad request", rec.Code, rec.Body.String())
	}
}

func TestAdminAgentToolRegistryAPIRequiresWriteScopeForAPIToken(t *testing.T) {
	adminAuth := newAdminAuthStore()
	adminAuth.UpsertPrincipal(adminPrincipal{
		ID:        "admin_agent_tool_reader_001",
		TenantID:  "tenant_lab_001",
		Subject:   "sub_agent_tool_reader_001",
		Email:     "agent-tool-reader@example.test",
		Roles:     []string{"admin"},
		IDPID:     "keycloak_lab",
		Status:    "active",
		CreatedAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
	})
	adminAuth.UpsertAPIToken(adminAPIToken{
		ID:                        "admin_token_agent_tool_reader_001",
		TenantID:                  "tenant_lab_001",
		Name:                      "agent-tool-reader-token",
		TokenHash:                 adminTokenHash("raw-agent-tool-reader-token"),
		Roles:                     []string{"admin"},
		Scopes:                    []string{"admin.agent_tools.read"},
		CreatedByAdminPrincipalID: "admin_agent_tool_reader_001",
		CreatedAt:                 time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt:                 time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		Status:                    "active",
	})
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Registry:  connector.NewRegistry(),
		AdminAuth: adminAuth,
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/agent-tools", strings.NewReader(`{"tool_id":"tool_scope_denied_001","action_type":"ticket:create"}`))
	req.Header.Set("authorization", "Bearer raw-agent-tool-reader-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "admin api token scope admin.agent_tools.write is required") {
		t.Fatalf("status = %d body=%s, want write scope denial", rec.Code, rec.Body.String())
	}
}

func testAgentToolRegistryEvaluator() decision.Evaluator {
	evaluator := testEvaluator()
	evaluator.Policies = []model.Policy{
		{
			ID:                 "pol_agent_tools_001",
			TenantID:           "tenant_lab_001",
			Name:               "Agent tool policy",
			Priority:           10,
			Conditions:         map[string]any{"service_family": "saas"},
			Action:             model.PolicyAction{Decision: "allow"},
			AllowedToolIDs:     []string{"tool_ticket_create_001", "tool_chat_notify_001"},
			AllowedToolActions: []string{"ticket:create"},
			Status:             "active",
		},
	}
	return evaluator
}
