package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	toolcallaudit "github.com/lantern-networks/dsse-core/toolcallaudit"

	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

func TestAdminToolCallEventAuditOpenAPIContract(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "openapi", "admin_api.yaml"))
	if err != nil {
		t.Fatalf("read admin OpenAPI contract: %v", err)
	}
	contract := string(data)
	for _, want := range []string{
		"    ToolCallEventAudit:",
		"    ToolCallEventAuditWrite:",
		"    ToolCallEventAuditList:",
		"  /admin/tool-call-events:",
		"  /admin/tool-call-events/{event_id}:",
		"admin.tool_call_events.read",
		"admin.tool_call_events.write",
		`$ref: "#/components/schemas/ToolCallEventAuditList"`,
		`$ref: "#/components/schemas/ToolCallEventAuditWrite"`,
	} {
		if !strings.Contains(contract, want) {
			t.Fatalf("admin OpenAPI contract missing %q", want)
		}
	}
}

func TestAdminToolCallEventAuditAPIUpsertThenDetailRead(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	outbox := &recordingAdminAuditOutboxDeadReader{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:               testEvaluator(),
		Writer:                  writer,
		AdminAuth:               newAdminAuthStore(),
		AdminAuditOutbox:        outbox,
		ToolCallEventAuditStore: toolcallaudit.NewStore(),
	})
	body := `{
		"id":"tce_admin_001",
		"tenant_id":"tenant_lab_001",
		"agent_task_session_id":"ats_admin_001",
		"actor_nhi_id":"nhi_admin_001",
		"subject_user_id":"subject-user-raw-001",
		"delegated_access_grant_id":"grant_admin_001",
		"task_id":"task-raw-001",
		"run_id":"run-raw-001",
		"tool_id":"tool_ticket_create_001",
		"mcp_server_id":"mcp_admin_001",
		"runtime_environment_id":"runtime_admin_001",
		"action_type":"ticket.create",
		"application_id":"app_admin_001",
		"context_boundary_id":"ctx_admin_001",
		"data_classification":"internal",
		"destination":"https://raw-destination.example.test",
		"token_audience":"raw-token-audience",
		"human_approval_event_id":"ha_admin_001",
		"access_decision_id":"dec_admin_001",
		"inspection_event_id":"insp_admin_001",
		"policy_id":"pol_admin_001",
		"decision":"allow",
		"result_summary":"raw masked result summary should not be returned",
		"result_summary_scope":"masked_summary",
		"masked":true,
		"payload_ref":"s3://raw-payload-ref",
		"retention_policy":"standard",
		"timestamp":"2026-06-01T01:02:03Z",
		"status":"success",
		"metadata":{"safe_label":"raw metadata value should not be returned"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/admin/tool-call-events", strings.NewReader(body))
	req.Header.Set("content-type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	for _, leaked := range []string{
		"subject-user-raw-001",
		"task-raw-001",
		"run-raw-001",
		"https://raw-destination.example.test",
		"raw-token-audience",
		"raw masked result summary should not be returned",
		"s3://raw-payload-ref",
		"raw metadata value should not be returned",
	} {
		if strings.Contains(rec.Body.String(), leaked) {
			t.Fatalf("tool call audit response leaked %q: %s", leaked, rec.Body.String())
		}
	}
	var created toolcallaudit.Event
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created tool call audit: %v", err)
	}
	if created.ID != "tce_admin_001" || created.TenantID != "tenant_lab_001" || created.ToolID != "tool_ticket_create_001" || created.ResultSummaryScope != "masked_summary" {
		t.Fatalf("created tool call audit = %#v, want normalized metadata-only event", created)
	}
	if !created.SubjectUserIDPresent || !created.TaskIDPresent || !created.RunIDPresent || !created.DestinationPresent || !created.TokenAudiencePresent || !created.ResultSummaryPresent || !created.PayloadRefPresent {
		t.Fatalf("created tool call audit presence flags = %#v, want raw fields represented as presence only", created)
	}
	if created.MetadataKeyCount != 1 || created.ToolCallMetadataValueScope != "none" {
		t.Fatalf("created tool call audit metadata boundary = %#v, want value scope none", created)
	}

	detailReq := httptest.NewRequest(http.MethodGet, "/admin/tool-call-events/tce_admin_001", nil)
	detailRec := httptest.NewRecorder()
	handler.ServeHTTP(detailRec, detailReq)
	if detailRec.Code != http.StatusOK {
		t.Fatalf("detail status = %d, want %d, body=%s", detailRec.Code, http.StatusOK, detailRec.Body.String())
	}
	var detail toolcallaudit.Event
	if err := json.Unmarshal(detailRec.Body.Bytes(), &detail); err != nil {
		t.Fatalf("decode tool call audit detail: %v", err)
	}
	if detail.ID != created.ID || detail.MetadataKeyCount != 1 || !detail.ResultSummaryPresent {
		t.Fatalf("detail tool call audit = %#v, want created metadata-only event", detail)
	}
	if len(outbox.insertedAudits) != 1 || outbox.insertedAudits[0].EventType != "admin_tool_call_event_upserted" {
		t.Fatalf("outbox inserted audits = %#v, want tool call event upsert", outbox.insertedAudits)
	}
	audit := outbox.insertedAudits[0]
	if audit.SourceIP != nil || audit.ActorUserID != nil || audit.ActorNHIID != nil {
		t.Fatalf("tool call admin audit included raw source/actor fields: %#v", audit)
	}
	if audit.Metadata["tool_call_metadata_recorded_scope"] != "none" || audit.Metadata["runtime_hot_reload"] != false {
		t.Fatalf("tool call admin audit metadata = %#v, want non-secret admin boundary", audit.Metadata)
	}
}

func TestAdminToolCallEventAuditAPIListFiltersTenantScope(t *testing.T) {
	store := toolcallaudit.NewStore()
	now := time.Date(2026, 6, 1, 1, 2, 3, 0, time.UTC)
	if _, err := store.Upsert(context.Background(), model.ToolCallEvent{
		ID:                 "tce_filter_001",
		TenantID:           "tenant_lab_001",
		ActorNHIID:         "nhi_filter_001",
		ToolID:             "tool_filter_001",
		ActionType:         "ticket.create",
		Decision:           stringPtr("allow"),
		ResultSummaryScope: "metadata_only",
		Timestamp:          now.Format(time.RFC3339),
		Status:             stringPtr("success"),
		Metadata:           map[string]any{"source": "test"},
	}, "tenant_lab_001", now); err != nil {
		t.Fatalf("upsert tenant tool call audit: %v", err)
	}
	if _, err := store.Upsert(context.Background(), model.ToolCallEvent{
		ID:                 "tce_filter_other_001",
		TenantID:           "tenant_other_001",
		ActorNHIID:         "nhi_filter_002",
		ToolID:             "tool_filter_001",
		ActionType:         "ticket.create",
		ResultSummaryScope: "metadata_only",
		Timestamp:          now.Format(time.RFC3339),
	}, "tenant_other_001", now); err != nil {
		t.Fatalf("upsert other tenant tool call audit: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:               testEvaluator(),
		AdminAuth:               newAdminAuthStore(),
		ToolCallEventAuditStore: store,
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/tool-call-events?tool_id=tool_filter_001&status=success&limit=10", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var result toolcallaudit.ListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode tool call audit list: %v", err)
	}
	if result.Count != 1 || result.Limit != 10 || len(result.Events) != 1 || result.Events[0].ID != "tce_filter_001" {
		t.Fatalf("tool call audit list = %#v, want one tenant-scoped filtered event", result)
	}
}

func TestAdminToolCallEventAuditAPIRejectsTenantMismatch(t *testing.T) {
	handler := newServerWithConfig(serverConfig{
		Evaluator:               testEvaluator(),
		AdminAuth:               newAdminAuthStore(),
		ToolCallEventAuditStore: toolcallaudit.NewStore(),
	})
	body := `{"id":"tce_other_001","tenant_id":"tenant_other_001","actor_nhi_id":"nhi_other_001","tool_id":"tool_other_001","action_type":"ticket.create"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/tool-call-events", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "tenant_id") {
		t.Fatalf("status = %d body=%s, want tenant mismatch rejection", rec.Code, rec.Body.String())
	}
}

func TestAdminToolCallEventAuditAPIRequiresWriteScopeForAPIToken(t *testing.T) {
	adminAuth := seedAdminConnectorAPITokenAuth("admin_tool_call_reader_001", "raw-tool-call-reader-token", []string{"admin.tool_call_events.read"})
	handler := newServerWithConfig(serverConfig{
		Evaluator:               testEvaluator(),
		AdminAuth:               adminAuth,
		ToolCallEventAuditStore: toolcallaudit.NewStore(),
	})
	body := `{"id":"tce_scope_denied_001","tenant_id":"tenant_lab_001","actor_nhi_id":"nhi_scope_001","tool_id":"tool_scope_001","action_type":"ticket.create"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/tool-call-events", strings.NewReader(body))
	req.Header.Set("authorization", "Bearer raw-tool-call-reader-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "admin api token scope admin.tool_call_events.write is required") {
		t.Fatalf("status = %d body=%s, want write scope denial", rec.Code, rec.Body.String())
	}
}
