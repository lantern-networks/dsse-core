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

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
)

func TestAdminHumanApprovalEventOpenAPIContract(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "openapi", "admin_api.yaml"))
	if err != nil {
		t.Fatalf("read admin OpenAPI contract: %v", err)
	}
	contract := string(data)
	for _, want := range []string{
		"    HumanApprovalEvent:",
		"    HumanApprovalEventList:",
		"    HumanApprovalEventRevokeRequest:",
		"  /admin/human-approval-events:",
		"  /admin/human-approval-events/{approval_id}:",
		"  /admin/human-approval-events/{approval_id}/revoke:",
		"admin.approval.read",
		"admin.approval.write",
		`$ref: "#/components/schemas/HumanApprovalEventList"`,
		`$ref: "#/components/schemas/HumanApprovalEvent"`,
		`$ref: "#/components/schemas/HumanApprovalEventRevokeRequest"`,
	} {
		if !strings.Contains(contract, want) {
			t.Fatalf("admin OpenAPI contract missing %q", want)
		}
	}
}

func TestAdminHumanApprovalEventAPIUpsertListDetailAndRevoke(t *testing.T) {
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
		"id":"hae_admin_001",
		"tenant_id":"tenant_lab_001",
		"approval_source":"admin_console",
		"approver_user_id":"approver_lab_001",
		"subject_user_id":"user_lab_001",
		"actor_nhi_id":"nhi_soc_agent_001",
		"delegated_access_grant_id":"dag_admin_001",
		"agent_task_session_id":"ats_admin_001",
		"application_id":"app_dummy_https",
		"audience":"service_desk",
		"resource":"ticket_queue",
		"action_type":"ticket:create",
		"task_id":"task_admin_001",
		"run_id":"run_admin_001",
		"requested_scopes":["ticket:write","ticket:read","ticket:write"],
		"reason_code":"least_privilege_exception",
		"approval_result":"approved"
	}`
	createReq := httptest.NewRequest(http.MethodPost, "/admin/human-approval-events", strings.NewReader(body))
	createReq.Header.Set("content-type", "application/json")
	createRec := httptest.NewRecorder()

	handler.ServeHTTP(createRec, createReq)

	if createRec.Code != http.StatusOK {
		t.Fatalf("create status = %d, want %d, body=%s", createRec.Code, http.StatusOK, createRec.Body.String())
	}
	var created adminHumanApprovalEvent
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created human approval: %v", err)
	}
	if created.ID != "hae_admin_001" || created.TenantID != "tenant_lab_001" || created.ApprovalResult != "approved" || created.ActivatedAt == nil || created.ExpiresAt == nil || created.CreatedAt == "" {
		t.Fatalf("created human approval = %#v, want normalized approved event", created)
	}
	if len(created.RequestedScopes) != 2 || created.ActorNHIID == nil || *created.ActorNHIID != "nhi_soc_agent_001" {
		t.Fatalf("created human approval = %#v, want deduped scopes and actor ref", created)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/admin/human-approval-events?approval_result=approved&actor_nhi_id=nhi_soc_agent_001&limit=10", nil)
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want %d, body=%s", listRec.Code, http.StatusOK, listRec.Body.String())
	}
	var list adminHumanApprovalEventListResponse
	if err := json.Unmarshal(listRec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode human approval list: %v", err)
	}
	if list.Count != 1 || len(list.Approvals) != 1 || list.Approvals[0].ID != created.ID {
		t.Fatalf("human approval list = %#v, want created approved event", list)
	}

	detailReq := httptest.NewRequest(http.MethodGet, "/admin/human-approval-events/hae_admin_001", nil)
	detailRec := httptest.NewRecorder()
	handler.ServeHTTP(detailRec, detailReq)
	if detailRec.Code != http.StatusOK {
		t.Fatalf("detail status = %d, want %d, body=%s", detailRec.Code, http.StatusOK, detailRec.Body.String())
	}

	revokeReq := httptest.NewRequest(http.MethodPost, "/admin/human-approval-events/hae_admin_001/revoke", strings.NewReader(`{"reason_code":"operator_revoked"}`))
	revokeRec := httptest.NewRecorder()
	handler.ServeHTTP(revokeRec, revokeReq)
	if revokeRec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, want %d, body=%s", revokeRec.Code, http.StatusOK, revokeRec.Body.String())
	}
	var revoked adminHumanApprovalEvent
	if err := json.Unmarshal(revokeRec.Body.Bytes(), &revoked); err != nil {
		t.Fatalf("decode revoked human approval: %v", err)
	}
	if revoked.ApprovalResult != "revoked" || revoked.ReasonCode == nil || *revoked.ReasonCode != "operator_revoked" {
		t.Fatalf("revoked human approval = %#v, want revoked with reason code", revoked)
	}

	if len(outbox.insertedAudits) != 2 || outbox.insertedAudits[0].EventType != "admin_human_approval_event_upserted" || outbox.insertedAudits[1].EventType != "admin_human_approval_event_revoked" {
		t.Fatalf("outbox inserted audits = %#v, want human approval upsert/revoke", outbox.insertedAudits)
	}
	for _, audit := range outbox.insertedAudits {
		if audit.SourceIP != nil || audit.ActorNHIID != nil || audit.ActorUserID == nil || *audit.ActorUserID == "approver_lab_001" || *audit.ActorUserID == "user_lab_001" {
			t.Fatalf("human approval audit must name the administrator without copying the approval subject/source: %#v", audit)
		}
		if audit.Metadata["human_approval_metadata_recorded_scope"] != "none" || audit.Metadata["notification_sent"] != false || audit.Metadata["runtime_hot_reload"] != false {
			t.Fatalf("human approval audit metadata = %#v, want non-secret admin boundary", audit.Metadata)
		}
	}
}

func TestAdminHumanApprovalEventAPIRejectsTenantMismatch(t *testing.T) {
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		AdminAuth: newAdminAuthStore(),
	})
	body := `{"id":"hae_other_001","tenant_id":"tenant_other_001","approval_source":"admin_console","approver_user_id":"approver_lab_001","actor_nhi_id":"nhi_soc_agent_001","action_type":"ticket:create","approval_result":"approved"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/human-approval-events", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "tenant_id") {
		t.Fatalf("status = %d body=%s, want tenant mismatch bad request", rec.Code, rec.Body.String())
	}
}

func TestAdminHumanApprovalEventAPIRequiresWriteScopeForAPIToken(t *testing.T) {
	adminAuth := newAdminAuthStore()
	adminAuth.UpsertPrincipal(adminPrincipal{
		ID:        "admin_human_approval_reader_001",
		TenantID:  "tenant_lab_001",
		Subject:   "sub_human_approval_reader_001",
		Email:     "human-approval-reader@example.test",
		Roles:     []string{"admin"},
		IDPID:     "keycloak_lab",
		Status:    "active",
		CreatedAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
	})
	adminAuth.UpsertAPIToken(adminAPIToken{
		ID:                        "admin_token_human_approval_reader_001",
		TenantID:                  "tenant_lab_001",
		Name:                      "human-approval-reader-token",
		TokenHash:                 adminTokenHash("raw-human-approval-reader-token"),
		Roles:                     []string{"admin"},
		Scopes:                    []string{"admin.approval.read"},
		CreatedByAdminPrincipalID: "admin_human_approval_reader_001",
		CreatedAt:                 time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt:                 time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		Status:                    "active",
	})
	store := newHumanApprovalEventStore()
	_, err := adminUpsertHumanApprovalEvent(store, nil, adminHumanApprovalEvent{
		ID:             "hae_scope_denied_001",
		TenantID:       "tenant_lab_001",
		ApprovalSource: "admin_console",
		ApproverUserID: stringPtr("approver_lab_001"),
		ActorNHIID:     stringPtr("nhi_soc_agent_001"),
		ActionType:     stringPtr("ticket:create"),
		ApprovalResult: "approved",
	}, "tenant_lab_001", time.Now())
	if err != nil {
		t.Fatalf("seed human approval: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Registry:         connector.NewRegistry(),
		AdminAuth:        adminAuth,
		HumanApprovals:   store,
		AdminAuditOutbox: &recordingAdminAuditOutboxDeadReader{},
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/human-approval-events/hae_scope_denied_001/revoke", strings.NewReader(`{"reason_code":"scope_denied_fixture"}`))
	req.Header.Set("authorization", "Bearer raw-human-approval-reader-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "admin api token scope admin.approval.write is required") {
		t.Fatalf("status = %d body=%s, want write scope denial", rec.Code, rec.Body.String())
	}
}
