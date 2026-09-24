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

func TestAdminDelegatedAccessGrantOpenAPIContract(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "openapi", "admin_api.yaml"))
	if err != nil {
		t.Fatalf("read admin OpenAPI contract: %v", err)
	}
	contract := string(data)
	for _, want := range []string{
		"    DelegatedAccessGrant:",
		"    DelegatedAccessGrantList:",
		"    DelegatedAccessGrantRevokeRequest:",
		"  /admin/delegated-grants:",
		"  /admin/delegated-grants/{grant_id}:",
		"  /admin/delegated-grants/{grant_id}/revoke:",
		"admin.delegated_grants.read",
		"admin.delegated_grants.write",
		"admin.delegated_grants.revoke",
		`$ref: "#/components/schemas/DelegatedAccessGrantList"`,
		`$ref: "#/components/schemas/DelegatedAccessGrant"`,
		`$ref: "#/components/schemas/DelegatedAccessGrantRevokeRequest"`,
	} {
		if !strings.Contains(contract, want) {
			t.Fatalf("admin OpenAPI contract missing %q", want)
		}
	}
}

func TestAdminDelegatedAccessGrantAPIUpsertListDetailAndRevoke(t *testing.T) {
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
		"id":"dag_admin_001",
		"tenant_id":"tenant_lab_001",
		"subject_user_id":"user_lab_001",
		"actor_nhi_id":"nhi_soc_agent_001",
		"application_id":"app_dummy_https",
		"audience":"service_desk",
		"resource":"ticket_queue",
		"scopes":["ticket:write","ticket:read","ticket:write"],
		"purpose":"incident_response",
		"task_id":"task_admin_001",
		"run_id":"run_admin_001",
		"tool_ids":["tool_ticket_create_001"],
		"approval_event_id":"hae_admin_001",
		"token_binding_required":true,
		"max_session_duration":1200,
		"status":"active"
	}`
	createReq := httptest.NewRequest(http.MethodPost, "/admin/delegated-grants", strings.NewReader(body))
	createReq.Header.Set("content-type", "application/json")
	createRec := httptest.NewRecorder()

	handler.ServeHTTP(createRec, createReq)

	if createRec.Code != http.StatusOK {
		t.Fatalf("create status = %d, want %d, body=%s", createRec.Code, http.StatusOK, createRec.Body.String())
	}
	var created adminDelegatedAccessGrant
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created delegated grant: %v", err)
	}
	if created.ID != "dag_admin_001" || created.TenantID != "tenant_lab_001" || created.Status != "active" || created.ExpiresAt == "" || created.CreatedAt == nil {
		t.Fatalf("created delegated grant = %#v, want normalized active grant", created)
	}
	if len(created.Scopes) != 2 || len(created.ToolIDs) != 1 || !created.TokenBindingRequired {
		t.Fatalf("created delegated grant = %#v, want deduped scopes/tool metadata", created)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/admin/delegated-grants?status=active&actor_nhi_id=nhi_soc_agent_001&limit=10", nil)
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want %d, body=%s", listRec.Code, http.StatusOK, listRec.Body.String())
	}
	var list adminDelegatedAccessGrantListResponse
	if err := json.Unmarshal(listRec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode delegated grant list: %v", err)
	}
	if list.Count != 1 || len(list.Grants) != 1 || list.Grants[0].ID != created.ID {
		t.Fatalf("delegated grant list = %#v, want created active grant", list)
	}

	detailReq := httptest.NewRequest(http.MethodGet, "/admin/delegated-grants/dag_admin_001", nil)
	detailRec := httptest.NewRecorder()
	handler.ServeHTTP(detailRec, detailReq)
	if detailRec.Code != http.StatusOK {
		t.Fatalf("detail status = %d, want %d, body=%s", detailRec.Code, http.StatusOK, detailRec.Body.String())
	}

	revokeReq := httptest.NewRequest(http.MethodPost, "/admin/delegated-grants/dag_admin_001/revoke", strings.NewReader(`{"revocation_reason_code":"operator_revoked"}`))
	revokeRec := httptest.NewRecorder()
	handler.ServeHTTP(revokeRec, revokeReq)
	if revokeRec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, want %d, body=%s", revokeRec.Code, http.StatusOK, revokeRec.Body.String())
	}
	var revoked adminDelegatedAccessGrant
	if err := json.Unmarshal(revokeRec.Body.Bytes(), &revoked); err != nil {
		t.Fatalf("decode revoked delegated grant: %v", err)
	}
	if revoked.Status != "revoked" || revoked.RevokedAt == nil || revoked.RevocationReasonCode == nil || *revoked.RevocationReasonCode != "operator_revoked" {
		t.Fatalf("revoked delegated grant = %#v, want revoked with reason code", revoked)
	}

	if len(outbox.insertedAudits) != 2 || outbox.insertedAudits[0].EventType != "admin_delegated_access_grant_upserted" || outbox.insertedAudits[1].EventType != "admin_delegated_access_grant_revoked" {
		t.Fatalf("outbox inserted audits = %#v, want delegated grant upsert/revoke", outbox.insertedAudits)
	}
	for _, audit := range outbox.insertedAudits {
		if audit.SourceIP != nil || audit.ActorUserID == nil || *audit.ActorUserID == "" {
			t.Fatalf("delegated grant audit must identify the acting administrator and omit raw source fields: %#v", audit)
		}
		if audit.Metadata["delegated_grant_metadata_recorded_scope"] != "none" || audit.Metadata["delegated_token_issued"] != false || audit.Metadata["runtime_hot_reload"] != false {
			t.Fatalf("delegated grant audit metadata = %#v, want non-secret admin boundary", audit.Metadata)
		}
	}
}

func TestAdminDelegatedAccessGrantAPIRejectsTenantMismatch(t *testing.T) {
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		AdminAuth: newAdminAuthStore(),
	})
	body := `{"id":"dag_other_001","tenant_id":"tenant_other_001","subject_user_id":"user_lab_001","actor_nhi_id":"nhi_soc_agent_001","status":"active"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/delegated-grants", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "tenant_id") {
		t.Fatalf("status = %d body=%s, want tenant mismatch bad request", rec.Code, rec.Body.String())
	}
}

func TestAdminDelegatedAccessGrantAPIRequiresRevokeScopeForAPIToken(t *testing.T) {
	adminAuth := newAdminAuthStore()
	adminAuth.UpsertPrincipal(adminPrincipal{
		ID:        "admin_delegated_grant_reader_001",
		TenantID:  "tenant_lab_001",
		Subject:   "sub_delegated_grant_reader_001",
		Email:     "delegated-grant-reader@example.test",
		Roles:     []string{"admin"},
		IDPID:     "keycloak_lab",
		Status:    "active",
		CreatedAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
	})
	adminAuth.UpsertAPIToken(adminAPIToken{
		ID:                        "admin_token_delegated_grant_reader_001",
		TenantID:                  "tenant_lab_001",
		Name:                      "delegated-grant-reader-token",
		TokenHash:                 adminTokenHash("raw-delegated-grant-reader-token"),
		Roles:                     []string{"admin"},
		Scopes:                    []string{"admin.delegated_grants.read"},
		CreatedByAdminPrincipalID: "admin_delegated_grant_reader_001",
		CreatedAt:                 time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt:                 time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		Status:                    "active",
	})
	store := newDelegatedAccessGrantStore()
	_, err := adminUpsertDelegatedAccessGrant(store, nil, adminDelegatedAccessGrant{
		ID:            "dag_scope_denied_001",
		TenantID:      "tenant_lab_001",
		SubjectUserID: "user_lab_001",
		ActorNHIID:    "nhi_soc_agent_001",
		Status:        "active",
	}, "tenant_lab_001", time.Now())
	if err != nil {
		t.Fatalf("seed delegated grant: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Registry:         connector.NewRegistry(),
		AdminAuth:        adminAuth,
		DelegatedGrants:  store,
		AdminAuditOutbox: &recordingAdminAuditOutboxDeadReader{},
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/delegated-grants/dag_scope_denied_001/revoke", strings.NewReader(`{"revocation_reason_code":"scope_denied_fixture"}`))
	req.Header.Set("authorization", "Bearer raw-delegated-grant-reader-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "admin api token scope admin.delegated_grants.revoke is required") {
		t.Fatalf("status = %d body=%s, want revoke scope denial", rec.Code, rec.Body.String())
	}
}
