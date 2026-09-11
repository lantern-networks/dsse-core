package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	nhi "github.com/lantern-networks/dsse-core/nhi"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

func TestDelegatedGrantRequiresRegisteredActiveNHIWhenRegistryPopulated(t *testing.T) {
	now := time.Date(2026, 5, 24, 1, 2, 3, 0, time.UTC)
	nhiRegistry := nhi.NewStore()
	if _, err := nhiRegistry.Upsert(context.Background(), model.NonHumanIdentity{
		ID:          "nhi_known_001",
		Name:        "Known Agent",
		NHIType:     "ai_agent",
		OwnerUserID: "user_owner_001",
		Status:      "active",
	}, "tenant_lab_001", now); err != nil {
		t.Fatalf("upsert known NHI returned error: %v", err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:          testEvaluator(),
		Writer:             writer,
		NonHumanIdentities: nhiRegistry,
	})

	body := `{
		"id":"dag_unknown_nhi_001",
		"tenant_id":"tenant_lab_001",
		"subject_user_id":"user_lab_001",
		"actor_nhi_id":"nhi_unknown_001",
		"expires_at":"2030-01-01T00:00:00Z",
		"status":"active",
		"metadata":{}
	}`
	req := httptest.NewRequest(http.MethodPost, "/delegated-grants", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
}

func TestHumanApprovalAndToolCallRejectInactiveNHIWhenRegistryPopulated(t *testing.T) {
	now := time.Now().UTC()
	nhiRegistry := nhi.NewStore()
	if _, err := nhiRegistry.Upsert(context.Background(), model.NonHumanIdentity{
		ID:          "nhi_inactive_001",
		Name:        "Inactive Agent",
		NHIType:     "ai_agent",
		OwnerUserID: "user_owner_001",
		Status:      "suspended",
	}, "tenant_lab_001", now); err != nil {
		t.Fatalf("upsert inactive NHI returned error: %v", err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:          testEvaluator(),
		Writer:             writer,
		NonHumanIdentities: nhiRegistry,
	})

	approvalBody := `{
		"id":"hae_inactive_nhi_001",
		"tenant_id":"tenant_lab_001",
		"approval_source":"admin_console",
		"approver_user_id":"approver_lab_001",
		"actor_nhi_id":"nhi_inactive_001",
		"action_type":"ticket:create",
		"approval_result":"approved",
		"metadata":{}
	}`
	approvalReq := httptest.NewRequest(http.MethodPost, "/human-approvals/events", strings.NewReader(approvalBody))
	approvalRec := httptest.NewRecorder()
	handler.ServeHTTP(approvalRec, approvalReq)
	if approvalRec.Code != http.StatusForbidden {
		t.Fatalf("approval status = %d, want %d, body=%s", approvalRec.Code, http.StatusForbidden, approvalRec.Body.String())
	}

	toolBody := `{
		"id":"tce_inactive_nhi_001",
		"tenant_id":"tenant_lab_001",
		"actor_nhi_id":"nhi_inactive_001",
		"tool_id":"tool_ticket_create_001",
		"action_type":"ticket:create",
		"timestamp":"2026-05-22T00:01:00Z",
		"metadata":{}
	}`
	toolReq := httptest.NewRequest(http.MethodPost, "/tools/events", strings.NewReader(toolBody))
	toolRec := httptest.NewRecorder()
	handler.ServeHTTP(toolRec, toolReq)
	if toolRec.Code != http.StatusForbidden {
		t.Fatalf("tool status = %d, want %d, body=%s", toolRec.Code, http.StatusForbidden, toolRec.Body.String())
	}
}

func TestHumanApprovalEventWriterAndLookup(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	domainOutbox := &recordingDomainEventOutbox{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:         testEvaluator(),
		Writer:            writer,
		Registry:          connector.NewRegistry(),
		DomainEventOutbox: domainOutbox,
	})
	body := `{
		"tenant_id":"tenant_lab_001",
		"approver_user_id":"approver_lab_001",
		"subject_user_id":"user_lab_001",
		"actor_nhi_id":"nhi_soc_agent_001",
		"delegated_access_grant_id":"dag_lab_001",
		"agent_task_session_id":"ats_lab_001",
		"application_id":"app_dummy_https",
		"audience":"https://mcp.local/soc",
		"resource":"incident/inc_lab_001",
		"action_type":"ticket:create",
		"requested_scopes":["incident:read","ticket:create"],
		"reason":"Approved for ransomware investigation exercise",
		"approval_result":"approved",
		"metadata":{"approval_ttl_seconds":120}
	}`
	req := httptest.NewRequest(http.MethodPost, "/human-approvals/events", strings.NewReader(body))
	req.RemoteAddr = "192.0.2.20:54000"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	var event model.HumanApprovalEvent
	if err := json.NewDecoder(rec.Body).Decode(&event); err != nil {
		t.Fatalf("decode human approval response: %v", err)
	}
	if !strings.HasPrefix(event.ID, "hae_") || event.ApprovalSource != "admin_console" {
		t.Fatalf("event = %#v, want generated id and admin_console source", event)
	}
	if event.ExpiresAt == nil || *event.ExpiresAt == "" || event.ActivatedAt == nil || *event.ActivatedAt == "" {
		t.Fatalf("event = %#v, want activated_at and expires_at", event)
	}
	rows, err := writer.ReadJSONL("human_approval_events.log.jsonl")
	if err != nil {
		t.Fatalf("read human approval log: %v", err)
	}
	if len(rows) != 1 || rows[0]["id"] != event.ID || rows[0]["actor_nhi_id"] != "nhi_soc_agent_001" {
		t.Fatalf("human approval rows = %#v", rows)
	}
	domainEvents := domainOutbox.insertedEvents()
	if len(domainEvents) != 1 || domainEvents[0].Stream != "human_approval_events" || domainEvents[0].EventType != "human_approval_event_recorded" || domainEvents[0].Metadata["source_event_id"] != event.ID {
		t.Fatalf("domain events = %#v", domainEvents)
	}
	auditRows, err := readAuditRowsExcludingWrapper(writer)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if len(auditRows) != 1 || auditRows[0]["event_type"] != "human_approval_event_recorded" {
		t.Fatalf("audit rows = %#v", auditRows)
	}
	if auditRows[0]["source_ip"] != nil || auditRows[0]["actor_user_id"] != nil || auditRows[0]["actor_nhi_id"] != nil {
		t.Fatalf("human approval audit included raw source/actor fields: %#v", auditRows[0])
	}
	if metadata, ok := auditRows[0]["metadata"].(map[string]any); !ok || metadata["human_approval_metadata_recorded_scope"] != "none" {
		t.Fatalf("human approval audit metadata = %#v, want scope none", auditRows[0]["metadata"])
	}
	if encoded, err := json.Marshal(auditRows[0]); err != nil {
		t.Fatalf("marshal human approval audit row: %v", err)
	} else {
		for _, leaked := range []string{"approver_lab_001", "nhi_soc_agent_001", "user_lab_001", "Approved for ransomware investigation exercise", "incident:read", "ticket:create"} {
			if strings.Contains(string(encoded), leaked) {
				t.Fatalf("human approval audit leaked %q: %s", leaked, string(encoded))
			}
		}
	}

	getReq := httptest.NewRequest(http.MethodGet, "/human-approvals/events/"+event.ID, nil)
	getRec := httptest.NewRecorder()
	handler.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("lookup status = %d, want %d, body=%s", getRec.Code, http.StatusOK, getRec.Body.String())
	}
	if !strings.Contains(getRec.Body.String(), event.ID) {
		t.Fatalf("lookup body = %s, want event id", getRec.Body.String())
	}
}

func TestHumanApprovalEventRejectsTenantMismatch(t *testing.T) {
	handler := newTestHandler(t)
	body := `{
		"tenant_id":"tenant_other",
		"approver_user_id":"approver_lab_001",
		"actor_nhi_id":"nhi_soc_agent_001",
		"action_type":"ticket:create",
		"approval_result":"approved"
	}`
	req := httptest.NewRequest(http.MethodPost, "/human-approvals/events", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

func TestHumanApprovalEventDomainOutboxFailureDoesNotBlock(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:         testEvaluator(),
		Writer:            writer,
		Registry:          connector.NewRegistry(),
		DomainEventOutbox: &recordingDomainEventOutbox{err: fmt.Errorf("domain outbox down")},
	})
	body := `{
		"id":"hae_outbox_down_001",
		"tenant_id":"tenant_lab_001",
		"approver_user_id":"approver_lab_001",
		"actor_nhi_id":"nhi_soc_agent_001",
		"action_type":"ticket:create",
		"approval_result":"approved",
		"metadata":{}
	}`
	req := httptest.NewRequest(http.MethodPost, "/human-approvals/events", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	rows, err := writer.ReadJSONL("human_approval_events.log.jsonl")
	if err != nil {
		t.Fatalf("read human approval log: %v", err)
	}
	if len(rows) != 1 || rows[0]["id"] != "hae_outbox_down_001" {
		t.Fatalf("human approval rows = %#v", rows)
	}
}

func TestHumanApprovalEventRejectsRevokedToApprovedReversal(t *testing.T) {
	handler := newTestHandler(t)
	approved := `{
		"id":"hae_state_001",
		"tenant_id":"tenant_lab_001",
		"approver_user_id":"approver_lab_001",
		"actor_nhi_id":"nhi_soc_agent_001",
		"action_type":"ticket:create",
		"approval_result":"approved",
		"metadata":{}
	}`
	revoked := `{
		"id":"hae_state_001",
		"tenant_id":"tenant_lab_001",
		"actor_nhi_id":"nhi_soc_agent_001",
		"action_type":"ticket:create",
		"approval_result":"revoked",
		"metadata":{}
	}`

	for _, body := range []string{approved, revoked} {
		req := httptest.NewRequest(http.MethodPost, "/human-approvals/events", strings.NewReader(body))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusAccepted, rec.Body.String())
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/human-approvals/events", strings.NewReader(approved))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusConflict, rec.Body.String())
	}
}

func TestHumanApprovalEventCapsGeneratedTTL(t *testing.T) {
	handler := newTestHandler(t)
	body := `{
		"id":"hae_ttl_001",
		"tenant_id":"tenant_lab_001",
		"approver_user_id":"approver_lab_001",
		"actor_nhi_id":"nhi_soc_agent_001",
		"action_type":"ticket:create",
		"approval_result":"approved",
		"metadata":{"approval_ttl_seconds":999999999}
	}`
	req := httptest.NewRequest(http.MethodPost, "/human-approvals/events", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	var event model.HumanApprovalEvent
	if err := json.NewDecoder(rec.Body).Decode(&event); err != nil {
		t.Fatalf("decode human approval response: %v", err)
	}
	if event.ActivatedAt == nil || event.ExpiresAt == nil {
		t.Fatalf("event = %#v, want generated activated_at/expires_at", event)
	}
	activatedAt, err := time.Parse(time.RFC3339, *event.ActivatedAt)
	if err != nil {
		t.Fatalf("parse activated_at: %v", err)
	}
	expiresAt, err := time.Parse(time.RFC3339, *event.ExpiresAt)
	if err != nil {
		t.Fatalf("parse expires_at: %v", err)
	}
	if expiresAt.Sub(activatedAt) > maxHumanApprovalTTL {
		t.Fatalf("ttl = %s, want <= %s", expiresAt.Sub(activatedAt), maxHumanApprovalTTL)
	}
}

func TestHumanApprovalStoreGetActiveChecksExpiryAndStatus(t *testing.T) {
	store := newHumanApprovalEventStore()
	now := time.Date(2026, 5, 22, 10, 0, 0, 0, time.UTC)
	activeExpiresAt := now.Add(time.Minute).Format(time.RFC3339)
	expiredAt := now.Add(-time.Minute).Format(time.RFC3339)

	if _, err := store.Upsert(model.HumanApprovalEvent{ID: "hae_active", TenantID: "tenant_lab_001", ApprovalResult: "approved", ExpiresAt: &activeExpiresAt}); err != nil {
		t.Fatalf("upsert active returned error: %v", err)
	}
	if _, ok := store.GetActive("hae_active", now); !ok {
		t.Fatal("GetActive returned false for active approval")
	}
	if _, err := store.Upsert(model.HumanApprovalEvent{ID: "hae_expired", TenantID: "tenant_lab_001", ApprovalResult: "approved", ExpiresAt: &expiredAt}); err != nil {
		t.Fatalf("upsert expired returned error: %v", err)
	}
	if _, ok := store.GetActive("hae_expired", now); ok {
		t.Fatal("GetActive returned true for expired approval")
	}
	if _, err := store.Upsert(model.HumanApprovalEvent{ID: "hae_revoked", TenantID: "tenant_lab_001", ApprovalResult: "revoked"}); err != nil {
		t.Fatalf("upsert revoked returned error: %v", err)
	}
	if _, ok := store.GetActive("hae_revoked", now); ok {
		t.Fatal("GetActive returned true for revoked approval")
	}
}

func TestDelegatedGrantLifecycle(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	domainOutbox := &recordingDomainEventOutbox{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:         testEvaluator(),
		Writer:            writer,
		Registry:          connector.NewRegistry(),
		DomainEventOutbox: domainOutbox,
	})
	body := `{
		"tenant_id":"tenant_lab_001",
		"subject_user_id":"user_lab_001",
		"actor_nhi_id":"nhi_soc_agent_001",
		"application_id":"app_dummy_https",
		"audience":"https://mcp.local/soc",
		"resource":"incident/inc_lab_001",
		"scopes":["incident:read","ticket:create"],
		"purpose":"ransomware_investigation_assistance",
		"tool_ids":["tool_ticket_create_001"],
		"approval_event_id":"hae_lab_001",
		"token_binding_required":true,
		"max_session_duration":120,
		"metadata":{"grant_type":"human_delegated_agent_task"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/delegated-grants", strings.NewReader(body))
	req.RemoteAddr = "192.0.2.30:55000"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	var grant model.DelegatedAccessGrant
	if err := json.NewDecoder(rec.Body).Decode(&grant); err != nil {
		t.Fatalf("decode delegated grant response: %v", err)
	}
	if !strings.HasPrefix(grant.ID, "dag_") || grant.Status != "active" || grant.ExpiresAt == "" {
		t.Fatalf("grant = %#v, want generated id, active status, expires_at", grant)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/delegated-grants/"+grant.ID, nil)
	getRec := httptest.NewRecorder()
	handler.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("lookup status = %d, want %d, body=%s", getRec.Code, http.StatusOK, getRec.Body.String())
	}

	revokeReq := httptest.NewRequest(http.MethodPost, "/delegated-grants/"+grant.ID+"/revoke", strings.NewReader(`{"revocation_reason":"exercise complete","revoked_by":"approver_lab_001"}`))
	revokeRec := httptest.NewRecorder()
	handler.ServeHTTP(revokeRec, revokeReq)
	if revokeRec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, want %d, body=%s", revokeRec.Code, http.StatusOK, revokeRec.Body.String())
	}
	var revoked model.DelegatedAccessGrant
	if err := json.NewDecoder(revokeRec.Body).Decode(&revoked); err != nil {
		t.Fatalf("decode revoked grant: %v", err)
	}
	if revoked.Status != "revoked" || revoked.RevokedAt == nil || revoked.RevocationReason == nil {
		t.Fatalf("revoked grant = %#v", revoked)
	}

	rows, err := writer.ReadJSONL("delegated_access_grants.log.jsonl")
	if err != nil {
		t.Fatalf("read delegated grants log: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("delegated grants rows = %#v, want create and revoke", rows)
	}
	auditRows, err := readAuditRowsExcludingWrapper(writer)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if len(auditRows) != 2 || auditRows[0]["event_type"] != "delegated_access_grant_recorded" || auditRows[1]["event_type"] != "delegated_access_grant_revoked" {
		t.Fatalf("audit rows = %#v", auditRows)
	}
	for _, auditRow := range auditRows {
		if auditRow["source_ip"] != nil || auditRow["actor_user_id"] != nil || auditRow["actor_nhi_id"] != nil {
			t.Fatalf("delegated grant audit included raw source/actor fields: %#v", auditRow)
		}
		if metadata, ok := auditRow["metadata"].(map[string]any); !ok || metadata["delegated_grant_metadata_recorded_scope"] != "none" {
			t.Fatalf("delegated grant audit metadata = %#v, want scope none", auditRow["metadata"])
		}
	}
	if encoded, err := json.Marshal(auditRows); err != nil {
		t.Fatalf("marshal delegated grant audit rows: %v", err)
	} else {
		for _, leaked := range []string{"user_lab_001", "nhi_soc_agent_001", "incident:read", "ticket:create", "incident/inc_lab_001", "exercise complete", "approver_lab_001"} {
			if strings.Contains(string(encoded), leaked) {
				t.Fatalf("delegated grant audit leaked %q: %s", leaked, string(encoded))
			}
		}
	}
	domainEvents := domainOutbox.insertedEvents()
	if len(domainEvents) != 2 || domainEvents[0].Stream != "delegated_access_grants" || domainEvents[1].EventType != "delegated_access_grant_revoked" {
		t.Fatalf("domain events = %#v", domainEvents)
	}
}

func TestDelegatedGrantRejectsRevokedToActiveReversal(t *testing.T) {
	handler := newTestHandler(t)
	active := `{
		"id":"dag_state_001",
		"tenant_id":"tenant_lab_001",
		"subject_user_id":"user_lab_001",
		"actor_nhi_id":"nhi_soc_agent_001",
		"expires_at":"2030-01-01T00:00:00Z",
		"status":"active",
		"metadata":{}
	}`
	createReq := httptest.NewRequest(http.MethodPost, "/delegated-grants", strings.NewReader(active))
	createRec := httptest.NewRecorder()
	handler.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusAccepted {
		t.Fatalf("create status = %d, want %d, body=%s", createRec.Code, http.StatusAccepted, createRec.Body.String())
	}

	revokeReq := httptest.NewRequest(http.MethodPost, "/delegated-grants/dag_state_001/revoke", strings.NewReader(`{"revocation_reason":"test"}`))
	revokeRec := httptest.NewRecorder()
	handler.ServeHTTP(revokeRec, revokeReq)
	if revokeRec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, want %d, body=%s", revokeRec.Code, http.StatusOK, revokeRec.Body.String())
	}

	recreateReq := httptest.NewRequest(http.MethodPost, "/delegated-grants", strings.NewReader(active))
	recreateRec := httptest.NewRecorder()
	handler.ServeHTTP(recreateRec, recreateReq)
	if recreateRec.Code != http.StatusConflict {
		t.Fatalf("recreate status = %d, want %d, body=%s", recreateRec.Code, http.StatusConflict, recreateRec.Body.String())
	}
}

func TestDelegatedGrantStoreGetActiveChecksExpiryAndStatus(t *testing.T) {
	store := newDelegatedAccessGrantStore()
	now := time.Date(2026, 5, 22, 10, 0, 0, 0, time.UTC)
	activeExpiresAt := now.Add(time.Minute).Format(time.RFC3339)
	expiredAt := now.Add(-time.Minute).Format(time.RFC3339)

	if _, err := store.Upsert(model.DelegatedAccessGrant{ID: "dag_active", TenantID: "tenant_lab_001", SubjectUserID: "user_lab_001", ActorNHIID: "nhi_soc_agent_001", Status: "active", ExpiresAt: activeExpiresAt}); err != nil {
		t.Fatalf("upsert active returned error: %v", err)
	}
	if _, ok := store.GetActive("dag_active", now); !ok {
		t.Fatal("GetActive returned false for active delegated grant")
	}
	if _, err := store.Upsert(model.DelegatedAccessGrant{ID: "dag_expired", TenantID: "tenant_lab_001", SubjectUserID: "user_lab_001", ActorNHIID: "nhi_soc_agent_001", Status: "active", ExpiresAt: expiredAt}); err != nil {
		t.Fatalf("upsert expired returned error: %v", err)
	}
	if _, ok := store.GetActive("dag_expired", now); ok {
		t.Fatal("GetActive returned true for expired delegated grant")
	}
	if _, err := store.Upsert(model.DelegatedAccessGrant{ID: "dag_revoked", TenantID: "tenant_lab_001", SubjectUserID: "user_lab_001", ActorNHIID: "nhi_soc_agent_001", Status: "revoked", ExpiresAt: activeExpiresAt}); err != nil {
		t.Fatalf("upsert revoked returned error: %v", err)
	}
	if _, ok := store.GetActive("dag_revoked", now); ok {
		t.Fatal("GetActive returned true for revoked delegated grant")
	}
}
