package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tunnel"
)

func TestBreakGlassSessionCreatesDecisionContext(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	evaluator := testEvaluator()
	breakGlassIdentityID := "bg_identity_lab_001"
	breakGlassMaxSessionSeconds := 900
	evaluator.Policies = append([]model.Policy{
		{
			ID:                           "pol_lab_break_glass_allow_001",
			TenantID:                     "tenant_lab_001",
			Priority:                     40,
			BreakGlassPolicy:             true,
			BreakGlassIdentityID:         &breakGlassIdentityID,
			BreakGlassMaxSessionSeconds:  &breakGlassMaxSessionSeconds,
			BreakGlassStrongAuthRequired: true,
			BreakGlassAuditRequired:      true,
			Conditions: map[string]any{
				"actor_type":     "human",
				"application_id": "app_recovery_console",
				"service_family": "https",
				"auth_method":    "break_glass",
			},
			Action: model.PolicyAction{Decision: "allow"},
			Status: "active",
		},
	}, evaluator.Policies...)
	domainOutbox := &recordingDomainEventOutbox{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:         evaluator,
		Writer:            writer,
		Registry:          connector.NewRegistry(),
		ProxyClient:       http.DefaultClient,
		ConnectorSecret:   defaultConnectorSecret,
		TunnelManager:     tunnel.NewManager(),
		SessionStore:      sessionStoreForTest(),
		DomainEventOutbox: domainOutbox,
	})

	createReq := httptest.NewRequest(http.MethodPost, "/break-glass/sessions", strings.NewReader(`{
		"tenant_id":"tenant_lab_001",
		"user_id":"admin_lab_001",
		"device_id":"dev_admin_001",
		"reason":"ransomware exercise recovery",
		"ticket_id":"INC-20260522-001",
		"duration_seconds":900
	}`))
	createRec := httptest.NewRecorder()
	handler.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("break-glass status = %d, want %d, body=%s", createRec.Code, http.StatusCreated, createRec.Body.String())
	}
	var session model.Session
	if err := json.NewDecoder(createRec.Body).Decode(&session); err != nil {
		t.Fatalf("decode session response: %v", err)
	}
	if session.Metadata["auth_method"] != "break_glass" || session.Metadata["break_glass_reason"] == "" {
		t.Fatalf("session metadata = %#v", session.Metadata)
	}

	decisionReq := httptest.NewRequest(http.MethodPost, "/decisions/evaluate", strings.NewReader(`{
		"session_id":"`+session.ID+`",
		"actor_type":"human",
		"application_id":"app_recovery_console",
		"application_sensitivity":"high",
		"destination":"recovery-console.local",
		"destination_port":8443,
		"protocol":"tcp",
		"service_family":"https",
		"connection_initiator":"client",
		"source_role":"managed_endpoint",
		"destination_role":"private_app"
	}`))
	decisionRec := httptest.NewRecorder()
	handler.ServeHTTP(decisionRec, decisionReq)
	if decisionRec.Code != http.StatusOK {
		t.Fatalf("decision status = %d, want %d, body=%s", decisionRec.Code, http.StatusOK, decisionRec.Body.String())
	}
	var dec model.AccessDecision
	if err := json.NewDecoder(decisionRec.Body).Decode(&dec); err != nil {
		t.Fatalf("decode decision response: %v", err)
	}
	if dec.PolicyID != "pol_lab_break_glass_allow_001" {
		t.Fatalf("policy_id = %q, want break-glass policy", dec.PolicyID)
	}
	if dec.Metadata["auth_method"] != "break_glass" {
		t.Fatalf("decision metadata = %#v", dec.Metadata)
	}

	exportReq := httptest.NewRequest(http.MethodGet, "/break-glass/events/export", nil)
	exportRec := httptest.NewRecorder()
	handler.ServeHTTP(exportRec, exportReq)
	if exportRec.Code != http.StatusOK {
		t.Fatalf("break-glass export status = %d, want %d, body=%s", exportRec.Code, http.StatusOK, exportRec.Body.String())
	}
	exportBody := exportRec.Body.String()
	for _, want := range []string{"break_glass_session_issued", "break_glass_session_used", session.ID, dec.ID, "INC-20260522-001"} {
		if !strings.Contains(exportBody, want) {
			t.Fatalf("break-glass export = %s, want %s", exportBody, want)
		}
	}
	accessLog, err := os.ReadFile(filepath.Join(logDir, "access.log.jsonl"))
	if err != nil {
		t.Fatalf("read access log: %v", err)
	}
	if !strings.Contains(string(accessLog), `"auth_method":"break_glass"`) {
		t.Fatalf("access log = %s, want break_glass auth_method", string(accessLog))
	}
	auditLog, err := os.ReadFile(filepath.Join(logDir, "audit.log.jsonl"))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if !strings.Contains(string(auditLog), "break_glass_exported") {
		t.Fatalf("audit log = %s, want break_glass_exported", string(auditLog))
	}
	if !strings.Contains(string(auditLog), "break_glass_session_used") {
		t.Fatalf("audit log = %s, want break_glass_session_used", string(auditLog))
	}
}

func TestBreakGlassRequestApproveIssueSessionFlow(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	evaluator := testEvaluator()
	breakGlassIdentityID := "bg_identity_lab_001"
	breakGlassMaxSessionSeconds := 900
	evaluator.Policies = append([]model.Policy{
		{
			ID:                           "pol_lab_break_glass_allow_001",
			TenantID:                     "tenant_lab_001",
			Priority:                     40,
			BreakGlassPolicy:             true,
			BreakGlassIdentityID:         &breakGlassIdentityID,
			BreakGlassMaxSessionSeconds:  &breakGlassMaxSessionSeconds,
			BreakGlassStrongAuthRequired: true,
			BreakGlassAuditRequired:      true,
			Conditions: map[string]any{
				"actor_type":     "human",
				"application_id": "app_recovery_console",
				"service_family": "https",
				"auth_method":    "break_glass",
			},
			Action: model.PolicyAction{Decision: "allow"},
			Status: "active",
		},
	}, evaluator.Policies...)
	domainOutbox := &recordingDomainEventOutbox{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:         evaluator,
		Writer:            writer,
		Registry:          connector.NewRegistry(),
		ProxyClient:       http.DefaultClient,
		ConnectorSecret:   defaultConnectorSecret,
		TunnelManager:     tunnel.NewManager(),
		SessionStore:      sessionStoreForTest(),
		DomainEventOutbox: domainOutbox,
	})

	createReq := httptest.NewRequest(http.MethodPost, "/break-glass/requests", strings.NewReader(`{
		"tenant_id":"tenant_lab_001",
		"user_id":"admin_lab_001",
		"subject_user_id":"admin_lab_001",
		"device_id":"dev_admin_001",
		"reason":"ransomware exercise recovery",
		"ticket_id":"INC-20260522-002",
		"duration_seconds":900
	}`))
	createRec := httptest.NewRecorder()
	handler.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("request status = %d, want %d, body=%s", createRec.Code, http.StatusCreated, createRec.Body.String())
	}
	var bgRequest breakGlassAccessRequest
	if err := json.NewDecoder(createRec.Body).Decode(&bgRequest); err != nil {
		t.Fatalf("decode request response: %v", err)
	}
	if bgRequest.Status != "requested" || bgRequest.ID == "" {
		t.Fatalf("break-glass request = %+v", bgRequest)
	}

	approveReq := httptest.NewRequest(http.MethodPost, "/break-glass/requests/"+bgRequest.ID+"/approve", strings.NewReader(`{
		"approver_user_id":"approver_lab_001",
		"reason":"exercise approved"
	}`))
	approveRec := httptest.NewRecorder()
	handler.ServeHTTP(approveRec, approveReq)
	if approveRec.Code != http.StatusOK {
		t.Fatalf("approve status = %d, want %d, body=%s", approveRec.Code, http.StatusOK, approveRec.Body.String())
	}
	var approved breakGlassAccessRequest
	if err := json.NewDecoder(approveRec.Body).Decode(&approved); err != nil {
		t.Fatalf("decode approve response: %v", err)
	}
	if approved.Status != "approved" || approved.ApproverUserID != "approver_lab_001" {
		t.Fatalf("approved request = %+v", approved)
	}

	issueReq := httptest.NewRequest(http.MethodPost, "/break-glass/requests/"+bgRequest.ID+"/issue-session", nil)
	issueRec := httptest.NewRecorder()
	handler.ServeHTTP(issueRec, issueReq)
	if issueRec.Code != http.StatusCreated {
		t.Fatalf("issue status = %d, want %d, body=%s", issueRec.Code, http.StatusCreated, issueRec.Body.String())
	}
	var session model.Session
	if err := json.NewDecoder(issueRec.Body).Decode(&session); err != nil {
		t.Fatalf("decode issue response: %v", err)
	}
	if session.Metadata["auth_method"] != "break_glass" || !strings.HasPrefix(session.ID, "sess_bg_") {
		t.Fatalf("issued session = %+v", session)
	}

	decisionReq := httptest.NewRequest(http.MethodPost, "/decisions/evaluate", strings.NewReader(`{
		"session_id":"`+session.ID+`",
		"actor_type":"human",
		"application_id":"app_recovery_console",
		"application_sensitivity":"high",
		"destination":"recovery-console.local",
		"destination_port":8443,
		"protocol":"tcp",
		"service_family":"https",
		"connection_initiator":"client",
		"source_role":"managed_endpoint",
		"destination_role":"private_app"
	}`))
	decisionRec := httptest.NewRecorder()
	handler.ServeHTTP(decisionRec, decisionReq)
	if decisionRec.Code != http.StatusOK {
		t.Fatalf("decision status = %d, want %d, body=%s", decisionRec.Code, http.StatusOK, decisionRec.Body.String())
	}

	exportReq := httptest.NewRequest(http.MethodGet, "/break-glass/events/export", nil)
	exportRec := httptest.NewRecorder()
	handler.ServeHTTP(exportRec, exportReq)
	if exportRec.Code != http.StatusOK {
		t.Fatalf("export status = %d, want %d, body=%s", exportRec.Code, http.StatusOK, exportRec.Body.String())
	}
	exportBody := exportRec.Body.String()
	if strings.Count(exportBody, "break_glass_session_issued") != 1 {
		t.Fatalf("export body = %s, want one session issued event", exportBody)
	}
	for _, want := range []string{bgRequest.ID, "break_glass_session_used", "INC-20260522-002"} {
		if !strings.Contains(exportBody, want) {
			t.Fatalf("export body = %s, want %s", exportBody, want)
		}
	}
	domainEvents := domainOutbox.insertedEvents()
	counts := map[string]int{}
	for _, event := range domainEvents {
		counts[event.Stream]++
	}
	if counts["break_glass_events"] != 3 || counts["authentication_events"] != 1 || counts["access_logs"] != 1 || counts["decision_traces"] != 0 {
		t.Fatalf("domain event counts = %#v from events %#v", counts, domainEvents)
	}
}

func TestBreakGlassDirectSessionRequiresAdminAuthWhenLabModeDisabled(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Writer:    writer,
		LabMode:   boolPtr(false),
	})

	req := httptest.NewRequest(http.MethodPost, "/break-glass/sessions", strings.NewReader(`{
		"tenant_id":"tenant_lab_001",
		"user_id":"user_lab_001",
		"reason":"incident response"
	}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}
