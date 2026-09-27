package main

import (
	"encoding/json"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/humanapproval"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAdminHumanApprovalPersistencePartialRetryAndTenantIsolation(t *testing.T) {
	for _, replaceBeforeError := range []bool{false, true} {
		name := "refused"
		if replaceBeforeError {
			name = "replaced_unconfirmed"
		}
		t.Run(name, func(t *testing.T) {
			checkAdminHumanApprovalPersistencePartialRetryAndTenantIsolation(t, replaceBeforeError)
		})
	}
}

func checkAdminHumanApprovalPersistencePartialRetryAndTenantIsolation(t *testing.T, replaceBeforeError bool) {
	now := time.Now()
	s := humanapproval.NewStore(0)
	p := &revocationAuditPersister{replaceBeforeError: replaceBeforeError, base: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "approvals.json")}}
	if e := s.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	for _, id := range []string{"shared", "foreign-only"} {
		if _, e := s.Upsert(model.HumanApprovalEvent{ID: id, TenantID: "tenant_other", ApprovalResult: "approved", ActorNHIID: stringPtr("foreign-agent")}); e != nil {
			t.Fatal(e)
		}
	}
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "approval-admin", TenantID: "tenant_lab_001", Roles: []string{"admin"}, Status: "active"})
	auth.UpsertAPIToken(adminAPIToken{ID: "approval-token", TenantID: "tenant_lab_001", TokenHash: adminTokenHash("approval-audit-fixture"), Roles: []string{"admin"}, Scopes: []string{"*"}, CreatedByAdminPrincipalID: "approval-admin", Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
	writer, e := logs.NewWriter(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), HumanApprovals: s, Writer: writer, AdminAuth: auth})
	if e := s.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	input := `{"id":"shared","approver_user_id":"own-approver","actor_nhi_id":"own-agent","action_type":"read","approval_result":"approved"}`
	for _, step := range []struct {
		path, body string
		fail       bool
		status     int
		domain     int
	}{
		{"", input, true, 500, 0}, {"", input, false, 200, 1}, {"/shared/revoke", `{"reason_code":"private-reason"}`, true, 500, 2}, {"/shared/revoke", `{"reason_code":"new-reason"}`, true, 500, 3}, {"/shared/revoke", `{}`, false, 200, 4},
	} {
		p.fail.Store(step.fail)
		before, _ := p.Load()
		req := httptest.NewRequest("POST", "/admin/human-approval-events"+step.path, strings.NewReader(step.body))
		req.Header.Set("Authorization", "Bearer approval-audit-fixture")
		req.Header.Set("Content-Type", "application/json")
		r := httptest.NewRecorder()
		h.ServeHTTP(r, req)
		if r.Code != step.status || strings.Contains(r.Body.String(), "private-runtime-location") {
			t.Fatalf("response %d %s", r.Code, r.Body)
		}
		if step.fail {
			after, _ := p.Load()
			if !replaceBeforeError && string(after) != string(before) {
				t.Fatal("refused persister changed saved data")
			}
		}
		if step.path == "" && step.fail {
			if _, ok := s.GetForTenant("tenant_lab_001", "shared"); ok {
				t.Fatal("rejected approval became active")
			}
		}
		if step.path != "" {
			own, ok := s.GetForTenant("tenant_lab_001", "shared")
			if !ok || own.ApprovalResult != "revoked" {
				t.Fatal("failed revoke restored approval")
			}
			if step.fail {
				var partial map[string]any
				json.Unmarshal(r.Body.Bytes(), &partial)
				if partial["status"] != "partial" || partial["applied"] != true || partial["approval_id"] != "shared" || partial["tenant_id"] != "tenant_lab_001" || partial["persistence"] != "unconfirmed" {
					t.Fatalf("partial outcome missing: %s", r.Body)
				}
			}
		}
		for _, id := range []string{"shared", "foreign-only"} {
			foreign, ok := s.GetForTenant("tenant_other", id)
			if !ok || foreign.ApprovalResult != "approved" {
				t.Fatal("foreign approval changed")
			}
		}
		domains := 0
		for _, audit := range readTransportAudits(t, writer) {
			if strings.HasPrefix(audit.EventType, "admin_human_approval_event_") {
				domains++
				if stringPtrValue(audit.ActorUserID) != "approval-admin" || audit.TenantID != "tenant_lab_001" || stringPtrValue(audit.TargetID) != "shared" {
					t.Fatalf("wrong attribution: %+v", audit)
				}
			}
		}
		if domains != step.domain {
			t.Fatalf("domain count %d want %d", domains, step.domain)
		}
	}
	rows := readTransportAudits(t, writer)
	if len(rows) != 9 {
		t.Fatalf("audit count %d", len(rows))
	}
	partial := 0
	for _, a := range rows {
		if stringPtrValue(a.Result) == "partial" {
			partial++
			if a.Metadata["persistence"] != "unconfirmed" {
				t.Fatal("missing durability outcome")
			}
		}
	}
	if partial != 2 {
		t.Fatal("partial audit count")
	}
	raw, _ := json.Marshal(rows)
	for _, bad := range []string{"private-reason", "new-reason", "private-runtime-location", "approval-audit-fixture"} {
		if strings.Contains(string(raw), bad) {
			t.Fatalf("audit leaked %s", bad)
		}
	}
	reloaded := humanapproval.NewStore(0)
	if e := reloaded.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	own, _ := reloaded.GetForTenant("tenant_lab_001", "shared")
	if own.ApprovalResult != "revoked" || stringPtrValue(own.Reason) != "private-reason" {
		t.Fatal("retry did not preserve revocation")
	}
	for _, tc := range []struct {
		path   string
		status int
	}{{"shared", 200}, {"foreign-only", 404}} {
		r := httptest.NewRecorder()
		h.ServeHTTP(r, httptest.NewRequest(http.MethodGet, "/human-approvals/events/"+tc.path, nil))
		if r.Code != tc.status {
			t.Fatalf("runtime lookup %d %s", r.Code, r.Body)
		}
		if tc.status == 200 && !strings.Contains(r.Body.String(), `"tenant_id":"tenant_lab_001"`) {
			t.Fatal("runtime returned foreign record")
		}
	}
}

func TestHumanApprovalRuntimeSaveRefusalDoesNotActivateOrRecordAcceptance(t *testing.T) {
	s := humanapproval.NewStore(0)
	p := &riskAuditPersister{base: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "runtime-approvals.json")}}
	dir := t.TempDir()
	writer, e := logs.NewWriter(dir)
	if e != nil {
		t.Fatal(e)
	}
	outbox := &recordingDomainEventOutbox{}
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), HumanApprovals: s, Writer: writer, DomainEventOutbox: outbox})
	if e := s.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	p.fail.Store(true)
	req := httptest.NewRequest("POST", "/human-approvals/events", strings.NewReader(`{"id":"save-refused","tenant_id":"tenant_lab_001","approver_user_id":"person","actor_nhi_id":"agent","action_type":"read","approval_result":"approved"}`))
	r := httptest.NewRecorder()
	h.ServeHTTP(r, req)
	if r.Code != 500 || strings.Contains(r.Body.String(), "private-runtime-location") {
		t.Fatalf("runtime response %d %s", r.Code, r.Body)
	}
	if _, ok := s.GetForTenant("tenant_lab_001", "save-refused"); ok {
		t.Fatal("failed runtime approval active")
	}
	for _, file := range []string{"human_approval_events.log.jsonl", "audit.log.jsonl"} {
		b, _ := os.ReadFile(filepath.Join(dir, file))
		if len(b) > 0 {
			t.Fatal("failed runtime approval recorded accepted event")
		}
	}
}

func TestAdminHumanApprovalMutationAuditOperatorPrivacy(t *testing.T) {
	for _, partial := range []bool{false, true} {
		req := httptest.NewRequest("POST", "/admin/human-approval-events/target/revoke", strings.NewReader("private-body-sentinel"))
		req.Header.Set("Authorization", "private-auth-sentinel")
		req.Header.Set("Cookie", "private-cookie-sentinel")
		req = requestWithAdminIdentity(req, adminIdentity{PrincipalID: "operator", TenantID: "operator-tenant"})
		audit := adminHumanApprovalMutationAuditLog(req, "admin_human_approval_event_revoked", adminHumanApprovalEvent{ID: "target", TenantID: "customer", ApprovalResult: "revoked", ApproverUserID: stringPtr("private-approver"), SubjectUserID: stringPtr("private-subject"), ReasonCode: stringPtr("private-reason"), RequestedScopes: []string{"private-scope"}}, testEvaluator(), time.Now(), partial)
		if stringPtrValue(audit.ActorUserID) != "operator" || audit.Metadata["operator_principal_id"] != "operator" || audit.Metadata["operator_tenant_id"] != "operator-tenant" || audit.TenantID != "customer" {
			t.Fatalf("operator attribution: %+v", audit)
		}
		if partial && stringPtrValue(audit.Result) != "partial" {
			t.Fatal("missing partial result")
		}
		audit.ActorUserID = nil
		assertAuditLogNonSecretInvariant(t, audit, []string{"private-body-sentinel", "private-auth-sentinel", "private-cookie-sentinel", "private-approver", "private-subject", "private-reason", "private-scope"})
	}
}
