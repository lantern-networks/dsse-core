package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
)

func TestAdminAPITokenLifecycleAuditUsesSelectedCaseDistinctTenant(t *testing.T) {
	const operatorTenant, targetTenant = "Acme", "acme"
	declareOperatorTenantForTest(t, operatorTenant)
	now := time.Now().UTC()
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{
		ID: "token-operator", TenantID: operatorTenant, Email: "operator@example.invalid",
		Roles: []string{"owner"}, Status: "active",
	})
	auth.UpsertSession(adminSession{
		ID: "token-operator-session", TenantID: operatorTenant, AdminPrincipalID: "token-operator",
		Roles: []string{"owner"}, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
		Metadata: map[string]any{adminCSRFTokenKey: "token-operator-csrf"},
	})
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	outbox := &recordingAdminAuditOutboxDeadReader{}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(), AdminAuth: auth, OperatorTenantID: operatorTenant,
		Writer: writer, AdminAuditOutbox: outbox,
	})
	request := func(path, body string, wantStatus int) adminAPITokenCreateResponse {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: "admin_session", Value: "token-operator-session"})
		req.Header.Set("X-CSRF-Token", "token-operator-csrf")
		req.Header.Set("X-Operate-Tenant", targetTenant)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != wantStatus {
			t.Fatalf("%s status = %d, want %d: %s", path, rec.Code, wantStatus, rec.Body.String())
		}
		var response adminAPITokenCreateResponse
		if wantStatus == http.StatusCreated {
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if response.Token.TenantID != targetTenant || response.Token.ID == "" {
				t.Fatalf("%s returned token for %q, want %q", path, response.Token.TenantID, targetTenant)
			}
		} else if wantStatus == http.StatusOK {
			var revoked adminAPITokenResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &revoked); err != nil {
				t.Fatal(err)
			}
			if revoked.TenantID != targetTenant || revoked.ID == "" {
				t.Fatalf("%s returned revoked token for %q, want %q", path, revoked.TenantID, targetTenant)
			}
		}
		return response
	}
	created := request("/admin/api-tokens", `{"name":"case-distinct-audit","roles":["auditor"],"scopes":["admin.logs.read"],"expires_at":"2099-01-01T00:00:00Z"}`, http.StatusCreated)
	rotated := request("/admin/api-tokens/"+created.Token.ID+"/rotate", `{}`, http.StatusCreated)
	if rotated.Token.ID == created.Token.ID {
		t.Fatal("rotation retained old token id")
	}
	request("/admin/api-tokens/"+rotated.Token.ID+"/revoke", `{}`, http.StatusOK)

	wants := map[string]bool{
		"admin_api_token_created": false, "admin_api_token_rotated": false, "admin_api_token_revoked": false,
	}
	for _, audit := range outbox.insertedAudits {
		if _, tracked := wants[audit.EventType]; !tracked {
			continue
		}
		if audit.TenantID != targetTenant {
			t.Errorf("%s audit tenant = %q, want %q", audit.EventType, audit.TenantID, targetTenant)
		}
		wants[audit.EventType] = true
	}
	for event, found := range wants {
		if !found {
			t.Errorf("missing %s outbox audit", event)
		}
	}
	for _, tenant := range []string{operatorTenant, testEvaluator().PolicyBundle.TenantID} {
		if tenant == targetTenant {
			continue
		}
		rows, err := writer.ReadJSONLForTenant(tenant, "audit.log.jsonl")
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			if event, ok := row["event_type"].(string); ok {
				if _, tracked := wants[event]; tracked {
					t.Errorf("%s lifecycle audit appeared in unrelated tenant %q", event, tenant)
				}
			}
		}
	}
	rows, err := writer.ReadJSONLForTenant(targetTenant, "audit.log.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, row := range rows {
		if event, ok := row["event_type"].(string); ok {
			seen[event] = true
		}
	}
	for event := range wants {
		if !seen[event] {
			t.Errorf("missing %s in selected tenant audit partition", event)
		}
	}
}
