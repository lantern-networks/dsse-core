package main

import (
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestManagedAccountChangesApplyToExistingCredentials(t *testing.T) {
	for _, kind := range []string{"session", "api_token"} {
		t.Run(kind, func(t *testing.T) {
			now := time.Now().UTC()
			creds := newLocalAdminCredentialStore("DSSE")
			seedActiveAdminAccount(t, creds, "live@example.com", "tenant_lab_001", "adm_live", []string{"admin"}, now)
			auth := newAdminAuthStore()
			auth.UpsertPrincipal(principalFromCredential(creds.byEmail["live@example.com"], now))
			auth.UpsertSession(adminSession{ID: "live-session", TenantID: "tenant_lab_001", AdminPrincipalID: "adm_live", Roles: []string{"admin"}, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "live-csrf"}})
			auth.UpsertAPIToken(adminAPIToken{ID: "live-token", TenantID: "tenant_lab_001", TokenHash: adminTokenHash("live-secret"), Roles: []string{"admin"}, Scopes: []string{"*"}, CreatedByAdminPrincipalID: "adm_live", Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
			writer, err := logs.NewWriter(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, Registry: connector.NewRegistry(), AdminAuth: auth, LocalCredentials: creds})
			request := func(method, path string) int {
				r := httptest.NewRequest(method, path, strings.NewReader(`{"active":true}`))
				if kind == "session" {
					r.AddCookie(&http.Cookie{Name: "admin_session", Value: "live-session"})
					r.Header.Set("X-CSRF-Token", "live-csrf")
				} else {
					r.Header.Set("Authorization", "Bearer live-secret")
				}
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				return w.Code
			}
			if status := request("GET", "/admin/session"); status != 200 {
				t.Fatalf("fixture: %d", status)
			}
			if _, err := creds.SetStatus("tenant_lab_001", "adm_live", credentialStatusSuspended, now); err != nil {
				t.Fatal(err)
			}
			if status := request("GET", "/admin/session"); status != 401 {
				t.Fatalf("suspended account credential still accepted: %d", status)
			}
			if _, err := creds.SetStatus("tenant_lab_001", "adm_live", credentialStatusActive, now); err != nil {
				t.Fatal(err)
			}
			if kind == "session" {
				if _, err := creds.SetRoles("tenant_lab_001", "adm_live", []string{"analyst"}, now); err != nil {
					t.Fatal(err)
				}
				if status := request("POST", "/admin/legal-hold"); status != 403 {
					t.Fatalf("session kept old write role: %d", status)
				}
			}
			if _, err := creds.Delete("tenant_lab_001", "adm_live", now); err != nil {
				t.Fatal(err)
			}
			if status := request("GET", "/admin/session"); status != 401 {
				t.Fatalf("deleted account credential still accepted: %d", status)
			}
			rows, err := writer.ReadJSONL("audit.log.jsonl")
			if err != nil {
				t.Fatal(err)
			}
			denied := 0
			for _, row := range rows {
				if row["event_type"] == "admin_auth_failed" {
					denied++
				}
			}
			if denied != 2 {
				t.Fatalf("expected suspension and deletion refusal audit, got %d", denied)
			}

		})
	}
}
