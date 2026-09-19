package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

func TestApplicationLifecycleActor(t *testing.T) {
	for _, selected := range []bool{false, true} {
		t.Run(map[bool]string{false: "own", true: "selected"}[selected], func(t *testing.T) {
			owner, target := "tenant_lab_001", "tenant_lab_001"
			if selected {
				target = "tenant_other"
			}
			now := time.Now()
			auth := newAdminAuthStore()
			auth.UpsertPrincipal(adminPrincipal{ID: "app-admin", TenantID: owner, Email: "private-email@example.invalid", Roles: []string{"admin", "super_admin"}, Status: "active"})
			auth.UpsertSession(adminSession{ID: "app-session", TenantID: owner, AdminPrincipalID: "app-admin", Roles: []string{"admin", "super_admin"}, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "app-csrf"}})
			writer, err := logs.NewWriter(filepath.Join(t.TempDir(), "logs"))
			if err != nil {
				t.Fatal(err)
			}
			outbox := &recordingAdminAuditOutboxDeadReader{}
			h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: auth, OperatorTenantID: owner, Writer: writer, AdminAuditOutbox: outbox})
			for _, x := range []struct{ method, path, body string }{{"POST", "/admin/applications", `{"application_id":"actor-app","application_type":"private_app","name":"App"}`}, {"POST", "/admin/applications/actor-app/publish", `{"name":"App","destination":"private.example.test","destination_port":443,"publish_protocol":"web"}`}, {"POST", "/admin/applications/actor-app/unpublish", `{}`}, {"DELETE", "/admin/applications/actor-app", ``}} {
				req := httptest.NewRequest(x.method, x.path, strings.NewReader(x.body))
				req.AddCookie(&http.Cookie{Name: "admin_session", Value: "app-session"})
				req.Header.Set("X-CSRF-Token", "app-csrf")
				req.Header.Set("X-Actor-User-ID", "forged")
				if selected {
					req.Header.Set("X-Operate-Tenant", target)
				}
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				if rec.Code != 200 {
					t.Fatalf("%s: %d %s", x.path, rec.Code, rec.Body.String())
				}
			}
			for _, rows := range [][]model.AuditLog{readTransportAudits(t, writer), outbox.insertedAudits} {
				count := 0
				for _, a := range rows {
					if !strings.HasPrefix(a.EventType, "admin_application_") {
						continue
					}
					count++
					raw, err := json.Marshal(a)
					if err != nil {
						t.Fatal(err)
					}
					if a.SourceIP != nil {
						t.Fatal("raw source IP in application audit")
					}
					for _, secret := range []string{"private-email@example.invalid", "app-session", "app-csrf", "forged"} {
						if strings.Contains(string(raw), secret) {
							t.Fatalf("audit contains %q", secret)
						}
					}
					if a.TenantID != target || stringPtrValue(a.ActorUserID) != "app-admin" || stringPtrValue(a.TargetID) != "actor-app" {
						t.Fatalf("wrong actor or tenant: %+v", a)
					}
					if selected && a.Metadata["operator_principal_id"] != "app-admin" {
						t.Fatal("missing operator attribution")
					}
				}
				if count != 4 {
					t.Fatalf("domain audits %d, want 4", count)
				}
			}
		})
	}
}

func TestApplicationAuditNoInventedActor(t *testing.T) {
	for _, r := range []*http.Request{nil, httptest.NewRequest("POST", "/admin/applications", nil), adminRequestBy(" ")} {
		a := applicationAuditWithActor(r, model.AuditLog{TenantID: "target"})
		if a.ActorUserID != nil || a.TenantID != "target" {
			t.Fatal("invented actor or changed tenant")
		}
	}
}
