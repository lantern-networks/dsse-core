package main

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

func TestSiteLifecycleAuditsUseAuthenticatedActor(t *testing.T) {
	for _, mode := range []string{"session-own", "token-own", "session-selected-tenant"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			now := time.Now().UTC()
			owner := "tenant_lab_001"
			target := owner
			if mode == "session-selected-tenant" {
				target = "tenant_other"
			}
			auth := newAdminAuthStore()
			auth.UpsertPrincipal(adminPrincipal{ID: "site-admin", TenantID: owner, Email: "site-admin@example.test", Roles: []string{"admin", "super_admin"}, Status: "active"})
			auth.UpsertSession(adminSession{ID: "site-session", TenantID: owner, AdminPrincipalID: "site-admin", Roles: []string{"admin", "super_admin"}, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "site-csrf"}})
			token := "site-private-test-token"
			auth.UpsertAPIToken(adminAPIToken{ID: "site-api-token", TenantID: owner, Name: "test", TokenHash: adminTokenHash(token), CreatedByAdminPrincipalID: "site-admin", Roles: []string{"admin", "super_admin"}, Scopes: []string{"*"}, Status: "active", CreatedAt: now.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
			writer, err := logs.NewWriter(filepath.Join(dir, "logs"))
			if err != nil {
				t.Fatal(err)
			}
			outbox := &recordingAdminAuditOutboxDeadReader{}
			h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: auth, OperatorTenantID: owner, SiteStore: newDurableAdminSiteStore(filepath.Join(dir, "sites.json")), Writer: writer, AdminAuditOutbox: outbox, ConnectorEnrollmentEdgeURL: "https://edge.example.test", ConnectorEnrollmentEdgeCAPEM: "-----BEGIN CERTIFICATE-----\ntest-anchor\n-----END CERTIFICATE-----\n"})
			request := func(method, path, body string) *httptest.ResponseRecorder {
				req := httptest.NewRequest(method, path, strings.NewReader(body))
				if mode == "token-own" {
					req.Header.Set("Authorization", "Bearer "+token)
				} else {
					req.AddCookie(&http.Cookie{Name: "admin_session", Value: "site-session"})
					req.Header.Set("X-CSRF-Token", "site-csrf")
				}
				if target != owner {
					req.Header.Set("X-Operate-Tenant", target)
				}
				req.Header.Set("X-Actor-User-ID", "forged-actor")
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				return rec
			}
			for _, name := range []string{"created", "updated"} {
				rec := request("POST", "/admin/sites", `{"site_id":"actor-site","name":"`+name+`","actor_user_id":"forged-actor"}`)
				if rec.Code != 200 {
					t.Fatalf("%s %d %s", name, rec.Code, rec.Body.String())
				}
			}
			enrollment := request("POST", "/admin/sites/actor-site/enrollment-command", `{}`)
			if enrollment.Code != 200 {
				t.Fatalf("enroll %d %s", enrollment.Code, enrollment.Body.String())
			}
			var issued adminSiteEnrollmentCommandResponse
			if err := json.Unmarshal(enrollment.Body.Bytes(), &issued); err != nil {
				t.Fatal(err)
			}
			if issued.BootstrapSecret == "" {
				t.Fatal("no test credential")
			}
			if rec := request("DELETE", "/admin/sites/actor-site", ""); rec.Code != 200 {
				t.Fatalf("delete %d %s", rec.Code, rec.Body.String())
			}
			rows := readSiteActorAudits(t, writer)
			domains := 0
			actions := map[string]int{}
			for _, a := range rows {
				raw, _ := json.Marshal(a)
				for _, forbidden := range []string{token, "site-csrf", "forged-actor", issued.BootstrapSecret, connectorRuntimeSecretHash(issued.BootstrapSecret)} {
					if strings.Contains(string(raw), forbidden) {
						t.Fatalf("audit contains private/forged material")
					}
				}
				if !strings.HasPrefix(a.EventType, "admin_site_") {
					continue
				}
				domains++
				actions[stringPtrValue(a.Action)]++
				if a.TenantID != target || stringPtrValue(a.ActorUserID) != "site-admin" || stringPtrValue(a.TargetID) != "actor-site" || stringPtrValue(a.Result) != "success" {
					t.Fatalf("wrong audit identity: %+v", a)
				}
				if _, err := time.Parse(time.RFC3339, a.Timestamp); err != nil {
					t.Fatal(err)
				}
			}
			if domains != 4 || actions["upserted"] != 2 || actions["deleted"] != 1 || actions["enrollment_command_issued"] != 1 {
				t.Fatalf("actions: %v", actions)
			}
			mirroredSites := 0
			for _, a := range outbox.insertedAudits {
				if !strings.HasPrefix(a.EventType, "admin_site_") {
					continue
				}
				mirroredSites++
				if stringPtrValue(a.ActorUserID) != "site-admin" || a.TenantID != target {
					t.Fatalf("mirror identity lost: %+v", a)
				}
			}
			if mirroredSites != 4 {
				t.Fatalf("site mirror count %d", mirroredSites)
			}
		})
	}
}

func TestSiteLifecycleAuditDoesNotInventAnActor(t *testing.T) {
	for _, r := range []*http.Request{nil, httptest.NewRequest("POST", "/admin/sites", nil), adminRequestBy(" ")} {
		if r != nil {
			r.Header.Set("X-Actor-User-ID", "forged-actor")
		}
		a := adminSiteAuditLog("admin_site_upserted", adminSiteModel{SiteID: "site", TenantID: "target"}, r, testEvaluator(), time.Now())
		if a.ActorUserID != nil || a.TenantID != "target" {
			t.Fatal("unresolved caller was attributed")
		}
	}
	a := adminSiteAuditLog("admin_site_upserted", adminSiteModel{SiteID: "site", TenantID: "target"}, adminRequestBy(" operator "), testEvaluator(), time.Now())
	if stringPtrValue(a.ActorUserID) != "operator" || a.TenantID != "target" {
		t.Fatal("request actor changed the target tenant")
	}
}

func readSiteActorAudits(t *testing.T, writer *logs.Writer) []model.AuditLog {
	t.Helper()
	file, err := os.Open(filepath.Join(writer.Dir(), "audit.log.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var rows []model.AuditLog
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var row model.AuditLog
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, row)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return rows
}
