package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

func readConnectorManagementAudits(t *testing.T, writer *logs.Writer) []model.AuditLog {
	t.Helper()
	f, err := os.Open(filepath.Join(writer.Dir(), "audit.log.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var rows []model.AuditLog
	scanner := bufio.NewScanner(f)
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

type connectorManagementTestPersister struct {
	blobstore.FilePersister
	fail bool
}

func (p *connectorManagementTestPersister) Save(data []byte) error {
	if p.fail {
		return errors.New("private save diagnostic")
	}
	return p.FilePersister.Save(data)
}

func TestConnectorManagementSaveFailureAndAuditActor(t *testing.T) {
	for _, mode := range []string{"session", "token", "selected-tenant"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			now := time.Now()
			owner := "tenant_lab_001"
			target := owner
			if mode == "selected-tenant" {
				target = "tenant_other"
			}
			auth := newAdminAuthStore()
			auth.UpsertPrincipal(adminPrincipal{ID: "connector-admin", TenantID: owner, Roles: []string{"admin", "super_admin"}, Status: "active"})
			auth.UpsertSession(adminSession{ID: "connector-session", TenantID: owner, AdminPrincipalID: "connector-admin", Roles: []string{"admin", "super_admin"}, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "connector-csrf"}})
			auth.UpsertAPIToken(adminAPIToken{ID: "connector-token", TenantID: owner, TokenHash: adminTokenHash("private-test-token"), CreatedByAdminPrincipalID: "connector-admin", Roles: []string{"admin", "super_admin"}, Scopes: []string{"*"}, Status: "active", CreatedAt: now.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
			p := &connectorManagementTestPersister{FilePersister: blobstore.FilePersister{Path: filepath.Join(dir, "registry.json")}}
			registry := connector.NewRegistry()
			if err := registry.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			if _, err := registry.Register(model.ConnectorRegistration{ID: "managed", TenantID: target, Name: "Original", PrivateBaseURL: "http://127.0.0.1:18090"}, now); err != nil {
				t.Fatal(err)
			}
			writer, err := logs.NewWriter(filepath.Join(dir, "logs"))
			if err != nil {
				t.Fatal(err)
			}
			h := newServerWithConfig(serverConfig{Registry: registry, Evaluator: testEvaluator(), AdminAuth: auth, OperatorTenantID: owner, Writer: writer})
			request := func(method, path, body string) *httptest.ResponseRecorder {
				req := httptest.NewRequest(method, path, strings.NewReader(body))
				if mode == "token" {
					req.Header.Set("Authorization", "Bearer private-test-token")
				} else {
					req.AddCookie(&http.Cookie{Name: "admin_session", Value: "connector-session"})
					req.Header.Set("X-CSRF-Token", "connector-csrf")
				}
				if target != owner {
					req.Header.Set("X-Operate-Tenant", target)
				}
				req.Header.Set("X-Actor-User-ID", "forged-actor")
				r := httptest.NewRecorder()
				h.ServeHTTP(r, req)
				return r
			}
			p.fail = true
			r := request("POST", "/admin/connectors/managed/name", `{"name":"Changed"}`)
			if r.Code != 503 || strings.Contains(r.Body.String(), "private save") {
				t.Fatalf("rename failure: %d %s", r.Code, r.Body.String())
			}
			p.fail = false
			r = request("POST", "/admin/connectors/managed/name", `{"name":"Changed"}`)
			if r.Code != 200 {
				t.Fatalf("rename: %d %s", r.Code, r.Body.String())
			}
			r = request("POST", "/admin/connectors/managed/name", `{"name":""}`)
			if r.Code != 200 {
				t.Fatal(r.Code)
			}
			p.fail = true
			r = request("DELETE", "/admin/connectors/managed", "")
			if r.Code != 503 || strings.Contains(r.Body.String(), "private save") {
				t.Fatalf("remove failure: %d %s", r.Code, r.Body.String())
			}
			if _, ok := registry.Get("managed"); !ok {
				t.Fatal("failed delete hid record")
			}
			p.fail = false
			r = request("DELETE", "/admin/connectors/managed", "")
			if r.Code != 200 {
				t.Fatal(r.Code)
			}
			rows := readConnectorManagementAudits(t, writer)
			domains, commonErrors := 0, 0
			for _, a := range rows {
				raw, _ := json.Marshal(a)
				for _, bad := range []string{"private save diagnostic", "private-test-token", "connector-csrf", "forged-actor"} {
					if strings.Contains(string(raw), bad) {
						t.Fatal("audit leaked private input")
					}
				}
				if a.EventType == "admin_config_change" && stringPtrValue(a.Result) == "error" {
					commonErrors++
				}
				if !strings.HasPrefix(a.EventType, "admin_connector_") {
					continue
				}
				domains++
				if a.TenantID != target || stringPtrValue(a.ActorUserID) != "connector-admin" || stringPtrValue(a.TargetID) != "managed" || stringPtrValue(a.Result) != "success" {
					t.Fatalf("incorrect audit: %+v", a)
				}
			}
			if domains != 3 || commonErrors != 2 {
				t.Fatalf("domains=%d commonErrors=%d rows=%d", domains, commonErrors, len(rows))
			}
		})
	}
}
