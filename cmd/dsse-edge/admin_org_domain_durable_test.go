package main

import (
	"bytes"
	"encoding/json"
	"github.com/lantern-networks/dsse-core/logs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAdminOrganizationDomainsSaveFailureKeepsAcknowledgedState(t *testing.T) {
	for _, failure := range []string{"replace", "clear"} {
		t.Run(failure, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "private-domains.json")
			now := time.Now().UTC()
			tenant := testEvaluator().PolicyBundle.TenantID
			creds := newLocalAdminCredentialStore("DSSE")
			seedActiveAdminAccount(t, creds, "review@example.test", tenant, "reviewer", []string{"admin", "super_admin"}, now)
			auth := newAdminAuthStore()
			auth.UpsertPrincipal(principalFromCredential(creds.byEmail["review@example.test"], now))
			auth.UpsertSession(adminSession{ID: "review-session", TenantID: tenant, AdminPrincipalID: "reviewer", Roles: []string{"admin", "super_admin"}, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "review-csrf"}})
			writer, err := logs.NewWriter(filepath.Join(dir, "logs"))
			if err != nil {
				t.Fatal(err)
			}
			cfg := serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, LocalCredentials: creds, OperatorTenantID: tenant, OrganizationDomainsStorePath: path}
			handler := newServerWithConfig(cfg)
			request := func(method, body string) *httptest.ResponseRecorder {
				req := httptest.NewRequest(method, "/admin/organization-domains", strings.NewReader(body))
				req.AddCookie(&http.Cookie{Name: "admin_session", Value: "review-session"})
				req.Header.Set("X-CSRF-Token", "review-csrf")
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				return rec
			}
			if rec := request("PUT", `{"domains":["@Acme.Example","*.division.example","acme.example"]}`); rec.Code != 200 {
				t.Fatalf("seed %d: %s", rec.Code, rec.Body.String())
			}
			saved, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			live := request("GET", "").Body.Bytes()
			if err := os.Rename(path, path+".backup"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			var rec *httptest.ResponseRecorder
			switch failure {
			case "replace":
				rec = request("PUT", `{"domains":["changed.example"]}`)
			case "clear":
				rec = request("PUT", `{"domains":[]}`)
			}

			if rec.Code != 500 {
				t.Fatalf("failed save returned %d", rec.Code)
			}
			if !bytes.Equal(request("GET", "").Body.Bytes(), live) {
				t.Fatal("failed policy was published")
			}
			if bytes.Contains(rec.Body.Bytes(), []byte(dir)) {
				t.Fatal("private path leaked")
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(path+".backup", path); err != nil {
				t.Fatal(err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(saved, after) {
				t.Fatal("last saved policy changed")
			}
			handler = newServerWithConfig(cfg)
			if !bytes.Equal(request("GET", "").Body.Bytes(), live) {
				t.Fatal("restart changed last acknowledged policy")
			}
			rows, err := writer.ReadJSONL("audit.log.jsonl")
			if err != nil {
				t.Fatal(err)
			}
			success, failed := 0, 0
			for _, a := range rows {
				if a["event_type"] != "admin_config_change" || a["target_id"] != "/admin/organization-domains" {
					continue
				}
				if a["actor_user_id"] != "reviewer" || a["tenant_id"] != tenant {
					t.Fatal("incorrect audit attribution")
				}
				switch a["result"] {
				case "success":
					success++
				case "error":
					failed++
				}
			}
			if success != 1 || failed != 1 {
				t.Fatalf("audit success=%d error=%d", success, failed)
			}
			raw, _ := json.Marshal(rows)
			if bytes.Contains(raw, []byte(dir)) {
				t.Fatal("private save path in audit")
			}
		})
	}
}
