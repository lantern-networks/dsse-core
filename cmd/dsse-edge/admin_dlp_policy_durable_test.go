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

func TestAdminDLPPolicySaveFailureKeepsAcknowledgedState(t *testing.T) {
	for _, failure := range []string{"create", "update", "delete"} {
		t.Run(failure, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "private-dlp.json")
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
			cfg := serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, LocalCredentials: creds, OperatorTenantID: tenant, DLPPolicyObjectStorePath: path}
			handler := newServerWithConfig(cfg)
			request := func(method, body string) *httptest.ResponseRecorder {
				req := httptest.NewRequest(method, "/admin/dlp-policies?id=one", strings.NewReader(body))
				req.AddCookie(&http.Cookie{Name: "admin_session", Value: "review-session"})
				req.Header.Set("X-CSRF-Token", "review-csrf")
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				return rec
			}
			if rec := request("POST", `{"id":"one","name":"Observe email","identifiers":["email"],"on_match":"observe"}`); rec.Code != 200 {
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
			case "create":
				rec = request("POST", `{"id":"two","name":"Second","identifiers":["email"],"on_match":"observe"}`)
			case "update":
				rec = request("POST", `{"id":"one","name":"Changed","identifiers":["email"],"on_match":"observe"}`)
			case "delete":
				rec = request("DELETE", "")
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
				if a["event_type"] != "admin_config_change" || a["target_id"] != "/admin/dlp-policies" {
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

func TestAdminDLPPolicyRejectsValuesThatCannotRestore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.json")
	tenant := testEvaluator().PolicyBundle.TenantID
	writer, err := logs.NewWriter(filepath.Join(dir, "logs"))
	if err != nil {
		t.Fatal(err)
	}
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "reviewer", TenantID: tenant, Roles: []string{"admin", "super_admin"}, Status: "active"})
	auth.UpsertSession(adminSession{ID: "review-session", TenantID: tenant, AdminPrincipalID: "reviewer", Roles: []string{"admin", "super_admin"}, Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "review-csrf"}})
	cfg := serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, OperatorTenantID: tenant, DLPPolicyObjectStorePath: path}
	handler := newServerWithConfig(cfg)
	request := func(method, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/admin/dlp-policies", strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: "admin_session", Value: "review-session"})
		req.Header.Set("X-CSRF-Token", "review-csrf")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	if rec := request("POST", `{"name":"Valid","identifiers":["email"],"on_match":"observe","tenant_id":"forged"}`); rec.Code != 200 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	before := request("GET", "").Body.String()
	for _, extra := range []string{`"id":" bad"`, `"status":"typo"`, `"min_count":-1`, `"device_risk":[{"min_count":1,"window_seconds":-1}]`} {
		body := `{"name":"Bad","identifiers":["email"],"on_match":"observe",` + extra + `}`
		if rec := request("POST", body); rec.Code != 400 {
			t.Fatalf("invalid policy: %d %s", rec.Code, rec.Body.String())
		}
		data, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(data, saved) || request("GET", "").Body.String() != before {
			t.Fatal("invalid write changed state")
		}
	}
	handler = newServerWithConfig(cfg)
	if request("GET", "").Body.String() != before {
		t.Fatal("valid generated identity was not retained on restart")
	}
	var snapshot dlpPolicyObjectSnapshot
	if err := json.Unmarshal(saved, &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.ByTenant) != 1 || len(snapshot.ByTenant[tenant]) != 1 {
		t.Fatal("body tenant escaped authenticated scope")
	}
	rows, err := writer.ReadJSONL("audit.log.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 5 {
		t.Fatalf("audit count=%d", len(rows))
	}
	for i, row := range rows {
		if row["actor_user_id"] != "reviewer" || row["tenant_id"] != tenant || row["target_id"] != "/admin/dlp-policies" {
			t.Fatal("audit attribution")
		}
		if (row["result"] == "success") != (i == 0) {
			t.Fatal("audit result differs from write outcome")
		}
	}
}
