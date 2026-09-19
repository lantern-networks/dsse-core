package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/lantern-networks/dsse-core/logs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAdminDNSPolicySaveFailureKeepsAcknowledgedState(t *testing.T) {
	for _, failure := range []string{"write", "rename"} {
		t.Run(failure, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "private-dns.json")
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
			cfg := serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, LocalCredentials: creds, OperatorTenantID: tenant, DNSPolicyStorePath: path}
			handler := newServerWithConfig(cfg)
			request := func(method, body string) *httptest.ResponseRecorder {
				req := httptest.NewRequest(method, "/admin/dns-policy", strings.NewReader(body))
				req.AddCookie(&http.Cookie{Name: "admin_session", Value: "review-session"})
				req.Header.Set("X-CSRF-Token", "review-csrf")
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				return rec
			}
			if rec := request("PUT", `{"deny":["blocked.example"],"stub_ipv4":{"fixed.example":"192.0.2.40"},"ech_strip":true}`); rec.Code != 200 {
				t.Fatalf("seed %d: %s", rec.Code, rec.Body.String())
			}
			saved, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			live := request("GET", "").Body.Bytes()
			if failure == "write" {
				if err := os.Mkdir(path+".tmp", 0700); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Rename(path, path+".backup"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			rec := request("PUT", `{"deny":["unsaved.example"]}`)
			if rec.Code != 500 {
				t.Fatalf("failed save returned %d", rec.Code)
			}
			if !bytes.Equal(request("GET", "").Body.Bytes(), live) {
				t.Fatal("failed policy was published")
			}
			if bytes.Contains(rec.Body.Bytes(), []byte(dir)) {
				t.Fatal("private path leaked")
			}
			if failure == "write" {
				if err := os.Remove(path + ".tmp"); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(path+".backup", path); err != nil {
					t.Fatal(err)
				}
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
				if a["event_type"] != "admin_config_change" || a["target_id"] != "/admin/dns-policy" {
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

// Concurrent replacements must not share a temporary write or publish a policy
// older than the durable file. Every acknowledged response names its own request.
func TestAdminDNSPolicyConcurrentDurableReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.json")
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: newAdminAuthStore(), DNSPolicyStorePath: path})
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("blocked-%d.example", i)
			req := httptest.NewRequest("PUT", "/admin/dns-policy", strings.NewReader(fmt.Sprintf(`{"deny":["%s"]}`, name)))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != 200 {
				t.Errorf("write %d: %d", i, rec.Code)
				return
			}
			var dto struct {
				Deny []string `json:"deny"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &dto); err != nil || !reflect.DeepEqual(dto.Deny, []string{name}) {
				t.Errorf("response does not acknowledge its own request: %s", rec.Body.String())
			}
		}(i)
	}
	wg.Wait()
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/admin/dns-policy", nil))
	var disk, live any
	if err := json.Unmarshal(saved, &disk); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &live); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(disk, live) {
		t.Fatal("last saved and live policies diverged")
	}
}
