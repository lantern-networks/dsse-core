package main

import (
	"bytes"
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

// Exercise the actual evaluation, JSONL append, tenant-scoped admin read and
// file-backed read after losing the in-memory decision store. Lab mode isolates
// attribution here; connector/mTLS authorization has separate boundary tests.
func TestDefaultDenyAttributionThroughRuntimeLogsAndAdminRead(t *testing.T) {
	for _, delegated := range []bool{false, true} {
		name := "human"
		if delegated {
			name = "delegated"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writer, err := logs.NewWriter(dir)
			if err != nil {
				t.Fatal(err)
			}
			ev := testEvaluatorWithPolicies([]model.Policy{{ID: "private-policy-a", TenantID: "tenant-a", Status: "active", Action: model.PolicyAction{Decision: "allow"}}})
			auth := newAdminAuthStore()
			for _, tenant := range []string{"tenant-a", "tenant-b"} {
				roles := []string{"admin"}
				auth.UpsertPrincipal(adminPrincipal{ID: tenant + "-admin", TenantID: tenant, Roles: roles, Status: "active"})
				auth.UpsertSession(adminSession{ID: tenant + "-session", TenantID: tenant, AdminPrincipalID: tenant + "-admin", Roles: roles, Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
			}
			lab := true
			config := serverConfig{Evaluator: ev, Writer: writer, AdminAuth: auth, LabMode: &lab}
			h := newServerWithConfig(config)
			req := model.DecisionRequest{TenantID: "tenant-b", UserID: "user-b", FQDN: "request.invalid", Protocol: "tcp", DestinationPort: 443}
			if delegated {
				req.DelegatedAccessGrantID = "missing-grant"
			}
			raw, err := json.Marshal(req)
			if err != nil {
				t.Fatal(err)
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/decisions/evaluate", bytes.NewReader(raw)))
			if rr.Code != http.StatusOK {
				t.Fatalf("evaluate: %d %s", rr.Code, rr.Body.String())
			}
			var dec model.AccessDecision
			if err := json.Unmarshal(rr.Body.Bytes(), &dec); err != nil {
				t.Fatal(err)
			}
			if dec.Decision != "deny" || dec.PolicyID != "" || dec.TenantID != "tenant-b" || strings.Contains(rr.Body.String(), "private-policy-a") {
				t.Fatalf("wrong decision attribution: %s", rr.Body.String())
			}
			streams := []string{"access"}
			if delegated {
				streams = append(streams, "audit")
			}
			for _, stream := range streams {
				data, err := os.ReadFile(filepath.Join(dir, stream+".log.jsonl"))
				if err != nil {
					t.Fatal(err)
				}
				lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
				if len(lines) != 1 {
					t.Fatalf("%s rows = %d", stream, len(lines))
				}
				var row map[string]any
				if err := json.Unmarshal(lines[0], &row); err != nil {
					t.Fatal(err)
				}
				if row["tenant_id"] != "tenant-b" || row["access_decision_id"] != dec.ID || (row["policy_id"] != nil && row["policy_id"] != "") || bytes.Contains(data, []byte("private-policy-a")) {
					t.Fatalf("wrong %s attribution: %s", stream, data)
				}
				if stream == "audit" && (row["event_type"] != "nhi_delegated_access_decision_evaluated" || row["result"] != "deny") {
					t.Fatalf("wrong delegated audit: %s", data)
				}
			}
			if !delegated {
				if _, err := os.Stat(filepath.Join(dir, "audit.log.jsonl")); !os.IsNotExist(err) {
					t.Fatalf("routine decision unexpectedly created audit: %v", err)
				}
			}
			for _, restart := range []bool{false, true} {
				if restart {
					h = newServerWithConfig(config)
				}
				for _, tenant := range []string{"tenant-b", "tenant-a"} {
					r := httptest.NewRequest(http.MethodGet, "/admin/access-decisions/"+dec.ID, nil)
					r.AddCookie(&http.Cookie{Name: "admin_session", Value: tenant + "-session"})
					response := httptest.NewRecorder()
					h.ServeHTTP(response, r)
					if tenant == "tenant-a" {
						if response.Code != http.StatusNotFound {
							t.Fatalf("foreign read: %d %s", response.Code, response.Body.String())
						}
						continue
					}
					if response.Code != http.StatusOK {
						t.Fatalf("own read: %d %s", response.Code, response.Body.String())
					}
					var detail struct {
						Decision *model.AccessDecision       `json:"access_decision"`
						Related  map[string][]map[string]any `json:"related_logs"`
						Summary  struct {
							Runtime bool `json:"has_runtime_decision"`
							Rows    int  `json:"related_log_rows"`
						} `json:"summary"`
					}
					if err := json.Unmarshal(response.Body.Bytes(), &detail); err != nil {
						t.Fatal(err)
					}
					if detail.Summary.Runtime == restart || detail.Summary.Rows != len(streams) || (detail.Decision == nil) != restart {
						t.Fatalf("wrong persistence summary: %s", response.Body.String())
					}
					if detail.Decision != nil && detail.Decision.PolicyID != "" {
						t.Fatal("runtime attribution reappeared")
					}
					for _, stream := range streams {
						rows := detail.Related[stream]
						if len(rows) != 1 || (rows[0]["policy_id"] != nil && rows[0]["policy_id"] != "") {
							t.Fatalf("wrong related %s: %+v", stream, rows)
						}
					}
					if strings.Contains(response.Body.String(), "private-policy-a") {
						t.Fatal("foreign policy leaked through detail")
					}
				}
			}
		})
	}
}
