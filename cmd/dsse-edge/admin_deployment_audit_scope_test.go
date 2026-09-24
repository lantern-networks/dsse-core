package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
)

func TestDeploymentAuditReadAndPreviewKeepTenantBoundaries(t *testing.T) {
	root := t.TempDir()
	writer, err := logs.NewWriter(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []map[string]any{
		{"id": "deployment-a", "tenant_id": "deployment", "event_type": "agent_update_published", "timestamp": "2026-09-18T00:00:03Z"},
		{"id": "deployment-b", "tenant_id": "deployment", "event_type": "agent_update_activated", "timestamp": "2026-09-18T00:00:02Z"},
		{"id": "own-a", "tenant_id": "tenant_lab_001", "event_type": "admin_config_change", "timestamp": "2026-09-18T00:00:01Z"},
		{"id": "other-a", "tenant_id": "tenant_other", "event_type": "admin_config_change", "timestamp": "2026-09-18T00:00:00Z"},
	} {
		if err := writer.Append("audit.log.jsonl", row); err != nil {
			t.Fatal(err)
		}
	}
	auth := newAdminAuthStore()
	for _, who := range []string{"operator", "ordinary", "customer-owner", "readless", "exportless"} {
		tenant, roles, scopes := "tenant_lab_001", []string{"admin", "super_admin"}, []string{"*"}
		if who == "ordinary" {
			roles = []string{"admin"}
		}
		if who == "customer-owner" {
			tenant = "tenant_other"
		}
		if who == "readless" {
			scopes = []string{"admin.endpoints.read"}
		}
		if who == "exportless" {
			scopes = []string{"admin.logs.read"}
		}
		auth.UpsertPrincipal(adminPrincipal{ID: who, TenantID: tenant, Roles: roles, Status: "active"})
		auth.UpsertAPIToken(adminAPIToken{ID: who, TokenHash: adminTokenHash(who + "-audit-test"), TenantID: tenant, CreatedByAdminPrincipalID: who, Roles: roles, Scopes: scopes, Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
	}
	oldOp, oldLegacy := operatorTenantConfigured(), operatorTenantlessMode.Load()
	defer func() { operatorTenantAuthority.Store(oldOp); operatorTenantlessMode.Store(oldLegacy) }()
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, OperatorTenantID: "tenant_lab_001"})
	request := func(who, header, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		if who != "" {
			r.Header.Set("Authorization", "Bearer "+who+"-audit-test")
		}
		if header != "" {
			r.Header.Set("X-Operate-Tenant", header)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	before, _ := os.ReadFile(filepath.Join(root, "audit.log.jsonl"))
	for _, suffix := range []string{"", "/export"} {
		for _, tc := range []struct{ name, who, header, query, scope string }{
			{"operator-default", "operator", "", "", "tenant_lab_001"},
			{"operator-explicit-tenant", "operator", "", "audit_scope=tenant", "tenant_lab_001"},
			{"operator-deployment", "operator", "", "audit_scope=deployment", "deployment"},
			{"query-cannot-select-customer", "operator", "", "audit_scope=deployment&tenant_id=tenant_other", "deployment"},
			{"selected-self", "operator", "tenant_lab_001", "", "tenant_lab_001"},
			{"selected-customer", "operator", "tenant_other", "", "tenant_other"},
			{"customer-owner", "customer-owner", "", "", "tenant_other"},
			{"ordinary-operator", "ordinary", "", "", "tenant_lab_001"},
		} {
			t.Run(tc.name+suffix, func(t *testing.T) {
				w := request(tc.who, tc.header, "/admin/logs/audit"+suffix+"?"+tc.query)
				if w.Code != 200 {
					t.Fatalf("status %d %s", w.Code, w.Body)
				}
				var rows []map[string]any
				if suffix == "" {
					var body struct {
						Rows    []map[string]any  `json:"rows"`
						Filters map[string]string `json:"filters"`
					}
					if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
						t.Fatal(err)
					}
					rows = body.Rows
					if body.Filters["tenant_id"] != tc.scope {
						t.Fatalf("scope %v", body.Filters)
					}
				} else {
					for _, line := range bytes.Split(bytes.TrimSpace(w.Body.Bytes()), []byte("\n")) {
						var row map[string]any
						if err := json.Unmarshal(line, &row); err != nil {
							t.Fatal(err)
						}
						rows = append(rows, row)
					}
				}
				count := 1
				if tc.scope == "deployment" {
					count = 2
				}
				if len(rows) != count {
					t.Fatalf("rows %v", rows)
				}
				for _, row := range rows {
					if row["tenant_id"] != tc.scope {
						t.Fatalf("foreign row %v", row)
					}
				}
			})
		}
	}
	after, _ := os.ReadFile(filepath.Join(root, "audit.log.jsonl"))
	if !bytes.Equal(before, after) {
		t.Fatal("metadata reads created change records")
	}
	// Two pages in the reserved scope do not mix the operator's or a customer's records.
	first := request("operator", "", "/admin/logs/audit?audit_scope=deployment&limit=1")
	var page map[string]any
	if json.Unmarshal(first.Body.Bytes(), &page) != nil {
		t.Fatal(first.Body)
	}
	if first.Code == 200 && page["next_cursor"] != nil {
		second := request("operator", "", "/admin/logs/audit?audit_scope=deployment&limit=1&cursor="+page["next_cursor"].(string))
		var next map[string]any
		if second.Code != 200 || json.Unmarshal(second.Body.Bytes(), &next) != nil {
			t.Fatalf("page 2 %d %s", second.Code, second.Body)
		}
		firstRow := page["rows"].([]any)[0].(map[string]any)
		nextRows := next["rows"].([]any)
		if len(nextRows) != 1 || nextRows[0].(map[string]any)["tenant_id"] != "deployment" || nextRows[0].(map[string]any)["id"] == firstRow["id"] || next["next_cursor"] != nil {
			t.Fatalf("page 2 crossed scope or repeated a row: %s", second.Body)
		}
	} else {
		t.Error("deployment paging unavailable", first.Body)
	}
	for _, suffix := range []string{"", "/export"} {
		for _, tc := range []struct {
			who, header, stream, query string
			status                     int
		}{
			{"ordinary", "", "audit", "audit_scope=deployment", 403}, {"customer-owner", "", "audit", "audit_scope=deployment", 403},
			{"operator", "tenant_lab_001", "audit", "audit_scope=deployment", 403}, {"operator", "tenant_other", "audit", "audit_scope=deployment", 403},
			{"operator", "", "access", "audit_scope=deployment", 400}, {"operator", "", "audit", "audit_scope=other", 400}, {"operator", "", "audit", "audit_scope=", 400},
			{"operator", "", "audit", "audit_scope=tenant&audit_scope=deployment", 400}, {"operator", "", "audit", "audit_scope=deployment&audit_scope=tenant", 400},
			{"readless", "", "audit", "audit_scope=deployment", 403}, {"", "", "audit", "audit_scope=deployment", 401},
		} {
			t.Run("refuse/"+suffix+"/"+tc.who+"/"+tc.header+"/"+tc.stream+"/"+tc.query, func(t *testing.T) {
				w := request(tc.who, tc.header, "/admin/logs/"+tc.stream+suffix+"?"+tc.query)
				if w.Code != tc.status || strings.Contains(w.Body.String(), "deployment-a") || strings.Contains(w.Body.String(), "own-a") || strings.Contains(w.Body.String(), "other-a") {
					t.Fatalf("status %d want %d: %s", w.Code, tc.status, w.Body)
				}
			})
		}
	}
	if w := request("exportless", "", "/admin/logs/audit/export?audit_scope=deployment"); w.Code != 403 {
		t.Fatalf("export permission %d %s", w.Code, w.Body)
	}
	if w := request("exportless", "", "/admin/logs/audit?audit_scope=deployment"); w.Code != 200 {
		t.Fatalf("read permission %d %s", w.Code, w.Body)
	}
	operatorTenantAuthority.Store("")
	for _, suffix := range []string{"", "/export"} {
		if w := request("operator", "", "/admin/logs/audit"+suffix+"?audit_scope=deployment"); w.Code != 403 {
			t.Fatalf("missing configured operator %d %s", w.Code, w.Body)
		}
	}
	final, err := os.ReadFile(filepath.Join(root, "audit.log.jsonl"))
	if err != nil || !bytes.HasPrefix(final, before) {
		t.Fatal("reads altered pre-existing audit records", err)
	}
	// Route-permission refusals retain their existing audits. Anonymous GETs
	// without credentials do not create an authentication-failure record.
	// Successful reads above add no records, and neither path is a configuration change.
	refusals := map[string]int{}
	for _, line := range bytes.Split(bytes.TrimSpace(final[len(before):]), []byte("\n")) {
		var row map[string]any
		if err := json.Unmarshal(line, &row); err != nil {
			t.Fatal(err)
		}
		event, _ := row["event_type"].(string)
		if event != "admin_rbac_denied" {
			t.Fatalf("read created an unexpected audit event: %v", row)
		}
		refusals[event]++
	}
	if refusals["admin_rbac_denied"] != 3 {
		t.Fatalf("refusal audits %v", refusals)
	}

}
