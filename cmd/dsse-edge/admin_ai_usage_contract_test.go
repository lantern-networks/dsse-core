package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/hotstore"
	"github.com/lantern-networks/dsse-core/logs"
)

// Synthetic access records go through the real JSONL store and HTTP report.
// Session totals deliberately union buckets per service, not per person.
func aiUsageReviewRows(now time.Time) []map[string]any {
	base := now.UTC().Truncate(30 * time.Minute).Add(-4 * time.Hour)
	rows := aiParityRows()
	original := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	for i, row := range rows {
		at, _ := time.Parse(time.RFC3339, row["timestamp"].(string))
		row["timestamp"] = base.Add(at.Sub(original)).Format(time.RFC3339)
		row["tenant_id"] = "tenant_lab_001"
		row["id"] = fmt.Sprintf("ai-review-%d", i)
		if row["saas_application_id"] == "saas_anthropic_claude" {
			row["saas_name"] = "Anthropic Claude"
		} else {
			row["saas_name"] = "ChatGPT"
		}
	}
	add := func(id, tenant, user, destination string, at time.Time, sent, received int) {
		rows = append(rows, map[string]any{"id": id, "tenant_id": tenant, "timestamp": at.Format(time.RFC3339), "user_id": user, "device_id": "review-device", "destination": destination,
			"metadata": map[string]any{"http_method": "POST", "ai_app": "browser", "bytes_sent": sent, "bytes_received": received}})
	}
	add("ai-day3", "tenant_lab_001", "alice", "api.anthropic.com", base.Add(-3*24*time.Hour), 400, 800)
	add("ai-day20", "tenant_lab_001", "bob", "chatgpt.com", base.Add(-20*24*time.Hour), 800, 1600)
	add("ai-day40", "tenant_lab_001", "alice", "claude.ai", base.Add(-40*24*time.Hour), 1600, 3200)
	add("ai-foreign", "tenant_other", "foreign-user", "claude.ai", base.Add(85*time.Minute), 9000, 9000)
	add("non-ai", "tenant_lab_001", "alice", "claude.ai.example.invalid", base.Add(90*time.Minute), 300, 300)
	add("ai-personal", "tenant_lab_001", "", "chatgpt.com", base.Add(80*time.Minute), 20, 40)
	rows[len(rows)-1]["metadata"].(map[string]any)["ai_account"] = "personal@gmail.com"
	sort.Slice(rows, func(i, j int) bool { return rows[i]["timestamp"].(string) < rows[j]["timestamp"].(string) })
	return rows
}

func aiUsageReviewWriter(t *testing.T, dir string, now time.Time) *logs.Writer {
	t.Helper()
	w, err := logs.NewWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range aiUsageReviewRows(now) {
		if err := w.Append("access.log.jsonl", row); err != nil {
			t.Fatal(err)
		}
	}
	return w
}

func TestAdminAIUsageRecordedWindows(t *testing.T) {
	w := aiUsageReviewWriter(t, t.TempDir(), time.Now())
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: w})
	for _, tc := range []struct {
		window                   string
		accesses, sessions, rows int
		sent, received           int64
	}{
		{"24h", 6, 4, 7, 255, 1665}, {"7d", 7, 5, 8, 655, 2465}, {"30d", 8, 6, 9, 1455, 4065},
	} {
		t.Run(tc.window, func(t *testing.T) {
			r := httptest.NewRecorder()
			h.ServeHTTP(r, httptest.NewRequest("GET", "/admin/ai-usage-report?window="+tc.window+"&tenant_id=tenant_other", nil))
			if r.Code != 200 {
				t.Fatal(r.Code, r.Body.String())
			}
			var report aiUsageReport
			if err := json.Unmarshal(r.Body.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			if report.TenantID != "tenant_lab_001" || report.TotalAIAccesses != tc.accesses || report.TotalAISessions != tc.sessions || report.TotalBytesSent != tc.sent || report.TotalBytesReceived != tc.received || report.Coverage.Rows != tc.rows || report.Coverage.Truncated || report.Window.Requested != tc.window {
				t.Fatalf("unexpected report: %+v", report)
			}
			for _, row := range report.ByActivity {
				if row.Identity == "foreign-user" {
					t.Fatal("foreign activity")
				}
			}
		})
	}
	for _, query := range []string{"window=90d", "window=7d&from=2026-01-01T00:00:00Z"} {
		r := httptest.NewRecorder()
		h.ServeHTTP(r, httptest.NewRequest("GET", "/admin/ai-usage-report?"+query, nil))
		if r.Code != http.StatusBadRequest {
			t.Fatal(query, r.Code)
		}
	}
}

type aiUsageContractRows struct {
	hotstore.Store
	calls int
	err   error
}

func (s *aiUsageContractRows) ExportRows(ctx context.Context, q hotstore.SearchQuery, yield hotstore.RowHandler) (hotstore.ExportResult, error) {
	s.calls++
	if s.err != nil {
		return hotstore.ExportResult{}, s.err
	}
	return s.Store.ExportRows(ctx, q, yield)
}

type aiUsageContractGroups struct {
	hotstore.Store
	calls int
	query hotstore.FieldGroupQuery
	err   error
}

func (s *aiUsageContractGroups) GroupRowsByFields(_ context.Context, q hotstore.FieldGroupQuery) (hotstore.FieldGroupResult, error) {
	s.calls++
	s.query = q
	return hotstore.FieldGroupResult{Truncated: true}, s.err
}

func TestAdminAIUsageContextAndFailures(t *testing.T) {
	oldAggregate := aiUsageAggregateEnabled
	aiUsageAggregateEnabled = true
	t.Cleanup(func() { aiUsageAggregateEnabled = oldAggregate })
	for _, grouped := range []bool{false, true} {
		t.Run(fmt.Sprint("aggregate=", grouped), func(t *testing.T) {
			w := aiUsageReviewWriter(t, t.TempDir(), time.Now())
			base := hotstore.NewJSONLStore(w, map[string]string{"access": "access.log.jsonl"})
			rows := &aiUsageContractRows{Store: base}
			groups := &aiUsageContractGroups{Store: base}
			var store hotstore.Store = rows
			if grouped {
				store = groups
			}
			auth := newAdminAuthStore()
			for _, tenant := range []string{"tenant_lab_001", "tenant_other", "tenant_empty"} {
				auth.UpsertPrincipal(adminPrincipal{ID: tenant, TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
				auth.UpsertSession(adminSession{ID: tenant, TenantID: tenant, AdminPrincipalID: tenant, Roles: []string{"admin"}, Status: "active", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
			}
			auth.UpsertAPIToken(adminAPIToken{ID: "limited", TokenHash: adminTokenHash("limited"), TenantID: "tenant_lab_001", CreatedByAdminPrincipalID: "tenant_lab_001", Roles: []string{"admin"}, Scopes: []string{"admin.logs.read"}, Status: "active", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
			h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: w, AdminAuth: auth, HotStore: store})
			request := func(tenant, query string) *httptest.ResponseRecorder {
				r := httptest.NewRequest("GET", "/admin/ai-usage-report?window=7d"+query, nil)
				if tenant != "" && tenant != "limited" {
					r.AddCookie(&http.Cookie{Name: "admin_session", Value: tenant})
				}
				if tenant == "limited" {
					r.Header.Set("Authorization", "Bearer limited")
				}
				res := httptest.NewRecorder()
				h.ServeHTTP(res, r)
				return res
			}
			for _, tc := range []struct {
				tenant, query string
				code          int
			}{
				{"tenant_lab_001", "&expected_tenant_id=tenant_other", 409}, {"", "", 401}, {"limited", "", 403},
			} {
				r := request(tc.tenant, tc.query)
				if r.Code != tc.code {
					t.Fatal(tc, r.Code, r.Body.String())
				}
			}
			if rows.calls+groups.calls != 0 {
				t.Fatal("refused requests reached hot store")
			}
			for _, tenant := range []string{"tenant_lab_001", "tenant_other", "tenant_empty"} {
				for _, query := range []string{"", "&expected_tenant_id=" + tenant} {
					r := request(tenant, query)
					if r.Code != 200 {
						t.Fatal(r.Code, r.Body.String())
					}
					var d aiUsageReport
					if err := json.Unmarshal(r.Body.Bytes(), &d); err != nil {
						t.Fatal(err)
					}
					if d.TenantID != tenant || d.Services == nil || d.ByActivity == nil {
						t.Fatalf("invalid tenant or arrays: %+v", d)
					}
					if grouped {
						if d.Coverage.Source != "aggregate" || d.Coverage.RowCap != 0 || !d.Coverage.Truncated || groups.query.TenantID != tenant || groups.query.From == nil || groups.query.To == nil {
							t.Fatal(d.Coverage, groups.query)
						}
					} else {
						want := 7
						if tenant == "tenant_other" {
							want = 1
						}
						if tenant == "tenant_empty" {
							want = 0
						}
						if d.TotalAIAccesses != want {
							t.Fatalf("%s accesses %d want %d", tenant, d.TotalAIAccesses, want)
						}
					}
				}
			}
			rows.err = fmt.Errorf("synthetic store error")
			groups.err = rows.err
			if r := request("tenant_lab_001", ""); r.Code != 500 {
				t.Fatal(r.Code, r.Body.String())
			}
			rows.err = nil
			groups.err = nil
			if r := request("tenant_lab_001", ""); r.Code != 200 {
				t.Fatal(r.Code, r.Body.String())
			}
		})
	}
}

func TestAdminAIUsageCoverageCap(t *testing.T) {
	old := aiUsageReportRowCap
	aiUsageReportRowCap = 3
	t.Cleanup(func() { aiUsageReportRowCap = old })
	w := aiUsageReviewWriter(t, t.TempDir(), time.Now())
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: w})
	r := httptest.NewRecorder()
	h.ServeHTTP(r, httptest.NewRequest("GET", "/admin/ai-usage-report?window=30d", nil))
	var d aiUsageReport
	if err := json.Unmarshal(r.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	if r.Code != 200 || !d.Coverage.Truncated || d.Coverage.Rows != 3 || d.Coverage.RowCap != 3 || d.Coverage.From <= d.Window.From || d.TotalAIAccesses != 2 || d.TotalAISessions != 2 || d.TotalBytesSent != 25 || d.TotalBytesReceived != 45 {
		t.Fatal(r.Code, r.Body.String())
	}
}
