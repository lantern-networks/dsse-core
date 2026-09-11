package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
)

func TestAdminLogQueryFiltersAndLimits(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	rows := []map[string]any{
		{"id": "alog_001", "tenant_id": "tenant_lab_001", "access_decision_id": "dec_001", "decision": "allow", "application_id": "app_dummy_https", "actor_type": "human"},
		{"id": "alog_002", "tenant_id": "tenant_lab_001", "access_decision_id": "dec_002", "decision": "deny", "application_id": "app_admin_rdp", "actor_type": "human"},
		{"id": "alog_003", "tenant_id": "tenant_lab_001", "access_decision_id": "dec_003", "decision": "deny", "application_id": "app_dummy_https", "actor_type": "delegated_agent"},
	}
	for _, row := range rows {
		if err := writer.Append("access.log.jsonl", row); err != nil {
			t.Fatalf("append access log returned error: %v", err)
		}
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Writer:    writer,
		Registry:  connector.NewRegistry(),
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/logs/access?decision=deny&limit=1", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var result map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode log query: %v", err)
	}
	if _, ok := result["filename"]; ok {
		t.Fatalf("result leaked filename: %#v", result)
	}
	if result["total_matches"] != float64(2) || result["returned"] != float64(1) {
		t.Fatalf("result summary = %#v", result)
	}
	returnedRows, ok := result["rows"].([]any)
	if !ok || len(returnedRows) != 1 {
		t.Fatalf("rows = %#v", result["rows"])
	}
	first, ok := returnedRows[0].(map[string]any)
	if !ok || first["access_decision_id"] != "dec_003" {
		t.Fatalf("first row = %#v, want newest deny row", returnedRows[0])
	}
}

func TestAdminLogQueryScopesTenant(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	for _, row := range []map[string]any{
		{"id": "alog_001", "tenant_id": "tenant_lab_001", "access_decision_id": "dec_001", "decision": "deny"},
		{"id": "alog_002", "tenant_id": "tenant_other_001", "access_decision_id": "dec_002", "decision": "deny"},
	} {
		if err := writer.Append("access.log.jsonl", row); err != nil {
			t.Fatalf("append access log returned error: %v", err)
		}
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Writer:    writer,
		Registry:  connector.NewRegistry(),
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/logs/access?decision=deny&tenant_id=tenant_other_001&limit=10", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var result map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode log query: %v", err)
	}
	if result["total_matches"] != float64(1) || result["returned"] != float64(1) {
		t.Fatalf("result summary = %#v", result)
	}
	returnedRows := result["rows"].([]any)
	first := returnedRows[0].(map[string]any)
	if first["tenant_id"] != "tenant_lab_001" || first["access_decision_id"] != "dec_001" {
		t.Fatalf("first row = %#v, want tenant scoped row", first)
	}
	filters := result["filters"].(map[string]any)
	if filters["tenant_id"] != "tenant_lab_001" {
		t.Fatalf("filters = %#v, want forced tenant", filters)
	}
}

func TestAdminLogQueryUsesConfiguredHotStore(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	store := &recordingHotStore{}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Writer:    writer,
		Registry:  connector.NewRegistry(),
		HotStore:  store,
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/logs/access?decision=allow&q=needle&limit=7", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if store.query.TenantID != "tenant_lab_001" || store.query.Stream != "access" || store.query.Limit != 7 || store.query.Text != "needle" {
		t.Fatalf("hot store query = %#v", store.query)
	}
	if store.query.Filters["decision"] != "allow" {
		t.Fatalf("hot store filters = %#v", store.query.Filters)
	}
	var result map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode log query: %v", err)
	}
	if result["total_matches"] != float64(1) || result["returned"] != float64(1) {
		t.Fatalf("result = %#v", result)
	}
	if _, ok := result["next_cursor"]; !ok {
		t.Fatalf("result = %#v, want next_cursor field", result)
	}
}

func TestAdminLogExportReturnsTenantScopedJSONL(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	for _, row := range []map[string]any{
		{"id": "audit_001", "tenant_id": "tenant_lab_001", "event_type": "tool_call_event_recorded"},
		{"id": "audit_002", "tenant_id": "tenant_other_001", "event_type": "tool_call_event_recorded"},
	} {
		if err := writer.Append("audit.log.jsonl", row); err != nil {
			t.Fatalf("append audit log returned error: %v", err)
		}
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Writer:    writer,
		Registry:  connector.NewRegistry(),
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/logs/audit/export?event_type=tool_call_event_recorded&limit=10", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !strings.Contains(rec.Result().Header.Get("content-type"), "application/x-ndjson") {
		t.Fatalf("content-type = %q, want ndjson", rec.Result().Header.Get("content-type"))
	}
	if rec.Result().Header.Get("x-export-mode") != "preview" || rec.Result().Header.Get("x-export-limit") != "10" {
		t.Fatalf("export headers = %#v, want preview limit 10", rec.Result().Header)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"id":"audit_001"`) || strings.Contains(body, `"id":"audit_002"`) {
		t.Fatalf("body = %s, want tenant scoped JSONL", body)
	}
}

func TestAdminLogQueryRejectsUnknownStream(t *testing.T) {
	handler := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/admin/logs/unknown", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
}

func TestAdminLogQueryRejectsFilenameStreamAlias(t *testing.T) {
	handler := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/admin/logs/access.log.jsonl", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
}
