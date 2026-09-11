package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

func TestDLPRuleRuntimeStoreHotSwap(t *testing.T) {
	s := newDLPRuleRuntimeStore()
	if s.RulesForTenant("t1") != nil {
		t.Fatalf("new store not empty")
	}
	s.SetRules("t1", []model.DLPRule{{ID: "r1", Identifiers: []string{"my_number"}, OnMatch: "block", Status: "active"}})
	s.SetRules("t2", []model.DLPRule{{ID: "r2", Identifiers: []string{"credit_card"}, OnMatch: "observe", Status: "active"}})
	if got := s.RulesForTenant("t1"); len(got) != 1 || got[0].ID != "r1" {
		t.Errorf("t1 rules = %+v", got)
	}
	// replace t1; t2 untouched
	s.SetRules("t1", nil)
	if s.RulesForTenant("t1") != nil {
		t.Errorf("t1 not replaced")
	}
	if len(s.RulesForTenant("t2")) != 1 {
		t.Errorf("t2 disturbed")
	}
}

func TestOverlayRuntimeDLPRules(t *testing.T) {
	base := decision.Evaluator{PolicyBundle: model.PolicyBundle{
		TenantID: "t1",
		DLPRules: []model.DLPRule{{ID: "bundle1"}},
	}}
	store := newDLPRuleRuntimeStore()
	store.SetRules("t1", []model.DLPRule{{ID: "runtime1"}})

	merged := overlayRuntimeDLPRules(base, store)
	if len(merged.PolicyBundle.DLPRules) != 2 {
		t.Fatalf("merged rules = %d, want 2", len(merged.PolicyBundle.DLPRules))
	}
	if len(base.PolicyBundle.DLPRules) != 1 {
		t.Errorf("base bundle mutated: %d rules", len(base.PolicyBundle.DLPRules))
	}
	// nil store / no rules => unchanged
	if got := overlayRuntimeDLPRules(base, nil); len(got.PolicyBundle.DLPRules) != 1 {
		t.Errorf("nil store should not change rules")
	}
}

func TestAdminDLPRulesEndpoint(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer})

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/admin/dlp-rules", strings.NewReader(body))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	rec := post(`{"rules":[{"id":"r1","saas_application_id":"saas_openai_chatgpt","identifiers":["my_number"],"on_match":"block"}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST status = %d, body=%s", rec.Code, rec.Body.String())
	}

	getRec := httptest.NewRecorder()
	handler.ServeHTTP(getRec, httptest.NewRequest(http.MethodGet, "/admin/dlp-rules", nil))
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET status = %d", getRec.Code)
	}
	var out struct {
		Rules []model.DLPRule `json:"rules"`
	}
	if err := json.Unmarshal(getRec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Rules) != 1 || out.Rules[0].OnMatch != "block" || out.Rules[0].SaaSApplicationID != "saas_openai_chatgpt" {
		t.Errorf("round-trip failed: %+v", out.Rules)
	}

	if bad := post(`{"rules":[{"identifiers":["my_number"],"on_match":"nuke"}]}`); bad.Code != http.StatusBadRequest {
		t.Errorf("invalid on_match: status = %d, want 400", bad.Code)
	}
}
