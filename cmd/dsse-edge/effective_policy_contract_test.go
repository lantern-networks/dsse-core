package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/inspectionposture"
	"github.com/lantern-networks/dsse-core/model"
)

func effectivePolicyTestHandler() http.Handler {
	eval := decision.Evaluator{
		PolicyBundle: model.PolicyBundle{TenantID: "tenant_lab_001"},
		Policies: []model.Policy{
			{ID: "pol_google_workspace_swg_allow_001", TenantID: "tenant_lab_001", Status: "active", Priority: 100,
				Conditions: map[string]any{"sni": "accounts.google.com"}, Action: model.PolicyAction{Decision: "allow"}},
		},
	}
	return newServerWithConfig(serverConfig{Evaluator: eval, Registry: connector.NewRegistry(), AdminAuth: newAdminAuthStore()})
}

func TestEffectivePolicyAndPostureOpenAPIContract(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "openapi", "admin_api.yaml"))
	if err != nil {
		t.Fatalf("read admin OpenAPI contract: %v", err)
	}
	contract := string(data)
	for _, want := range []string{
		"  /admin/effective-policy:",
		"  /admin/effective-policies:",
		"  /admin/policies/{policy_id}/status:",
		"  /admin/catalog-groups:",
		"  /admin/inspection-posture:",
		"known_bypass_enabled",
		"admin.policy.read",
		"admin.policy.write",
	} {
		if !strings.Contains(contract, want) {
			t.Fatalf("admin OpenAPI contract missing %q", want)
		}
	}
}

func TestEffectivePolicyEndpoint(t *testing.T) {
	handler := effectivePolicyTestHandler()

	// Missing destination -> 400.
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/effective-policy", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing destination: status=%d want 400, body=%s", rec.Code, rec.Body.String())
	}

	// With destination -> 200, the built-in policy wins and is tagged built_in; inspection is inspect.
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/effective-policy?destination=accounts.google.com", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%s", rec.Code, rec.Body.String())
	}
	var resp effectivePolicyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode effective-policy: %v", err)
	}
	if resp.WinnerPolicyID != "pol_google_workspace_swg_allow_001" || resp.WinnerDecision != "allow" {
		t.Fatalf("winner=%q/%q, want the built-in google allow", resp.WinnerPolicyID, resp.WinnerDecision)
	}
	if len(resp.Trace) == 0 || resp.Trace[0].Source != "built_in" || !resp.Trace[0].Winner {
		t.Fatalf("trace[0]=%+v, want built_in winner", resp.Trace)
	}
	if resp.Inspection.Decision != "inspect" || resp.Inspection.Source != "default_decrypt_all" {
		t.Fatalf("inspection=%+v, want inspect/default_decrypt_all", resp.Inspection)
	}
}

func TestEffectivePolicyListEndpoint(t *testing.T) {
	handler := effectivePolicyTestHandler()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/effective-policies", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%s", rec.Code, rec.Body.String())
	}
	var resp effectivePolicyListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(resp.Policies) == 0 {
		t.Fatalf("expected at least the built-in policy in the listing")
	}
	var found bool
	for _, p := range resp.Policies {
		if p.PolicyID == "pol_google_workspace_swg_allow_001" {
			found = true
			if p.Source != "built_in" || p.Decision != "allow" {
				t.Fatalf("built-in policy mis-tagged: %+v", p)
			}
		}
	}
	if !found {
		t.Fatalf("the built-in policy should appear in the full listing")
	}
}

func TestCatalogGroupsEndpoint(t *testing.T) {
	handler := effectivePolicyTestHandler()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/catalog-groups", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", rec.Code)
	}
	var resp struct {
		Groups []struct {
			Name, Category, Axis string
			Patterns             []string
		} `json:"groups"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var haveOpenAI, haveOptimize bool
	for _, g := range resp.Groups {
		if g.Name == "openai" && g.Axis == "decrypt" && g.Category == "ai" && len(g.Patterns) > 0 {
			haveOpenAI = true
		}
		if g.Name == "m365_optimize" && g.Axis == "bypass" {
			haveOptimize = true
		}
	}
	if !haveOpenAI || !haveOptimize {
		t.Fatalf("catalog-groups should include openai(decrypt/ai) + m365_optimize(bypass): %+v", resp.Groups)
	}
}

func TestPolicyStatusEndpointValidation(t *testing.T) {
	handler := effectivePolicyTestHandler()
	// Invalid status -> 400.
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/admin/policies/pol_x/status", strings.NewReader(`{"status":"garbage"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid status: %d want 400, body=%s", rec.Code, rec.Body.String())
	}
	// Unknown policy (no matching tenant/id) -> 404.
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/admin/policies/pol_absent/status", strings.NewReader(`{"status":"disabled"}`)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("absent policy: %d want 404, body=%s", rec.Code, rec.Body.String())
	}
}

func TestInspectionPostureEndpointNoEngine(t *testing.T) {
	handler := effectivePolicyTestHandler()

	// GET with no interception engine wired -> 200, default posture (decrypt_all), presets listed.
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/inspection-posture", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET posture status=%d want 200, body=%s", rec.Code, rec.Body.String())
	}
	var posture inspectionPostureResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &posture); err != nil {
		t.Fatalf("decode posture: %v", err)
	}
	if posture.DefaultMode != "decrypt_all" {
		t.Fatalf("default_mode=%q want decrypt_all (default posture)", posture.DefaultMode)
	}
	if len(posture.KnownBypassGroups) == 0 || len(posture.AuthDecryptGroups) == 0 {
		t.Fatalf("posture should list curated known-bypass groups AND auth-decrypt presets")
	}

	// POST with no engine wired -> 409 (not configurable), whatever the body.
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/admin/inspection-posture", strings.NewReader(`{"mode":"bypass_default"}`)))
	if rec.Code != http.StatusConflict {
		t.Fatalf("POST posture (no engine) status=%d want 409, body=%s", rec.Code, rec.Body.String())
	}
}

func TestInspectionPostureToggleFullPosture(t *testing.T) {
	store := inspectionposture.NewStore()
	eval := decision.Evaluator{PolicyBundle: model.PolicyBundle{TenantID: "tenant_lab_001"}}
	handler := newServerWithConfig(serverConfig{
		Evaluator: eval, Registry: connector.NewRegistry(), AdminAuth: newAdminAuthStore(),
		InspectionPosture:    func() inspectionposture.Posture { return store.Get() },
		SetInspectionPosture: func(p inspectionposture.Posture, _ string) (inspectionposture.Posture, error) { return store.Set(p) },
	})
	post := func(body string) (int, inspectionPostureResponse) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/admin/inspection-posture", strings.NewReader(body)))
		var resp inspectionPostureResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		return rec.Code, resp
	}

	// Switch to bypass-default with the m365 auth preset + an Optimize bypass group + known-bypass off.
	code, resp := post(`{"mode":"bypass_default","decrypt_allowlist_groups":["m365_auth"],"bypass_groups":["m365_optimize"],"known_bypass_enabled":false}`)
	if code != http.StatusOK {
		t.Fatalf("switch to bypass_default status=%d, want 200", code)
	}
	if resp.DefaultMode != "bypass_default" || resp.KnownBypassEnabled {
		t.Fatalf("posture not applied: mode=%q known_bypass=%v", resp.DefaultMode, resp.KnownBypassEnabled)
	}
	if len(resp.DecryptAllowlistGroups) != 1 || resp.DecryptAllowlistGroups[0] != "m365_auth" {
		t.Fatalf("decrypt_allowlist_groups=%v want [m365_auth]", resp.DecryptAllowlistGroups)
	}
	if len(resp.BypassGroups) != 1 || resp.BypassGroups[0] != "m365_optimize" {
		t.Fatalf("bypass_groups=%v want [m365_optimize]", resp.BypassGroups)
	}
	if len(resp.SaaSBypassGroups) == 0 {
		t.Fatalf("saas_bypass_groups presets should be listed")
	}

	// Partial update: flip known-bypass back on; mode + allowlist must persist (not be wiped).
	code, resp = post(`{"known_bypass_enabled":true}`)
	if code != http.StatusOK || !resp.KnownBypassEnabled || resp.DefaultMode != "bypass_default" || len(resp.DecryptAllowlistGroups) != 1 || len(resp.BypassGroups) != 1 {
		t.Fatalf("partial update did not preserve other fields: %+v", resp)
	}

	// Invalid mode -> 400.
	code, _ = post(`{"mode":"garbage"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("invalid mode status=%d, want 400", code)
	}
}
