package main

import (
	"encoding/json"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/swg"
	"github.com/lantern-networks/dsse-core/swghttprewrite"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mixedHeaderFixture(t *testing.T) (swg.RuntimeConfig, model.PolicyBundle, *policy.Store) {
	t.Helper()
	ref := "operator_config_ref:allowed"
	rule := model.SWGTenantRestrictionRule{ID: "rule", TenantID: "tenant", SaaSApplicationID: "app", Provider: "google_workspace", HeaderName: "X-GoogApps-Allowed-Domains", HeaderValueRef: ref, HeaderValueKind: "configured_allowed_domains", Status: "active"}
	bundle := model.PolicyBundle{TenantID: "tenant", SWGTenantRestrictionRules: []model.SWGTenantRestrictionRule{rule}}
	config := swghttprewrite.OperatorManagedHeaderValueConfig{SchemaVersion: swghttprewrite.SWGOperatorConfigSchemaVersion, Status: "active", TenantID: "tenant", Metadata: map[string]any{"designated_operator_config_file": true}, HeaderValues: []swghttprewrite.OperatorManagedHeaderValue{{Ref: ref, TenantID: "tenant", SaaSApplicationID: "app", Provider: rule.Provider, HeaderName: rule.HeaderName, HeaderValueKind: rule.HeaderValueKind, Value: "old.example", Status: "active", Metadata: map[string]any{"operator_managed": true}}}}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "operator.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	runtime, err := swg.LoadRuntimeConfig(swg.RuntimeConfigInput{PolicyBundle: bundle, TenantRestrictionOperatorConfigPath: path})
	if err != nil {
		t.Fatal(err)
	}
	s := policy.NewStore(nil)
	if err = s.SetRuntimeStatePath(filepath.Join(t.TempDir(), "runtime.json")); err != nil {
		t.Fatal(err)
	}
	return runtime, bundle, s
}
func TestLegacyHeaderHTTPFailedSaveAndRetry(t *testing.T) {
	runtime, bundle, s := mixedHeaderFixture(t)
	disk := &legacyToggleDisk{fail: true}
	if err := s.SetRuntimeStatePersister(disk); err != nil {
		t.Fatal(err)
	}
	ev := testEvaluator()
	ev.PolicyBundle = bundle
	h := newServerWithConfig(serverConfig{Evaluator: ev, PolicyStore: s, SWGRuntime: runtime, AdminAuth: newAdminAuthStore()})
	body := `{"header_value_updates":{"operator_config_ref:allowed":"new.example"},"saas_enablement":{"app":false}}`
	call := func(want int) {
		t.Helper()
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest("POST", "/admin/swg/tenant-restriction", strings.NewReader(body)))
		if rr.Code != want {
			t.Fatalf("HTTP %d want %d: %s", rr.Code, want, rr.Body)
		}
		if strings.Contains(rr.Body.String(), "synthetic private") {
			t.Fatal("storage detail leaked")
		}
	}
	call(503)
	if value, _ := runtime.TenantRestrictionResolver.ResolveHeaderValue("operator_config_ref:allowed"); value != "old.example" {
		t.Fatal("failed save changed live header")
	}
	disk.fail = false
	call(200)
	if value, _ := runtime.TenantRestrictionResolver.ResolveHeaderValue("operator_config_ref:allowed"); value != "new.example" {
		t.Fatal("retry did not apply header")
	}
	if s.TenantRestrictionRuleStatusOverrides()["rule"] != "inactive" {
		t.Fatal("retry did not disable rule")
	}
}
