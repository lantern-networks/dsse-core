package main

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/swg"
)

func TestLegacyTenantRestrictionUpdateResponseIsTenantScoped(t *testing.T) {
	store := policy.NewStore(nil)
	if err := store.SetRuntimeStatePath(filepath.Join(t.TempDir(), "runtime.json")); err != nil {
		t.Fatal(err)
	}
	bundle := model.PolicyBundle{TenantID: "operator", SWGTenantRestrictionRules: []model.SWGTenantRestrictionRule{
		{ID: "own", TenantID: "customer", SaaSApplicationID: "own-app", HeaderValueRef: "operator_config_ref:own", Status: "active"},
		{ID: "other", TenantID: "other-customer", SaaSApplicationID: "private-other-app", HeaderValueRef: "operator_config_ref:private-other", Status: "active"},
	}}
	mux := http.NewServeMux()
	registerSWGTenantRestrictionRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, decision.Evaluator{PolicyBundle: bundle}, nil, store,
		swg.RuntimeConfig{TenantRestrictionOperatorConfigRefs: []string{"operator_config_ref:own", "operator_config_ref:private-other"}}, nil, "")
	w := managedTRRequest(mux, "customer", "POST", `{"saas_enablement":{"own-app":false}}`)
	if w.Code != http.StatusOK {
		t.Fatalf("own update failed: %d %s", w.Code, w.Body.String())
	}
	for _, forbidden := range []string{"other-customer", "private-other", `"tenant_id":"operator"`} {
		if strings.Contains(w.Body.String(), forbidden) {
			t.Fatalf("successful update exposed foreign status: %s", forbidden)
		}
	}
}
