package main

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
)

// Authoring an egress deny rule compiles it into the live policy store as a destination-matched,
// device-source-restricted deny policy (unioned with the operator/adopted policies, not clobbering them).
func TestAdminRulesEgressCompilesToPolicyStore(t *testing.T) {
	tenant := testEvaluator().PolicyBundle.TenantID
	policyStore := policy.NewStore(nil)
	handler := newServerWithConfig(serverConfig{
		Evaluator:   testEvaluator(),
		Registry:    connector.NewRegistry(),
		AdminAuth:   newAdminAuthStore(),
		PolicyStore: policyStore,
	})

	mkEndpoint := func(body string) string {
		t.Helper()
		rec := doAdmin(t, handler, http.MethodPost, "/admin/assets/endpoints", body)
		if rec.Code != http.StatusOK {
			t.Fatalf("create endpoint %s = %d: %s", body, rec.Code, rec.Body.String())
		}
		var m map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &m)
		return m["id"].(string)
	}
	macID := mkEndpoint(`{"alias":"alice-mac","kind":"steered_device","platform":"macos","steered":true,"identity":"dev-alice"}`)
	badID := mkEndpoint(`{"alias":"badsite","kind":"network","address":"evil.example.com"}`)

	body := `{"plane":"egress","priority":10,"source":["` + macID + `"],"destination":["` + badID + `"],"action":{"access":"deny"}}`
	if rec := doAdmin(t, handler, http.MethodPost, "/admin/rules", body); rec.Code != http.StatusOK {
		t.Fatalf("author egress deny rule = %d: %s", rec.Code, rec.Body.String())
	}

	eval := policyStore.RuntimeEvaluator(decision.Evaluator{PolicyBundle: model.PolicyBundle{TenantID: tenant}})
	var compiled *model.Policy
	for i := range eval.Policies {
		if eval.Policies[i].Action.Decision == "deny" && eval.Policies[i].Conditions["fqdn"] == "evil.example.com" {
			compiled = &eval.Policies[i]
		}
	}
	if compiled == nil {
		t.Fatalf("authored egress deny did not compile into the policy store; policies = %#v", eval.Policies)
	}
	devs, ok := compiled.Conditions["device_id"].([]any)
	if !ok || len(devs) != 1 || devs[0] != "dev-alice" {
		t.Fatalf("compiled deny device_id = %v, want [dev-alice] (source restricted)", compiled.Conditions["device_id"])
	}
	// (Device gating of this condition shape is proven in decision.TestPolicyDeviceIDCondition.)
}
