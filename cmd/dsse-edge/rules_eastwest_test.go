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

// Authoring an outbound East-West rule compiles it into the live policy store as a device-restricted
// EastWestRule, unioned with (not clobbering) the legacy admin set, and only when east-west is enabled.
func TestAdminRulesEastWestCompilesToPolicyStore(t *testing.T) {
	tenant := testEvaluator().PolicyBundle.TenantID
	policyStore := policy.NewStore(nil)
	policyStore.SetEastWestEnabled(tenant, true)
	// A pre-existing legacy admin rule must survive authoring.
	policyStore.SetEastWestRules(tenant, []decision.EastWestRule{{ID: "legacy-1", Destinations: []string{"dc.internal"}, Mode: "deny"}})

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
	dbID := mkEndpoint(`{"alias":"prod-db","kind":"network","address":"db.internal"}`)
	var svc map[string]any
	rec := doAdmin(t, handler, http.MethodPost, "/admin/assets/services", `{"alias":"smb","ports":[{"protocol":"tcp","port":445}]}`)
	_ = json.Unmarshal(rec.Body.Bytes(), &svc)
	svcID := svc["id"].(string)

	// Author an outbound east-west authenticate rule: alice-mac -> prod-db : smb.
	body := `{"plane":"east_west","direction":"outbound","priority":100,"source":["` + macID + `"],"destination":["` + dbID + `"],"service_id":"` + svcID + `","action":{"access":"authenticate"}}`
	if rec := doAdmin(t, handler, http.MethodPost, "/admin/rules", body); rec.Code != http.StatusOK {
		t.Fatalf("author east-west rule = %d: %s", rec.Code, rec.Body.String())
	}

	// The live evaluator now carries BOTH the legacy rule and the compiled, device-restricted authored rule.
	eval := policyStore.RuntimeEvaluator(decision.Evaluator{PolicyBundle: model.PolicyBundle{TenantID: tenant}})
	if !eval.EastWestEnabled {
		t.Fatalf("east-west should be enabled")
	}
	var legacy, authored *decision.EastWestRule
	for i := range eval.EastWestRules {
		switch eval.EastWestRules[i].ID {
		case "legacy-1":
			legacy = &eval.EastWestRules[i]
		default:
			authored = &eval.EastWestRules[i]
		}
	}
	if legacy == nil {
		t.Fatalf("legacy rule was clobbered; rules = %#v", eval.EastWestRules)
	}
	if authored == nil {
		t.Fatalf("authored east-west rule did not compile into the store; rules = %#v", eval.EastWestRules)
	}
	if authored.Mode != "authenticate" {
		t.Fatalf("authored mode = %q, want authenticate", authored.Mode)
	}
	if len(authored.SourceDevices) != 1 || authored.SourceDevices[0] != "dev-alice" {
		t.Fatalf("authored source devices = %v, want [dev-alice] (source restricted by device identity)", authored.SourceDevices)
	}
	if !contains(authored.Destinations, "db.internal") {
		t.Fatalf("authored destinations = %v, want db.internal", authored.Destinations)
	}

	// The compiled rule restricts to the named device: it matches alice's device, not another.
	matchReq := func(deviceID string) model.DecisionRequest {
		return model.DecisionRequest{DeviceID: deviceID, Destination: "db.internal", ServiceFamily: "smb", Protocol: "tcp", DestinationPort: 445}
	}
	if _, ok := decision.MatchedEastWestRule([]decision.EastWestRule{*authored}, matchReq("dev-alice")); !ok {
		t.Fatalf("compiled rule should match dev-alice")
	}
	if _, ok := decision.MatchedEastWestRule([]decision.EastWestRule{*authored}, matchReq("dev-mallory")); ok {
		t.Fatalf("compiled rule must NOT match an unlisted device")
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
