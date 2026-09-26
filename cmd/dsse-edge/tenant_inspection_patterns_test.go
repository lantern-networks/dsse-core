package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/inspectionposture"
	"github.com/lantern-networks/dsse-core/knownbypass"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/policyrule"
)

func TestTenantInspectionProductWritesAndReadViews(t *testing.T) {
	oldOperator := operatorTenantConfigured()
	t.Cleanup(func() { operatorTenantAuthority.Store(oldOperator) })
	e := edgeplane.NewNetworkExtensionLabTLSInterceptionMatchOnly([]string{"*"})
	posture := inspectionposture.NewStore()
	rules := policyrule.NewStore()
	assets := assetcatalog.NewStore()
	overrides := knownbypass.NewOverrideStore()
	auth := newAdminAuthStore()
	now := time.Now()
	for _, tenant := range []string{"a", "b"} {
		auth.UpsertPrincipal(adminPrincipal{ID: tenant, TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
		auth.UpsertAPIToken(adminAPIToken{ID: tenant, TenantID: tenant, Roles: []string{"admin"}, Scopes: []string{"*"}, TokenHash: adminTokenHash("token-" + tenant), CreatedByAdminPrincipalID: tenant, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
		if _, err := assets.UpsertEndpoint(assetcatalog.Endpoint{ID: "destination", TenantID: tenant, Kind: assetcatalog.KindNetwork, Address: tenant + ".invalid", Alias: tenant, Source: assetcatalog.SourceManual}); err != nil {
			t.Fatal(err)
		}
	}
	apply := newTenantInspectionApplier(e, posture, rules, assets, overrides, func() []knownbypass.Group { return nil }, []string{"*"}, nil)
	policies := policy.NewStore(nil)
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: auth, OperatorTenantID: "operator", RuleStore: rules, AssetStore: assets, PolicyStore: policies, NetworkExtensionLabTLS: e, InspectionPosture: posture.Get, ApplyInspectionPosture: apply, ApplyMaterializedCertPinBypass: apply})
	call := func(tenant, method, path, body string) []byte {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer token-"+tenant)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s %s: %d %s", tenant, path, w.Code, w.Body)
		}
		return w.Body.Bytes()
	}
	for _, tenant := range []string{"a", "b"} {
		call(tenant, "POST", "/admin/rules", `{"id":"exception","plane":"egress","source":["*"],"destination":["destination"],"action":{"access":"allow","inspection":"bypass"}}`)
	}
	for _, tenant := range []string{"a", "b"} {
		for _, host := range []string{"a.invalid", "b.invalid"} {
			if e.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{TenantID: tenant, Host: host, Port: 443}) != (host != tenant+".invalid") {
				t.Fatal("cross-tenant bypass", tenant, host)
			}
		}
		var p inspectionPostureResponse
		if err := json.Unmarshal(call(tenant, "GET", "/admin/inspection-posture", ""), &p); err != nil {
			t.Fatal(err)
		}
		if p.TenantID != tenant || len(p.EffectiveBypass) != 1 || p.EffectiveBypass[0] != tenant+".invalid" {
			t.Fatal("posture disclosed another tenant", p)
		}
		var bypass []string
		json.Unmarshal(call(tenant, "GET", "/admin/intercept/bypass-hosts", ""), &bypass)
		if len(bypass) != 1 || bypass[0] != tenant+".invalid" {
			t.Fatal("bypass read scope", bypass)
		}
		other := "a.invalid"
		if tenant == "a" {
			other = "b.invalid"
		}
		for _, path := range []string{"/admin/effective-policy?destination=" + tenant + ".invalid", "/admin/egress-effective-rules"} {
			if strings.Contains(string(call(tenant, "GET", path, "")), other) {
				t.Fatal("foreign host in preview", path)
			}
		}
	}
	// Editing one tenant's rule must immediately replace its own selection only.
	for _, edit := range []struct {
		status, inspection string
		wantInspect        bool
	}{
		{"disabled", "bypass", true}, {"active", "bypass", false},
		{"active", "inspect", true}, {"active", "bypass", false},
	} {
		call("a", "POST", "/admin/rules", `{"id":"exception","plane":"egress","source":["*"],"destination":["destination"],"status":"`+edit.status+`","action":{"access":"allow","inspection":"`+edit.inspection+`"}}`)
		if got := e.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{TenantID: "a", Host: "a.invalid", Port: 443}); got != edit.wantInspect {
			t.Fatalf("edit %v: inspect=%v", edit, got)
		}
		if e.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{TenantID: "b", Host: "b.invalid", Port: 443}) {
			t.Fatal("edit changed other tenant")
		}
		var hosts []string
		if err := json.Unmarshal(call("a", "GET", "/admin/intercept/bypass-hosts", ""), &hosts); err != nil {
			t.Fatal(err)
		}
		if (len(hosts) == 0) != edit.wantInspect {
			t.Fatalf("stale readback after edit %v: %v", edit, hosts)
		}
	}
	call("b", "DELETE", "/admin/rules/exception", "")
	if e.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{TenantID: "a", Host: "a.invalid", Port: 443}) || !e.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{TenantID: "b", Host: "b.invalid", Port: 443}) {
		t.Fatal("last-rule deletion changed another tenant or retained bypass")
	}
	src := configBundleSource{tenantID: "operator"}
	if _, err := src.apply(configBundlePayload{Rules: &authoredRuleBundle{}}, configApplyTargets{policyStore: policies, rules: rules, onRulesApplied: func() { apply("") }}); err != nil {
		t.Fatal(err)
	}
	if !e.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{TenantID: "a", Host: "a.invalid", Port: 443}) {
		t.Fatal("empty bundle retained stale tenant snapshot")
	}
}

func TestTenantInspectionDefaultsAndCatalogOverridesRefreshTogether(t *testing.T) {
	e := edgeplane.NewNetworkExtensionLabTLSInterceptionMatchOnly(nil)
	p := inspectionposture.NewStore()
	r := policyrule.NewStore()
	a := assetcatalog.NewStore()
	o := knownbypass.NewOverrideStore()
	groups := []knownbypass.Group{{ID: "apple_push", Patterns: []string{"system.invalid"}}}
	apply := newTenantInspectionApplier(e, p, r, a, o, func() []knownbypass.Group { return groups }, []string{"*"}, []string{"operator.invalid"})
	if _, err := o.Set("a", knownbypass.Override{EntryID: "apple_push", Mode: knownbypass.OverrideForceInspect}, time.Now()); err != nil {
		t.Fatal(err)
	}
	apply("a")
	for _, tenant := range []string{"a", "b", ""} {
		if got := e.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{TenantID: tenant, Host: "system.invalid", Port: 443}); got != (tenant == "a") {
			t.Fatal("catalog override crossed tenant", tenant)
		}
		if e.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{TenantID: tenant, Host: "operator.invalid", Port: 443}) {
			t.Fatal("deployment bypass lost")
		}
	}
	for _, tenant := range []string{"a", "b"} {
		if _, err := a.UpsertEndpoint(assetcatalog.Endpoint{ID: "destination", TenantID: tenant, Kind: assetcatalog.KindNetwork, Address: "authored.invalid", Alias: tenant, Source: assetcatalog.SourceManual}); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Upsert(policyrule.Rule{ID: "inspect", TenantID: tenant, Plane: policyrule.PlaneEgress, Source: []string{"*"}, Destination: []string{"destination"}, Action: policyrule.Action{Access: policyrule.AccessAllow, Inspection: policyrule.InspectionInspect}}); err != nil {
			t.Fatal(err)
		}
	}
	p.Set(inspectionposture.Posture{Mode: inspectionposture.ModeBypassDefault, DecryptAllowlistHosts: []string{"selected.invalid"}})
	apply("operator")
	for _, tenant := range []string{"a", "b"} {
		if !e.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{TenantID: tenant, Host: "authored.invalid", Port: 443}) {
			t.Fatal("posture changed only caller's inspect rules", tenant)
		}
	}
	if e.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{TenantID: "unknown", Host: "authored.invalid", Port: 443}) {
		t.Fatal("unknown tenant inherited authored inspect")
	}
	if cleared := o.Clear("a", "apple_push"); !cleared {
		t.Fatal("clear override failed")
	}
	p.Set(inspectionposture.DefaultPosture())
	apply("b")
	if e.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{TenantID: "a", Host: "system.invalid", Port: 443}) {
		t.Fatal("cleared override retained")
	}
}
