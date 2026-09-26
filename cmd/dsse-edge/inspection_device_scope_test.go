package main

import (
	"encoding/json"
	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/inspectionposture"
	"github.com/lantern-networks/dsse-core/knownbypass"
	"github.com/lantern-networks/dsse-core/policyrule"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDeviceScopedInspectionProductHTTPAndWarnings(t *testing.T) {
	old := operatorTenantConfigured()
	t.Cleanup(func() { operatorTenantAuthority.Store(old) })
	assets := assetcatalog.NewStore()
	rules := policyrule.NewStore()
	posture := inspectionposture.NewStore()
	engine := edgeplane.NewNetworkExtensionLabTLSInterceptionMatchOnly([]string{"*"})
	auth := newAdminAuthStore()
	for _, tenant := range []string{"a", "b"} {
		auth.UpsertPrincipal(adminPrincipal{ID: tenant, TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
		auth.UpsertAPIToken(adminAPIToken{ID: tenant, TenantID: tenant, Roles: []string{"admin"}, Scopes: []string{"*"}, TokenHash: adminTokenHash("token-" + tenant), CreatedByAdminPrincipalID: tenant, Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
		for _, ep := range []assetcatalog.Endpoint{{ID: "source", TenantID: tenant, Kind: assetcatalog.KindSteeredDevice, Identity: "device-" + tenant, Alias: "source"}, {ID: "target", TenantID: tenant, Kind: assetcatalog.KindNetwork, Address: "target.invalid", Alias: "target"}} {
			if _, err := assets.UpsertEndpoint(ep); err != nil {
				t.Fatal(err)
			}
		}
	}
	apply := newTenantInspectionApplier(engine, posture, rules, assets, knownbypass.NewOverrideStore(), func() []knownbypass.Group { return nil }, []string{"*"}, nil)
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: auth, OperatorTenantID: "operator", RuleStore: rules, AssetStore: assets, NetworkExtensionLabTLS: engine, InspectionPosture: posture.Get, ApplyInspectionPosture: apply, ApplyMaterializedCertPinBypass: apply})
	call := func(tenant, method, path, body string) []byte {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer token-"+tenant)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body)
		}
		return w.Body.Bytes()
	}
	body := `{"id":"rule","plane":"egress","source":["source"],"destination":["target"],"action":{"access":"allow","inspection":"bypass"}}`
	for _, tenant := range []string{"a", "b"} {
		call(tenant, "POST", "/admin/rules", body)
	}
	for _, tenant := range []string{"a", "b"} {
		for _, device := range []string{"device-a", "device-b", ""} {
			if got := engine.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{TenantID: tenant, DeviceIdentity: device, Host: "target.invalid", Port: 443}); got == (device == "device-"+tenant) {
				t.Fatal("device scope mismatch", tenant, device, got)
			}
		}
		var view inspectionPostureResponse
		json.Unmarshal(call(tenant, "GET", "/admin/inspection-posture", ""), &view)
		if !view.DeviceScoped || len(view.EffectiveBypass) != 0 {
			t.Fatal("device hosts presented as shared", view)
		}
		var hosts []string
		json.Unmarshal(call(tenant, "GET", "/admin/intercept/bypass-hosts", ""), &hosts)
		if len(hosts) != 0 {
			t.Fatal("device bypass flattened", hosts)
		}
		var preview effectivePolicyResponse
		json.Unmarshal(call(tenant, "GET", "/admin/effective-policy?destination=target.invalid", ""), &preview)
		if preview.Inspection.Decision != "depends_on_device" {
			t.Fatal("preview assumed a source", preview.Inspection)
		}
	}
	for _, source := range []string{"idgroup:staff", "missing"} {
		call("a", "POST", "/admin/rules", strings.Replace(body, `["source"]`, `["`+source+`"]`, 1))
		want := "identity_context_unavailable"
		if source == "missing" {
			want = "no_resolved_device"
		}
		for _, path := range []string{"/admin/rules?plane=egress", "/admin/egress-effective-rules"} {
			if !strings.Contains(string(call("a", "GET", path, "")), `"inspection_source_warning":"`+want+`"`) {
				t.Fatal("missing source warning", path)
			}
		}
		if !engine.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{TenantID: "a", DeviceIdentity: "device-a", Host: "target.invalid", Port: 443}) {
			t.Fatal("unsupported source became a device wildcard")
		}
	}
	call("b", "DELETE", "/admin/rules/rule", "")
	if !engine.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{TenantID: "b", DeviceIdentity: "device-b", Host: "target.invalid", Port: 443}) {
		t.Fatal("last rule device exception retained")
	}
}

func TestDeviceInspectionPreviewDoesNotOverstateAHostVerdict(t *testing.T) {
	for _, tc := range []struct {
		name string
		s    inspectionSources
		want string
	}{
		{"per-device bypass", inspectionSources{InterceptHosts: []string{"*"}, DeviceBypass: map[string][]string{"a": {"target.invalid"}}}, "depends_on_device"},
		{"per-device inspect", inspectionSources{DeviceIntercept: map[string][]string{"a": {"target.invalid"}}}, "depends_on_device"},
		{"already bypassed", inspectionSources{EffectiveBypass: []string{"target.invalid"}, DeviceIntercept: map[string][]string{"a": {"target.invalid"}}}, "bypass"},
		{"already inspected", inspectionSources{InterceptHosts: []string{"*"}, DeviceIntercept: map[string][]string{"a": {"target.invalid"}}}, "inspect"},
		{"unrelated host", inspectionSources{InterceptHosts: []string{"*"}, DeviceBypass: map[string][]string{"a": {"other.invalid"}}}, "inspect"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyInspection("target.invalid", tc.s); got.Decision != tc.want {
				t.Fatal(got)
			}
		})
	}
}
