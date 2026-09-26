package main

import (
	"net/http"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/policyrule"
)

func TestAssetAdminRecompilesDependentEgressRulesAfterConfirmedSave(t *testing.T) {
	tenant := testEvaluator().PolicyBundle.TenantID
	p := &assetDurabilityPersister{}
	assets := assetcatalog.NewStore()
	if err := assets.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if _, err := assets.UpsertEndpoint(assetcatalog.Endpoint{ID: "destination", TenantID: tenant, Kind: assetcatalog.KindNetwork, Alias: "destination", Address: "old.example.invalid"}); err != nil {
		t.Fatal(err)
	}
	if _, err := assets.UpsertService(assetcatalog.Service{ID: "service", TenantID: tenant, Alias: "service", Ports: []assetcatalog.PortProto{{Protocol: "tcp", Port: 22}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := assets.UpsertEndpoint(assetcatalog.Endpoint{ID: "source", TenantID: tenant, Kind: assetcatalog.KindSteeredDevice, Alias: "source", Identity: "device-one"}); err != nil {
		t.Fatal(err)
	}
	if _, err := assets.UpsertGroup(assetcatalog.Group{ID: "group-one", TenantID: tenant, Alias: "group-one", StaticMembers: []string{"source"}}); err != nil {
		t.Fatal(err)
	}
	rules := policyrule.NewStore()
	if _, err := rules.Upsert(policyrule.Rule{ID: "dependent", TenantID: tenant, Plane: policyrule.PlaneEgress, Status: policyrule.StatusActive, Source: []string{"*"}, Destination: []string{"destination"}, ServiceID: "service", Action: policyrule.Action{Access: policyrule.AccessDeny}}); err != nil {
		t.Fatal(err)
	}
	if _, err := rules.Upsert(policyrule.Rule{ID: "dependent-group", TenantID: tenant, Plane: policyrule.PlaneEgress, Status: policyrule.StatusActive, Source: []string{"group-one"}, Destination: []string{"destination"}, ServiceID: "service", Action: policyrule.Action{Access: policyrule.AccessDeny}}); err != nil {
		t.Fatal(err)
	}
	policies := policy.NewStore(nil)
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), OperatorTenantID: tenant, AssetStore: assets, RuleStore: rules, PolicyStore: policies, AdminAuth: newAdminAuthStore(), Writer: writer})
	check := func(host string, port int, want bool) {
		t.Helper()
		found := false
		for _, row := range policies.RuntimeEvaluator(testEvaluator()).Policies {
			if !strings.HasPrefix(row.ID, "rule-egress-dependent") {
				continue
			}
			if row.Conditions["fqdn"] == host && row.Conditions["destination_port"] == port {
				found = true
			}
		}
		if found != want {
			t.Fatalf("compiled host=%s port=%d found=%t want=%t", host, port, found, want)
		}
	}
	checkGroup := func(want bool) {
		t.Helper()
		found := false
		for _, row := range policies.RuntimeEvaluator(testEvaluator()).Policies {
			if !strings.HasPrefix(row.ID, "rule-egress-dependent-group") {
				continue
			}
			if members, ok := row.Conditions["device_id"].([]any); ok {
				for _, member := range members {
					if member == "device-one" {
						found = true
					}
				}
			}
		}
		if found != want {
			t.Fatalf("compiled group member found=%t want=%t", found, want)
		}
	}
	call := func(method, path, body string, want int) {
		t.Helper()
		rec := doAdmin(t, h, method, path, body)
		if rec.Code != want {
			t.Fatalf("%s %s status=%d want=%d", method, path, rec.Code, want)
		}
	}
	check("old.example.invalid", 22, true)
	checkGroup(true)
	call(http.MethodPost, "/admin/assets/endpoints", `{"id":"destination","kind":"network","alias":"destination","address":"new.example.invalid"}`, http.StatusOK)
	check("old.example.invalid", 22, false)
	check("new.example.invalid", 22, true)
	call(http.MethodPost, "/admin/assets/services", `{"id":"service","alias":"service","ports":[{"protocol":"tcp","port":2222}]}`, http.StatusOK)
	check("new.example.invalid", 22, false)
	check("new.example.invalid", 2222, true)
	p.fail = true
	call(http.MethodPost, "/admin/assets/services", `{"id":"service","alias":"service","ports":[{"protocol":"tcp","port":443}]}`, http.StatusServiceUnavailable)
	check("new.example.invalid", 2222, true)
	check("new.example.invalid", 443, false)
	p.fail = false
	call(http.MethodPost, "/admin/assets/groups", `{"id":"group-one","alias":"group-one","static_members":[]}`, http.StatusOK)
	checkGroup(false)
	call(http.MethodPost, "/admin/assets/groups", `{"id":"group-one","alias":"group-one","static_members":["source"]}`, http.StatusOK)
	checkGroup(true)
	call(http.MethodDelete, "/admin/assets/groups/group-one", "", http.StatusOK)
	checkGroup(false)
	call(http.MethodDelete, "/admin/assets/services/service", "", http.StatusOK)
	check("new.example.invalid", 2222, false)
	check("new.example.invalid", 443, false) // missing service must not broaden a rule to every port
	call(http.MethodDelete, "/admin/assets/endpoints/destination", "", http.StatusOK)
	check("new.example.invalid", 443, false)
}
