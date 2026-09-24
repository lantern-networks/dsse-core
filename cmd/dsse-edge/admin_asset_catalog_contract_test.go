package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/inspectionposture"
	"github.com/lantern-networks/dsse-core/knownbypass"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/policyrule"
)

func TestCatalogHTTPPublishesOnlyDurableChanges(t *testing.T) {
	tenant := testEvaluator().PolicyBundle.TenantID
	a := assetcatalog.NewStore()
	p := &riskAuditPersister{base: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "assets.json")}}
	if err := a.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	for _, e := range []assetcatalog.Endpoint{{ID: "a", TenantID: tenant, Alias: "private-device", Kind: assetcatalog.KindSteeredDevice, Identity: "verified-a", Source: assetcatalog.SourceManual}, {ID: "dest", TenantID: tenant, Alias: "private-host", Kind: assetcatalog.KindNetwork, Address: "old.invalid", Source: assetcatalog.SourceManual}} {
		if _, err := a.UpsertEndpoint(e); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.UpsertGroup(assetcatalog.Group{ID: "g", TenantID: tenant, Alias: "private-group", StaticMembers: []string{"a"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.UpsertService(assetcatalog.Service{ID: "svc", TenantID: tenant, Alias: "private-service", Ports: []assetcatalog.PortProto{{Protocol: "tcp", Port: 443}}}); err != nil {
		t.Fatal(err)
	}
	rules := policyrule.NewStore()
	if _, err := rules.Upsert(policyrule.Rule{ID: "rule", TenantID: tenant, Plane: policyrule.PlaneEgress, Source: []string{"g"}, Destination: []string{"dest"}, ServiceID: "svc", Action: policyrule.Action{Access: policyrule.AccessAllow, Inspection: policyrule.InspectionBypass}}); err != nil {
		t.Fatal(err)
	}
	engine := edgeplane.NewNetworkExtensionLabTLSInterceptionMatchOnly([]string{"*"})
	posture := inspectionposture.NewStore()
	apply := newTenantInspectionApplier(engine, posture, rules, a, knownbypass.NewOverrideStore(), func() []knownbypass.Group { return nil }, []string{"*"}, nil)
	w, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	policies := policy.NewStore(nil)
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), OperatorTenantID: tenant, Writer: w, AdminAuth: newAdminAuthStore(), AssetStore: a, RuleStore: rules, PolicyStore: policies, NetworkExtensionLabTLS: engine, ApplyInspectionPosture: apply})
	check := func(host string, want bool) {
		t.Helper()
		if got := engine.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{TenantID: tenant, DeviceIdentity: "verified-a", Host: host, Port: 443}); got != want {
			t.Fatalf("%s match=%v want=%v", host, got, want)
		}
	}
	call := func(method, path, body string, status int) {
		t.Helper()
		r := doAdmin(t, h, method, path, body)
		if r.Code != status {
			t.Fatalf("%s %s: %d %s", method, path, r.Code, r.Body)
		}
		if strings.Contains(r.Body.String(), "private-runtime-location") {
			t.Fatal("storage error leaked")
		}
	}
	check("old.invalid", false)
	endpoint := `{"id":"dest","alias":"private-edited","kind":"network","source":"manual","address":"new.invalid"}`
	p.fail.Store(true)
	call("POST", "/admin/assets/endpoints", endpoint, 500)
	check("old.invalid", false)
	check("new.invalid", true)
	p.fail.Store(false)
	call("POST", "/admin/assets/endpoints", endpoint, 200)
	check("old.invalid", true)
	check("new.invalid", false)
	p.fail.Store(true)
	call("POST", "/admin/assets/services", `{"id":"svc","alias":"private-edited","ports":[{"protocol":"udp","port":443}]}`, 500)
	check("new.invalid", false)
	p.fail.Store(false)
	call("POST", "/admin/assets/services", `{"id":"svc","alias":"private-edited","ports":[{"protocol":"udp","port":443}]}`, 200)
	check("new.invalid", true)
	call("POST", "/admin/assets/services", `{"id":"svc","alias":"private-edited","ports":[{"protocol":"tcp","port":443}]}`, 200)
	check("new.invalid", false)
	p.fail.Store(true)
	call("DELETE", "/admin/assets/groups/g", "", 500)
	check("new.invalid", false)
	p.fail.Store(false)
	call("DELETE", "/admin/assets/groups/g", "", 200)
	check("new.invalid", true)
	call("DELETE", "/admin/assets/groups/g", "", 404)
	for _, compiled := range policies.RuntimeEvaluator(testEvaluator()).Policies {
		if reflect.DeepEqual(compiled.Conditions["device_id"], []string{"verified-a"}) {
			t.Fatal("removed group remains compiled")
		}
	}
	call("POST", "/admin/assets/groups", `{"id":"foreign","tenant_id":"customer-b","alias":"private-cross"}`, 200)
	rows := readTransportAudits(t, w)
	n, failed := 0, 0
	for _, row := range rows {
		if row.EventType != "admin_asset_catalog_changed" {
			continue
		}
		n++
		expectedTenant := tenant
		if stringPtrValue(row.TargetID) == "foreign" {
			expectedTenant = "customer-b"
		}
		if row.TenantID != expectedTenant || stringPtrValue(row.ActorUserID) == "" || stringPtrValue(row.TargetID) == "" {
			t.Fatalf("bad audit %+v", row)
		}
		if stringPtrValue(row.Result) == "persistence_unconfirmed" {
			failed++
		}
	}
	if n != 9 || failed != 3 {
		t.Fatal("audit count", n, failed)
	}
	raw, _ := json.Marshal(rows)
	for _, secret := range []string{"private-edited", "private-cross", "new.invalid", "private-runtime-location"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("audit leaked", secret)
		}
	}
}

func TestCatalogSyncRetriesBeforePublishingDependentRules(t *testing.T) {
	a := assetcatalog.NewStore()
	p := &riskAuditPersister{base: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "assets.json")}}
	if err := a.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	old := assetcatalog.Endpoint{ID: "ep", TenantID: "tenant_lab_001", Alias: "old", Kind: assetcatalog.KindNetwork, Address: "old.invalid", Source: assetcatalog.SourceManual}
	if _, err := a.UpsertEndpoint(old); err != nil {
		t.Fatal(err)
	}
	next := old
	next.Address = "new.invalid"
	rules := policyrule.NewStore()
	rule, err := rules.Upsert(policyrule.Rule{ID: "r", TenantID: old.TenantID, Name: "old", Plane: policyrule.PlaneEgress, Source: []string{"*"}, Destination: []string{"ep"}, Action: policyrule.Action{Access: policyrule.AccessAllow}})
	if err != nil {
		t.Fatal(err)
	}
	newRule := rule
	newRule.Name = "new"
	p.fail.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	status := &configBundleSyncStatus{}
	var polls, compiled atomic.Int32
	checks := make(chan bool, 2)
	payload := configBundlePayload{Generation: 41, Epoch: "catalog-retry", Rules: &authoredRuleBundle{Rules: []policyrule.Rule{newRule}, Endpoints: []assetcatalog.Endpoint{next}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch polls.Add(1) {
		case 3:
			status.mu.RLock()
			failed := !status.haveApplied && status.lastError != ""
			status.mu.RUnlock()
			ep, _ := a.GetEndpoint(old.TenantID, old.ID)
			checks <- failed && reflect.DeepEqual(ep, old) && reflect.DeepEqual(rules.Snapshot(), []policyrule.Rule{rule}) && compiled.Load() == 0
			p.fail.Store(false)
		case 4:
			status.mu.RLock()
			ok := status.haveApplied && status.lastAppliedGeneration == 41
			status.mu.RUnlock()
			ep, _ := a.GetEndpoint(old.TenantID, old.ID)
			checks <- ok && reflect.DeepEqual(ep, next) && reflect.DeepEqual(rules.Snapshot(), []policyrule.Rule{newRule}) && compiled.Load() == 1
			cancel()
		}
		json.NewEncoder(w).Encode(payload)
	}))
	defer srv.Close()
	src := configBundleSource{tenantID: old.TenantID, url: srv.URL, client: srv.Client(), interval: 10 * time.Millisecond, status: status}
	src.run(ctx, configApplyTargets{policyStore: policy.NewStore(nil), assets: a, rules: rules, onRulesApplied: func() { compiled.Add(1) }})
	if len(checks) != 2 || !<-checks || !<-checks {
		t.Fatal("catalog failure was acknowledged or dependent rules applied")
	}
	if _, err := src.apply(payload, configApplyTargets{policyStore: policy.NewStore(nil), rules: rules}); err == nil {
		t.Fatal("nonempty catalog accepted without target")
	}
	reload := assetcatalog.NewStore()
	if err := reload.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	got, _ := reload.GetEndpoint(old.TenantID, old.ID)
	if !reflect.DeepEqual(got, next) {
		t.Fatal("retry not durable")
	}
}
