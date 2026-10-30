package main

import (
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/policyrule"
)

func TestConfigBundleRefusesRulesUntilTheirAssetCatalogIsSaved(t *testing.T) {
	const tenant = "tenant_fleet"
	assets := assetcatalog.NewStore()
	gate := &rejectingRoutePersister{Persister: &memoryPersister{}}
	if err := assets.SetPersister(gate); err != nil {
		t.Fatal(err)
	}
	rules := policyrule.NewStore()
	recompiled := 0
	asset := assetcatalog.Endpoint{ID: "app-wiki", TenantID: tenant, Alias: "Wiki", Kind: assetcatalog.KindNetwork,
		Address: "wiki.example.test", Source: assetcatalog.SourceApplication}
	rule := policyrule.Rule{ID: "wiki-rule", TenantID: tenant, Plane: policyrule.PlaneEgress, Priority: 10,
		Name: "Wiki", Source: []string{"*"}, Destination: []string{asset.ID},
		Action: policyrule.Action{Access: policyrule.AccessAllow}, Status: policyrule.StatusActive}
	source := configBundleSource{tenantID: tenant}
	targets := configApplyTargets{policyStore: policy.NewStore(nil), assets: assets, rules: rules,
		onRulesApplied: func() { recompiled++ }}
	payload := configBundlePayload{Rules: &authoredRuleBundle{Endpoints: []assetcatalog.Endpoint{asset}, Rules: []policyrule.Rule{rule}}}
	gate.fail = true
	if _, err := source.apply(payload, targets); err == nil || strings.Contains(err.Error(), "private database connection detail") {
		t.Fatalf("failed asset save must reject the generation without backend details: %v", err)
	}
	if _, found := assets.GetEndpoint(tenant, asset.ID); found || len(rules.Snapshot()) != 0 || recompiled != 0 {
		t.Fatalf("rejected bundle changed live asset/rules: asset=%v rules=%v recompiled=%d", found, rules.Snapshot(), recompiled)
	}
	gate.fail = false
	if _, err := source.apply(payload, targets); err != nil {
		t.Fatalf("retry after saving recovers: %v", err)
	}
	if _, found := assets.GetEndpoint(tenant, asset.ID); !found || len(rules.Snapshot()) != 1 || recompiled != 1 {
		t.Fatalf("retry did not apply asset and rule: asset=%v rules=%v recompiled=%d", found, rules.Snapshot(), recompiled)
	}
}
