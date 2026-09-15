package main

import (
	"sync"

	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/inspectionposture"
	"github.com/lantern-networks/dsse-core/knownbypass"
	"github.com/lantern-networks/dsse-core/policyrule"
)

// Rebuild all selections, including the deployment fallback, on any contributing
// change. The callback's tenant is deliberately not used to choose global state.
func newTenantInspectionApplier(engine *edgeplane.NetworkExtensionLabTLSInterception, posture *inspectionposture.Store, rules *policyrule.Store, assets *assetcatalog.Store, overrides *knownbypass.OverrideStore, catalog func() []knownbypass.Group, configuredIntercept, operatorBypass []string) func(string) {
	var mu sync.Mutex
	configuredIntercept = append([]string(nil), configuredIntercept...)
	operatorBypass = append([]string(nil), operatorBypass...)
	return func(_ string) {
		if engine == nil {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		p := posture.Get()
		groups := catalog()
		byTenant := map[string][]policyrule.Rule{}
		for _, rule := range rules.Snapshot() {
			byTenant[rule.TenantID] = append(byTenant[rule.TenantID], rule)
		}
		overrideSnapshot := overrides.Snapshot()
		delete(overrideSnapshot, "")
		for tenant := range overrideSnapshot {
			if _, exists := byTenant[tenant]; !exists {
				byTenant[tenant] = nil
			}
		}
		build := func(tenant string, authored []policyrule.Rule) edgeplane.InspectionPatterns {
			intercept := append([]string{}, configuredIntercept...)
			if p.Mode == inspectionposture.ModeBypassDefault {
				intercept = inspectionposture.EffectiveInterceptHosts(p)
				intercept = append(intercept, policyrule.EgressInspectFQDNs(tenant, authored, assets)...)
			}
			bypass := append([]string{}, operatorBypass...)
			if p.KnownBypassEnabled {
				bypass = append(bypass, knownbypass.EffectiveBypassHostsFrom(groups, overrideSnapshot[tenant])...)
			}
			bypass = append(bypass, policyrule.EgressBypassFQDNs(tenant, authored, assets)...)
			return edgeplane.InspectionPatterns{Intercept: intercept, Bypass: bypass}
		}
		defaults := build("", nil)
		tenants := make(map[string]edgeplane.InspectionPatterns, len(byTenant))
		for tenant, authored := range byTenant {
			tenants[tenant] = build(tenant, authored)
		}
		engine.ReplaceInspectionPatterns(defaults, tenants)
	}
}
