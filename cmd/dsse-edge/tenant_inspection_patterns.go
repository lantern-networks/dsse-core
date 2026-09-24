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
			var interceptByDevice map[string][]string
			if p.Mode == inspectionposture.ModeBypassDefault {
				intercept = inspectionposture.EffectiveInterceptHosts(p)
				selection := policyrule.EgressInspectionHosts(tenant, authored, assets, policyrule.InspectionInspect)
				intercept = append(intercept, selection.AnySource...)
				interceptByDevice = selection.ByDevice
			}
			bypass := append([]string{}, operatorBypass...)
			if p.KnownBypassEnabled {
				bypass = append(bypass, knownbypass.EffectiveBypassHostsFrom(groups, overrideSnapshot[tenant])...)
			}
			selection := policyrule.EgressInspectionHosts(tenant, authored, assets, policyrule.InspectionBypass)
			bypass = append(bypass, selection.AnySource...)
			return edgeplane.InspectionPatterns{Intercept: intercept, Bypass: bypass, InterceptByDevice: interceptByDevice, BypassByDevice: selection.ByDevice}
		}
		defaults := build("", nil)
		tenants := make(map[string]edgeplane.InspectionPatterns, len(byTenant))
		for tenant, authored := range byTenant {
			tenants[tenant] = build(tenant, authored)
		}
		engine.ReplaceInspectionPatterns(defaults, tenants)
	}
}
