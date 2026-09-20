package main

import (
	"sync"

	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/policyrule"
)

// Installed before the elector starts. Refreshing only the Console's raw stores
// leaves the promoted process enforcing its startup snapshot indefinitely.
func configureAuthoredPromotion(e *cpLeaderElector, rules *policyrule.Store, assets *assetcatalog.Store, recompile func()) {
	if e == nil {
		return
	}
	previous := e.prepareLeadership
	e.prepareLeadership = func() error {
		if previous != nil {
			if err := previous(); err != nil {
				return err
			}
		}
		if err := rules.RefreshShared(); err != nil {
			return err
		}
		if err := assets.RefreshShared(); err != nil {
			return err
		}
		recompile()
		return nil
	}
}

// One instance is shared by startup, promotion and all rule/catalog change
// handlers. Include prior compiled owners to remove a tenant's last deleted rule.
func newAuthoredRuleCompiler(defaultTenant string, policies policy.RuntimeStore, rules *policyrule.Store, assets *assetcatalog.Store, applyInspection func(string)) func() {
	var mu sync.Mutex
	return func() {
		mu.Lock()
		defer mu.Unlock()
		tenants := append([]string{defaultTenant}, rules.Tenants()...)
		if s, ok := policies.(interface{ CompiledRuleTenants() []string }); ok {
			tenants = append(tenants, s.CompiledRuleTenants()...)
		}
		seen := map[string]bool{}
		for _, tenant := range tenants {
			if seen[tenant] {
				continue
			}
			seen[tenant] = true
			if applyInspection != nil {
				applyInspection(tenant)
			}
			if s, ok := policies.(interface {
				SetCompiledEastWestRules(string, []decision.EastWestRule)
			}); ok {
				s.SetCompiledEastWestRules(tenant, policyrule.CompileEastWest(tenant, rules.List(tenant, policyrule.PlaneEastWest), assets))
			}
			if s, ok := policies.(interface{ SetCompiledPolicies(string, []model.Policy) }); ok {
				s.SetCompiledPolicies(tenant, policyrule.CompileEgressPolicies(tenant, rules.List(tenant, policyrule.PlaneEgress), assets))
			}
		}
	}
}
