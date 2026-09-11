package main

import (
	"os"
	"strings"
	"testing"

	assetcatalog "github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/policy"
	policyrule "github.com/lantern-networks/dsse-core/policyrule"
)

// Regression for 2026-08-10: an adopted cert-pin bypass reached one Edge while the device was served by
// another, and every admin-visible surface reported success because each Edge answers truthfully about itself.
// See docs/authored_policy_reaches_one_edge_not_the_serving_one.md.
//
// The properties asserted here are the ones whose absence produced that outcome, and each is written so it
// fails for the original reason rather than for a nearby one.
func TestConfigBundleDistributesAuthoredRulesWithTheCatalogTheyName(t *testing.T) {
	const tenant = "tenant_fleet"

	cpAssets := assetcatalog.NewStore()
	ep, err := cpAssets.UpsertEndpoint(assetcatalog.Endpoint{
		ID: "ep-cloudkit", TenantID: tenant, Kind: assetcatalog.KindNetwork,
		Alias: "apple-cloudkit", Address: "api.apple-cloudkit.com",
	})
	if err != nil {
		t.Fatalf("upsert endpoint: %v", err)
	}
	cpRules := policyrule.NewStore()
	if _, err := cpRules.Upsert(policyrule.Rule{
		ID: "certpin-rule-1", TenantID: tenant, Plane: policyrule.PlaneEgress, Priority: 900000,
		Name: "Cert-pin bypass: api.apple-cloudkit.com", Source: []string{"*"}, Destination: []string{ep.ID},
		Action: policyrule.Action{Access: policyrule.AccessAllow, Inspection: policyrule.InspectionBypass},
		Status: policyrule.StatusActive,
	}); err != nil {
		t.Fatalf("upsert rule: %v", err)
	}

	// A rule change must be VISIBLE to the sync loop. Without a generation the section could exist and never be
	// pulled, which is the same invisible outcome by a different route.
	if cpRules.ConfigGeneration() == 0 || cpAssets.ConfigGeneration() == 0 {
		t.Fatalf("authoring a rule/endpoint must advance the config generation (rules=%d assets=%d)",
			cpRules.ConfigGeneration(), cpAssets.ConfigGeneration())
	}

	edgeRules := policyrule.NewStore()
	edgeAssets := assetcatalog.NewStore()
	recompiled := 0
	src := configBundleSource{tenantID: tenant}
	targets := configApplyTargets{
		policyStore:    policy.NewStore(nil),
		rules:          edgeRules,
		assets:         edgeAssets,
		onRulesApplied: func() { recompiled++ },
	}
	endpoints, groups, services := cpAssets.AuthoredSnapshot()
	bundle := configBundlePayload{Rules: &authoredRuleBundle{
		Rules: cpRules.Snapshot(), Endpoints: endpoints, Groups: groups, Services: services,
	}}

	_, _ = src.apply(bundle, targets)

	// The rule arrived...
	got := edgeRules.List(tenant, policyrule.PlaneEgress)
	if len(got) != 1 || got[0].ID != "certpin-rule-1" {
		t.Fatalf("the authored rule did not reach the second Edge: %+v", got)
	}
	// ...and RESOLVES, which is the property that actually stops the interception. A rule whose destination id
	// is unknown to the local catalog compiles to no addresses: inert on egress, and a wildcard on east-west.
	hosts := policyrule.EgressBypassFQDNs(tenant, edgeRules.List(tenant, policyrule.PlaneEgress), edgeAssets)
	if len(hosts) != 1 || hosts[0] != "api.apple-cloudkit.com" {
		t.Fatalf("the distributed rule did not resolve to the host it names (catalog missing?): %v", hosts)
	}
	// ...and the ENGINE was told. The compiled sets are in-memory derivations; updating the store without
	// recompiling moves the same divergence one layer inward, where no admin surface shows it at all.
	if recompiled != 1 {
		t.Fatalf("applying a distributed rule set must recompile exactly once, got %d", recompiled)
	}
}

// DELETE has to propagate, which is why the rule section REPLACES where every other section upserts. An
// authored allow/bypass that outlives its own deletion fails in the permissive direction.
func TestConfigBundleAuthoredRulesReplaceSoDeletePropagates(t *testing.T) {
	const tenant = "tenant_fleet"
	edgeRules := policyrule.NewStore()
	if _, err := edgeRules.Upsert(policyrule.Rule{
		ID: "stale-allow", TenantID: tenant, Plane: policyrule.PlaneEgress, Priority: 10,
		Name: "deleted on the CP", Source: []string{"*"}, Destination: []string{"ep-x"},
		Action: policyrule.Action{Access: policyrule.AccessAllow, Inspection: policyrule.InspectionBypass},
		Status: policyrule.StatusActive,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	keep := policyrule.Rule{
		ID: "kept", TenantID: tenant, Plane: policyrule.PlaneEgress, Priority: 20,
		Name: "still authored", Source: []string{"*"}, Destination: []string{"ep-y"},
		Action: policyrule.Action{Access: policyrule.AccessAllow, Inspection: policyrule.InspectionInspect},
		Status: policyrule.StatusActive,
	}
	src := configBundleSource{tenantID: tenant}
	_, _ = src.apply(configBundlePayload{Rules: &authoredRuleBundle{Rules: []policyrule.Rule{keep}}},
		configApplyTargets{policyStore: policy.NewStore(nil), rules: edgeRules})

	got := edgeRules.List(tenant, policyrule.PlaneEgress)
	if len(got) != 1 || got[0].ID != "kept" {
		t.Fatalf("a rule deleted on the control plane must not survive on the Edge: %+v", got)
	}
}

// The two directions, and they are NOT the same rule every other section follows.
//
//	section ABSENT (nil)  -> this control plane does not author rules; leave the Edge alone.
//	section PRESENT-EMPTY -> it IS the authority and there are none; CLEAR.
//
// The second reverses the usual lockout-safe default deliberately. Elsewhere empty is ambiguous and dangerous
// (empty enrolled inventory = admission lockout, empty policies = deny-all); an empty authored rule set is the
// ordinary state of a fresh deployment and locks nobody out. Keeping local instead broke DELETE for the last
// rule — measured live: the CP dropped to zero rules and both Edges went on enforcing a bypass that no longer
// existed anywhere, with their own /admin/rules refusing writes. A bypass nobody can remove is the permissive
// direction, arrived at from the safety rule.
func TestConfigBundleAuthoredRulesAbsentLeavesAloneButEmptyClears(t *testing.T) {
	const tenant = "tenant_fleet"
	edgeRules := policyrule.NewStore()
	if _, err := edgeRules.Upsert(policyrule.Rule{
		ID: "local-1", TenantID: tenant, Plane: policyrule.PlaneEgress, Priority: 10,
		Name: "local", Source: []string{"*"}, Destination: []string{"ep-z"},
		Action: policyrule.Action{Access: policyrule.AccessAllow, Inspection: policyrule.InspectionInspect},
		Status: policyrule.StatusActive,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	recompiled := 0
	src := configBundleSource{tenantID: tenant}
	targets := configApplyTargets{policyStore: policy.NewStore(nil), rules: edgeRules,
		onRulesApplied: func() { recompiled++ }}

	_, _ = src.apply(configBundlePayload{}, targets)
	if len(edgeRules.List(tenant, "")) != 1 {
		t.Fatalf("a bundle with NO rules section must leave the Edge's rules alone")
	}
	if recompiled != 0 {
		t.Fatalf("an absent section must not recompile")
	}

	_, _ = src.apply(configBundlePayload{Rules: &authoredRuleBundle{Rules: []policyrule.Rule{}}}, targets)
	if n := len(edgeRules.List(tenant, "")); n != 0 {
		t.Fatalf("a PRESENT-but-empty rule section must clear the Edge (deleting the last rule has to "+
			"propagate), got %d rule(s) still enforced", n)
	}
	if recompiled != 1 {
		t.Fatalf("clearing the rule set must recompile the engine, got %d", recompiled)
	}
}

// An invalid rule anywhere in the set refuses the WHOLE set. A half-applied policy is an access posture nobody
// authored, and picking it over the last good one lets a malformed CP response invent enforcement.
func TestConfigBundleAuthoredRulesAreAllOrNothing(t *testing.T) {
	const tenant = "tenant_fleet"
	edgeRules := policyrule.NewStore()
	good := policyrule.Rule{
		ID: "good", TenantID: tenant, Plane: policyrule.PlaneEgress, Priority: 10,
		Name: "good", Source: []string{"*"}, Destination: []string{"ep-a"},
		Action: policyrule.Action{Access: policyrule.AccessAllow, Inspection: policyrule.InspectionInspect},
		Status: policyrule.StatusActive,
	}
	bad := policyrule.Rule{ID: "bad", TenantID: tenant, Plane: "not-a-plane", Priority: 20}
	recompiled := 0
	src := configBundleSource{tenantID: tenant}
	_, _ = src.apply(configBundlePayload{Rules: &authoredRuleBundle{Rules: []policyrule.Rule{good, bad}}},
		configApplyTargets{policyStore: policy.NewStore(nil), rules: edgeRules, onRulesApplied: func() { recompiled++ }})

	if n := len(edgeRules.List(tenant, "")); n != 0 {
		t.Fatalf("a rule set containing an invalid rule must be refused whole, got %d rule(s) applied", n)
	}
	if recompiled != 0 {
		t.Fatalf("a refused rule set must not recompile the engine")
	}
}

// ★ THE CONTROL PLANE IS THE AUTHORITY FOR ASSETS: what it does not author does not survive on an Edge.
//
// Operator decision, 2026-08-11: "CP authority is absolute; Edges come and go." An Edge is a replaceable
// instance, so an asset held only there is lost with it.
//
// This test has been written three times and the history is the point. First it asserted removal while the
// code sat in a branch that never ran. Then the code ran and deleted 47 operator assets — because the Edge
// could still AUTHOR assets and the CP had none, so absence in the bundle meant "never migrated", not
// "deleted". Then it asserted the opposite and kept everything. It asserts removal again now, and what changed
// is not the assertion: it is that the Edge's asset writes are refused, which is what makes absence mean
// something. TestAssetReconciliationRequiresTheEdgeWriteGuard below holds those two together.
func TestConfigBundleRemovesAssetsTheControlPlaneDoesNotAuthor(t *testing.T) {
	const tenant = "tenant_fleet"

	newEdge := func() (*assetcatalog.Store, configApplyTargets) {
		assets := assetcatalog.NewStore()
		for _, e := range []assetcatalog.Endpoint{
			{ID: "ep-withdrawn", TenantID: tenant, Kind: assetcatalog.KindNetwork, Alias: "withdrawn",
				Address: "gone.example", Source: assetcatalog.SourceManual},
			// The Edge's own derivation from the enrolled ledger — not the CP's authored catalog and not its to
			// delete. Removing it leaves a device missing from policy until the next ledger pass.
			{ID: "dev-mac-1", TenantID: tenant, Kind: assetcatalog.KindSteeredDevice, Alias: "mac-dev-1",
				Address: "10.0.0.5", Source: assetcatalog.SourceEnrolled},
		} {
			if _, err := assets.UpsertEndpoint(e); err != nil {
				t.Fatalf("seed %s: %v", e.ID, err)
			}
		}
		return assets, configApplyTargets{
			policyStore: policy.NewStore(nil), rules: policyrule.NewStore(), assets: assets,
		}
	}

	for _, tc := range []struct {
		name  string
		rules []policyrule.Rule
	}{
		{"the control plane still authors a rule", []policyrule.Rule{{
			ID: "r1", TenantID: tenant, Plane: policyrule.PlaneEgress, Priority: 100,
			Name: "keep", Source: []string{"*"}, Destination: []string{"*"},
			Action: policyrule.Action{Access: policyrule.AccessAllow}, Status: policyrule.StatusActive,
		}}},
		// ★ Reconciliation must not hang off how many rules there happen to be. A first fix put it inside the
		// "at least one rule" branch and it never ran for the case that mattered.
		{"the control plane authors NO rules", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assets, targets := newEdge()
			src := configBundleSource{tenantID: tenant}
			_, _ = src.apply(configBundlePayload{Rules: &authoredRuleBundle{
				Rules: tc.rules,
				Endpoints: []assetcatalog.Endpoint{{
					ID: "ep-from-cp", TenantID: tenant, Kind: assetcatalog.KindNetwork,
					Alias: "from-cp", Address: "cp.example", Source: assetcatalog.SourceManual,
				}},
			}}, targets)

			if _, ok := assets.GetEndpoint(tenant, "ep-withdrawn"); ok {
				t.Error("an asset the control plane does not author is still on the Edge — the CP answers 200 to a " +
					"delete, so leaving it is a write reported as successful and absent where it takes effect")
			}
			if _, ok := assets.GetEndpoint(tenant, "ep-from-cp"); !ok {
				t.Error("an asset the control plane authors did not reach the Edge")
			}
			if _, ok := assets.GetEndpoint(tenant, "dev-mac-1"); !ok {
				t.Error("the enrolled-derived endpoint was deleted: each Edge derives those from the enrolled " +
					"ledger, so removing one leaves a device missing from policy until the next ledger pass")
			}
		})
	}
}

// ★★ THE TWO HALVES MUST SHIP TOGETHER, and this is the guard that says so.
//
// Reconciling the asset catalog is only safe because an Edge can no longer AUTHOR assets. With the write routes
// open and reconciliation on — the exact combination that existed for one deploy — every asset an operator
// created on an Edge is deleted on the next pull. That combination destroyed 47 of them here.
//
// Checked as source text, because the alternative is discovering it on a fleet.
func TestAssetReconciliationRequiresTheEdgeWriteGuard(t *testing.T) {
	sync, err := os.ReadFile("config_bundle_sync.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sync), "ReplaceAuthored(") {
		t.Skip("the apply no longer reconciles assets, so the write guard is not required by this test")
	}
	admin, err := os.ReadFile("assets_admin.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(admin)
	for _, route := range []string{
		"POST /admin/assets/endpoints", "POST /admin/assets/groups", "POST /admin/assets/services",
		"DELETE /admin/assets/endpoints/{id}", "DELETE /admin/assets/groups/{id}", "DELETE /admin/assets/services/{id}",
	} {
		i := strings.Index(src, route)
		if i < 0 {
			t.Errorf("route %q not found in assets_admin.go", route)
			continue
		}
		end := i + 700
		if end > len(src) {
			end = len(src)
		}
		if !strings.Contains(src[i:end], "configWriteRejectedWhenSourced") {
			t.Errorf("%s is not guarded while the config bundle reconciles assets — that combination deletes "+
				"every asset an operator authored on an Edge, on the next pull", route)
		}
	}
}
