package main

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	appcatalog "github.com/lantern-networks/dsse-core/appcatalog"
	connector "github.com/lantern-networks/dsse-core/connector"
	policy "github.com/lantern-networks/dsse-core/policy"
	policyrule "github.com/lantern-networks/dsse-core/policyrule"
	steerexclusion "github.com/lantern-networks/dsse-core/steerexclusion"
)

// TestAnExclusionAuthoredOnTheControlPlaneReachesTheEdge reproduces acceptance C's third walk: the Console saved
// an exclusion on the control plane, the list said "active", and the Edge the device steered through held
// none, so the device logged "refreshed 0 signed exclusion(s)" until it was uninstalled. The Edge pulls one
// thing from the control plane — the config bundle — so the exclusion has to be in it, the bundle's version has
// to move when it is added or removed, and the Edge has to apply both.
func TestAnExclusionAuthoredOnTheControlPlaneReachesTheEdge(t *testing.T) {
	const tenant = "tenant_lab_001" // the organization testEvaluator's administrator belongs to
	cp := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(),
		AdminAuth: newAdminAuthStore(), OperatorTenantID: tenant, SteerExclusions: steerexclusion.NewStore(),
		RuleStore: policyrule.NewStore()})
	edgeStore := steerexclusion.NewStore()
	source := configBundleSource{tenantID: tenant}
	pull := func(step string) configBundlePayload {
		t.Helper()
		read := doAdmin(t, cp, http.MethodGet, "/admin/config-bundle", "")
		var bundle configBundlePayload
		if read.Code != http.StatusOK || json.Unmarshal(read.Body.Bytes(), &bundle) != nil {
			t.Fatalf("%s: bundle status=%d body=%s", step, read.Code, read.Body.String())
		}
		if bundle.SteerExclusions == nil {
			t.Fatalf("%s: the bundle carries no steering exclusions section — the Edge would keep whatever it had", step)
		}
		if _, err := source.apply(bundle, configApplyTargets{policyStore: policy.NewStore(nil),
			rules: policyrule.NewStore(), applications: appcatalog.NewStore(),
			dlp: dlpStoresForTest("exclusion-" + step), steerExclusions: edgeStore}); err != nil {
			t.Fatalf("%s: apply: %v", step, err)
		}
		return bundle
	}

	first := pull("before")
	if got := edgeStore.ResolveForDevice(tenant, "DESKTOP-ACC3", ""); len(got) != 0 {
		t.Fatalf("before anything was authored the Edge signs %v", got)
	}

	created := doAdmin(t, cp, http.MethodPost, "/admin/steer-exclusions",
		`{"scope_type":"tenant","excluded_app_signing_ids":["\\git\\usr\\bin\\ssh.exe"],"note":"keep the operator's SSH"}`)
	if created.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	var saved steerexclusion.Policy
	if err := json.Unmarshal(created.Body.Bytes(), &saved); err != nil || saved.ID == "" {
		t.Fatalf("create body=%s", created.Body.String())
	}
	if saved.TenantID != tenant {
		t.Fatalf("the exclusion was saved under %q, not the administrator's organization %q", saved.TenantID, tenant)
	}
	second := pull("after-create")
	if second.Generation <= first.Generation {
		t.Fatalf("adding an exclusion left the bundle at generation %d (was %d); no Edge would pull it", second.Generation, first.Generation)
	}
	if got := edgeStore.ResolveForDevice(tenant, "DESKTOP-ACC3", ""); len(got) != 1 || got[0] != `\git\usr\bin\ssh.exe` {
		t.Fatalf("the Edge signs %v for a device of the organization; want the exclusion authored on the control plane", got)
	}

	removed := doAdmin(t, cp, http.MethodDelete, "/admin/steer-exclusions/"+saved.ID, "")
	if removed.Code != http.StatusOK && removed.Code != http.StatusNoContent {
		t.Fatalf("delete status=%d body=%s", removed.Code, removed.Body.String())
	}
	third := pull("after-delete")
	if third.Generation <= second.Generation {
		t.Fatalf("removing an exclusion left the bundle at generation %d (was %d)", third.Generation, second.Generation)
	}
	if got := edgeStore.ResolveForDevice(tenant, "DESKTOP-ACC3", ""); len(got) != 0 {
		t.Fatalf("after the deletion the Edge still signs %v — a removed exclusion would stay in force", got)
	}
}

// TestASectionForOneOrganizationLeavesTheOthersAlone: a bundle read with one organization's credential speaks
// only for that organization. Reading its silence about the others as "they have none" would strip every other
// organization's exclusions from an Edge.
func TestASectionForOneOrganizationLeavesTheOthersAlone(t *testing.T) {
	now := time.Now().UTC()
	mine := steerexclusion.Policy{ID: "sx_mine", TenantID: "org-a", ScopeType: "tenant", ExcludedAppSigningIDs: []string{"a.exe"}, Status: "active", CreatedAt: now, UpdatedAt: now}
	theirs := steerexclusion.Policy{ID: "sx_theirs", TenantID: "org-b", ScopeType: "tenant", ExcludedAppSigningIDs: []string{"b.exe"}, Status: "active", CreatedAt: now, UpdatedAt: now}

	scoped := steerExclusionBundleFor([]steerexclusion.Policy{mine, theirs}, []adminTenantModel{{TenantID: "org-a"}, {TenantID: "org-b"}}, "org-a", false)
	if len(scoped.Tenants) != 1 || scoped.Tenants[0] != "org-a" || len(scoped.Policies) != 1 || scoped.Policies[0].ID != "sx_mine" {
		t.Fatalf("a single organization's section = %+v; it must name and carry only that organization", scoped)
	}
	edge := steerexclusion.NewStore()
	edge.ReplaceTenant("org-b", []steerexclusion.Policy{theirs})
	if err := applySteerExclusionBundle(edge, scoped); err != nil {
		t.Fatal(err)
	}
	if got := edge.ResolveForDevice("org-b", "any", ""); len(got) != 1 {
		t.Fatalf("org-b's exclusions were removed by a section that did not speak for org-b: %v", got)
	}

	// The fleet's section names every organization in the catalogue, so one that has none is emptied — that is
	// how the last exclusion of an organization leaves the fleet.
	fleet := steerExclusionBundleFor([]steerexclusion.Policy{mine}, []adminTenantModel{{TenantID: "org-a"}, {TenantID: "org-b"}}, "org-a", true)
	if err := applySteerExclusionBundle(edge, fleet); err != nil {
		t.Fatal(err)
	}
	if got := edge.ResolveForDevice("org-b", "any", ""); len(got) != 0 {
		t.Fatalf("org-b has no exclusions on the control plane and the Edge still signs %v", got)
	}

	// A policy for an organization the section does not name is refused whole, before anything is replaced.
	bad := &steerExclusionBundle{Tenants: []string{"org-a"}, Policies: []steerexclusion.Policy{mine, theirs}}
	if err := applySteerExclusionBundle(edge, bad); err == nil {
		t.Fatal("a section carrying another organization's policy was applied")
	}
}

// TestAnEdgeThatPullsItsConfigRefusesAnExclusionWrite: a write accepted on an Edge that pulls the bundle would
// be erased by the next poll without a trace. It is refused, and the refusal names where to write.
func TestAnEdgeThatPullsItsConfigRefusesAnExclusionWrite(t *testing.T) {
	edge := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Registry: connector.NewRegistry(),
		AdminAuth: newAdminAuthStore(), OperatorTenantID: "org-a", SteerExclusions: steerexclusion.NewStore(),
		ConfigSourceURL: "https://admin.region-a.example.test"})
	rec := doAdmin(t, edge, http.MethodPost, "/admin/steer-exclusions", `{"scope_type":"tenant","excluded_app_signing_ids":["a.exe"]}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("an Edge that pulls its config accepted an exclusion write: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

// TestAnIncompleteSectionDoesNotEraseExclusions — review C3-R4: a section with its policies missing or null was
// read as an empty list and erased every exclusion of the organizations it named.
func TestAnIncompleteSectionDoesNotEraseExclusions(t *testing.T) {
	now := time.Now().UTC()
	held := steerexclusion.Policy{ID: "sx_a", TenantID: "org-a", ScopeType: "tenant", ExcludedAppSigningIDs: []string{"a.exe"}, Status: "active", CreatedAt: now, UpdatedAt: now}
	for _, raw := range []string{`{"tenants":["org-a"]}`, `{"tenants":["org-a"],"policies":null}`, `{"policies":[]}`} {
		edge := steerexclusion.NewStore()
		edge.ReplaceTenant("org-a", []steerexclusion.Policy{held})
		var section steerExclusionBundle
		if err := json.Unmarshal([]byte(raw), &section); err != nil {
			t.Fatal(err)
		}
		if err := applySteerExclusionBundle(edge, &section); err == nil {
			t.Errorf("%s was applied", raw)
		}
		if got := edge.ResolveForDevice("org-a", "x", ""); len(got) != 1 {
			t.Errorf("%s erased what org-a held: %v", raw, got)
		}
	}
	// An explicit empty list is a removal.
	edge := steerexclusion.NewStore()
	edge.ReplaceTenant("org-a", []steerexclusion.Policy{held})
	var section steerExclusionBundle
	if err := json.Unmarshal([]byte(`{"tenants":["org-a"],"policies":[]}`), &section); err != nil {
		t.Fatal(err)
	}
	if err := applySteerExclusionBundle(edge, &section); err != nil {
		t.Fatal(err)
	}
	if got := edge.ResolveForDevice("org-a", "x", ""); len(got) != 0 {
		t.Fatalf("an explicit empty list did not remove: %v", got)
	}
}
