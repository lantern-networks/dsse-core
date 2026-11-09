package main

import (
	"context"
	"os"
	"strings"
	"testing"
)

// 0.4.1 final acceptance A (2026-11-09): the single-region and three-region layouts had no -activate-auth step, so
// revocation reauthentication and ceremony recovery never switched on, and revoking an approval said an existing
// identity-provider sign-in may authorize a new one. Every published plan's order now ends by activating them.
func TestEveryPublishedPlansOrderActivatesAuthentication(t *testing.T) {
	for _, name := range []string{"single-region.json", "three-regions.json", "one-region-three-independent-entries.json", "three-regions-multi-edge.json"} {
		plan, err := LoadPlan("../../docs/plans/" + name)
		if err != nil {
			t.Fatal(err)
		}
		steps := plan.InstallOrder("/opt/dsse/region-a", "/home/ubuntu/plan.json")
		activate, verify := -1, -1
		for i, s := range steps {
			if strings.Contains(s.Do, "dsse-install -activate-auth ") {
				activate = i
			}
			if strings.Contains(s.Do, "dsse-install -verify ") {
				verify = i
			}
		}
		if activate < 0 {
			t.Fatalf("%s: the order never activates authentication", name)
		}
		if verify >= 0 && activate > verify {
			t.Fatalf("%s: activation comes after -verify (step %d > %d)", name, activate+1, verify+1)
		}
	}
}

// -activate-auth refuses a deployment without a complete plan, and no longer refuses a plan for not being a declared
// shared fleet: with the single-region plan it gets as far as the census.
func TestActivateAuthTakesEveryPlanAndStillNeedsTheCensus(t *testing.T) {
	_, err := runActivateAuth(context.Background(), t.TempDir(), "../../docs/plans/single-region.json", "", "operator", "reader", "")
	if err == nil {
		t.Fatal("activation succeeded without a census")
	}
	if strings.Contains(err.Error(), "declared shared-fleet profile") {
		t.Fatalf("a single-region plan was refused for its profile: %v", err)
	}
	if _, err := runActivateAuth(context.Background(), t.TempDir(), "", "", "operator", "reader", ""); err == nil {
		t.Fatal("a deployment without a plan was activated")
	}
}

// The bootstrap reserves the installation read credential for every plan install, not only declared shared fleets.
func TestBootstrapReservesTheReadCredentialForEveryPlan(t *testing.T) {
	src, err := os.ReadFile("bootstrap.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	i := strings.Index(text, "readPath = privateInstallReadTokenDestination(dir)")
	if i < 0 {
		t.Fatal("bootstrap no longer reserves the read credential; point this guard at it")
	}
	cond := text[strings.LastIndex(text[:i], "if "):i]
	if strings.Contains(cond, "declaredNodeMapProfile") {
		t.Fatalf("the read credential is still reserved only for declared profiles: %s", strings.TrimSpace(cond))
	}
}

// -activate-auth confirms each Edge applied the feature set at the same admin route -verify dials. On one machine
// it used to build region-a-node-a-edge-a.admin.<deployment>, which the deployment does not serve (404), and never
// confirmed the Edge.
func TestActivationAsksEachEdgeWhereVerifyDoes(t *testing.T) {
	plan, err := LoadPlan("../../docs/plans/single-region.json")
	if err != nil {
		t.Fatal(err)
	}
	routes := plan.edgeAdminRoutes()
	if len(routes) != 1 || !strings.HasPrefix(routes[0].URL, "https://region-a-edge-a.admin."+plan.Deployment+"@") {
		t.Fatalf("the single machine's Edge admin route is %+v, want region-a-edge-a.admin.%s", routes, plan.Deployment)
	}
	if routes[0].Machine != plan.Regions[0].Machines[0].Name {
		t.Fatalf("the route names machine %q", routes[0].Machine)
	}
	src, err := os.ReadFile("activate_auth.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), "nodeAdminTargets()") || !strings.Contains(string(src), "plan.edgeAdminRoutes()") {
		t.Fatal("-activate-auth no longer takes its Edge routes from edgeAdminRoutes, the rule -verify uses")
	}
	for _, name := range []string{"three-regions.json", "one-region-three-independent-entries.json", "three-regions-multi-edge.json"} {
		p, err := LoadPlan("../../docs/plans/" + name)
		if err != nil {
			t.Fatal(err)
		}
		got := p.verifyEdgeAdmins()
		routes := p.edgeAdminRoutes()
		if len(got) != len(routes) || len(routes) == 0 {
			t.Fatalf("%s: %d -verify routes, %d activation routes", name, len(got), len(routes))
		}
	}
}
