package main

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// An authored binding keyed by the CONNECTOR id (POST /admin/connectors/{id}/routes) must route even when the
// connector belongs to a differently-named site, alongside the site-keyed bindings — and a binding present
// under both keys is not duplicated. Regression for the 2026-07-16 write-only-per-connector-key defect.
func TestConnectorRouteGovernanceConnectorKeyedAuthoredRoutes(t *testing.T) {
	g := newConnectorRouteGovernance()
	conns := []model.ConnectorRegistration{{ID: "conn-1", ConnectorGroupID: "site-1", ReachableRoutes: model.ConnectorReachableRoutes{Namespace: "site-1"}}}
	g.AddAuthored("t", "site-1", authoredRoute{CIDR: "10.1.0.0/16"}) // site-bound
	g.AddAuthored("t", "conn-1", authoredRoute{CIDR: "10.2.0.0/16"}) // connector-bound
	g.AddAuthored("t", "conn-1", authoredRoute{CIDR: "10.1.0.0/16"}) // duplicate of the site binding
	eff := g.Apply("t", conns)[0].ReachableRoutes.CIDRs
	if len(eff) != 2 {
		t.Fatalf("site- and connector-keyed authored bindings must both route exactly once, got %v", eff)
	}
	seen := map[string]bool{}
	for _, c := range eff {
		seen[c] = true
	}
	if !seen["10.1.0.0/16"] || !seen["10.2.0.0/16"] {
		t.Fatalf("expected both authored subnets in the effective set, got %v", eff)
	}
}

func TestConnectorRouteGovernance(t *testing.T) {
	g := newConnectorRouteGovernance()
	conns := []model.ConnectorRegistration{{ID: "c1", ConnectorGroupID: "c1", ReachableRoutes: model.ConnectorReachableRoutes{CIDRs: []string{"10.0.0.0/24", "10.0.1.0/24"}, Namespace: "site-a"}}}

	// Default: both self-declared routes are routable.
	if got := g.Apply("t", conns)[0].ReachableRoutes.CIDRs; len(got) != 2 {
		t.Fatalf("default should keep both routes, got %v", got)
	}
	// Hold one -> dropped from the effective set; the other stays.
	g.SetHeld("t", "c1", "10.0.1.0/24", true)
	eff := g.Apply("t", conns)[0].ReachableRoutes.CIDRs
	if len(eff) != 1 || eff[0] != "10.0.0.0/24" {
		t.Fatalf("held route must be dropped, got %v", eff)
	}
	// Add an admin-authored route -> present in the effective set.
	g.AddAuthored("t", "c1", authoredRoute{CIDR: "192.168.5.0/24", Description: "extra subnet"})
	eff = g.Apply("t", conns)[0].ReachableRoutes.CIDRs
	if len(eff) != 2 || eff[1] != "192.168.5.0/24" {
		t.Fatalf("authored route must be added, got %v", eff)
	}
	// Routes view reports source + held/routable.
	rows := g.Routes("t", "c1", conns[0].ReachableRoutes.CIDRs, nil)
	var heldSeen, authoredSeen bool
	for _, r := range rows {
		if r.CIDR == "10.0.1.0/24" && r.Source == "connector" && r.Held && !r.Routable {
			heldSeen = true
		}
		if r.CIDR == "192.168.5.0/24" && r.Source == "admin" && r.Routable {
			authoredSeen = true
		}
	}
	if !heldSeen || !authoredSeen {
		t.Fatalf("Routes view wrong: %+v", rows)
	}
	// Unhold restores it; remove authored drops it.
	g.SetHeld("t", "c1", "10.0.1.0/24", false)
	g.RemoveAuthored("t", "c1", "192.168.5.0/24")
	if got := g.Apply("t", conns)[0].ReachableRoutes.CIDRs; len(got) != 2 {
		t.Fatalf("unhold+remove should restore the 2 declared routes, got %v", got)
	}
	// nil governance is the identity.
	var nilg *connectorRouteGovernance
	if got := nilg.Apply("t", conns); len(got) != 1 || len(got[0].ReachableRoutes.CIDRs) != 2 {
		t.Fatal("nil governance must be the identity")
	}
}

// The fail-safe: first sight grandfathers the connector's routes (existing deployments keep working); a route
// advertised LATER is PENDING until approved, so a rogue/misconfigured connector cannot grab 0.0.0.0/0.
func TestConnectorRouteGovernance_FailSafeAdvertisement(t *testing.T) {
	g := newConnectorRouteGovernance()
	now := time.Now()
	conns := []model.ConnectorRegistration{{ID: "c1", ConnectorGroupID: "c1", ReachableRoutes: model.ConnectorReachableRoutes{CIDRs: []string{"10.0.0.0/24"}}}}

	// First sight grandfathers the current set -> routable.
	g.SeeRoutes("t", "c1", []string{"10.0.0.0/24"}, now)
	if got := g.Apply("t", conns)[0].ReachableRoutes.CIDRs; len(got) != 1 {
		t.Fatalf("grandfathered route must be routable, got %v", got)
	}

	// A NEW route advertised later stays PENDING (not routable).
	conns[0].ReachableRoutes.CIDRs = []string{"10.0.0.0/24", "0.0.0.0/0"}
	g.SeeRoutes("t", "c1", conns[0].ReachableRoutes.CIDRs, now)
	eff := g.Apply("t", conns)[0].ReachableRoutes.CIDRs
	if len(eff) != 1 || eff[0] != "10.0.0.0/24" {
		t.Fatalf("a newly advertised route must stay pending (rogue 0.0.0.0/0 not grabbed), got %v", eff)
	}
	var pendingSeen bool
	for _, r := range g.Routes("t", "c1", conns[0].ReachableRoutes.CIDRs, nil) {
		if r.CIDR == "0.0.0.0/0" && r.Pending && !r.Routable {
			pendingSeen = true
		}
	}
	if !pendingSeen {
		t.Fatal("0.0.0.0/0 must be reported pending + not routable")
	}

	// Approve it -> routable.
	g.SetApproved("t", "c1", "0.0.0.0/0", true)
	if got := g.Apply("t", conns)[0].ReachableRoutes.CIDRs; len(got) != 2 {
		t.Fatalf("approved route must become routable, got %v", got)
	}
}

// HA / multi-region: the governance DECISIONS must be durable + shared. Persisting to a path and reloading
// (another Edge mounting the same file, or a restart) must reproduce the same held/approved/authored/seen
// state, so routing is identical fleet-wide. See docs/connector_network_route_advertisement_design.md.
func TestConnectorRouteGovernance_PersistenceSharesDecisions(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/gov.json"
	now := time.Now()

	g := newConnectorRouteGovernanceWithPersistence(path)
	g.SeeRoutes("t", "c1", []string{"10.0.0.0/16"}, now) // grandfather 10.0/16 (approved) + seen
	g.AddAuthored("t", "c1", authoredRoute{CIDR: "192.168.9.0/24", Description: "extra"})
	g.SeeRoutes("t", "c1", []string{"10.0.0.0/16", "10.1.0.0/16"}, now) // re-advertise: 10.1 is NEW -> pending
	g.SetApproved("t", "c1", "10.1.0.0/16", true)                       // operator approves 10.1
	g.SetHeld("t", "c1", "10.0.0.0/16", true)                           // operator holds 10.0

	// A SECOND Edge (fresh governance) reading the SAME shared file must see identical decisions.
	g2 := newConnectorRouteGovernanceWithPersistence(path)
	conns := []model.ConnectorRegistration{{ID: "c1", ConnectorGroupID: "c1", ReachableRoutes: model.ConnectorReachableRoutes{CIDRs: []string{"10.0.0.0/16", "10.1.0.0/16"}}}}
	eff := g2.Apply("t", conns)[0].ReachableRoutes.CIDRs
	has := func(c string) bool {
		for _, x := range eff {
			if x == c {
				return true
			}
		}
		return false
	}
	if has("10.0.0.0/16") {
		t.Fatalf("held route must not be routable on the second Edge; eff=%v", eff)
	}
	if !has("10.1.0.0/16") {
		t.Fatalf("approved route must be routable on the second Edge; eff=%v", eff)
	}
	if !has("192.168.9.0/24") {
		t.Fatalf("admin-authored route must survive on the second Edge; eff=%v", eff)
	}
	// seen must persist: a brand-new advertised route on Edge 2 must be PENDING (not auto-grandfathered).
	g2.SeeRoutes("t", "c1", []string{"10.0.0.0/16", "10.1.0.0/16", "0.0.0.0/0"}, now)
	for _, r := range g2.Routes("t", "c1", []string{"0.0.0.0/0"}, nil) {
		if r.CIDR == "0.0.0.0/0" && !r.Pending {
			t.Fatal("a new route on the second Edge must be pending (seen state shared), not grandfathered")
		}
	}
}

// CP-configured model (the corrected model): a connector's self-reported (discovered) subnets are
// non-authoritative — NOT routable until the operator ADOPTS (approves) them, with no grandfather. Only
// admin-authored (CP-configured) bindings route by themselves. A HELD route is always dropped.
func TestConnectorRouteGovernance_CPConfiguredNoGrandfather(t *testing.T) {
	g := newConnectorRouteGovernanceWithOptions("", true)
	now := time.Now()
	conns := []model.ConnectorRegistration{{ID: "c1", ConnectorGroupID: "c1", ReachableRoutes: model.ConnectorReachableRoutes{CIDRs: []string{"10.0.0.0/24", "0.0.0.0/0"}}}}

	// First sight does NOT grandfather: the discovered subnets are not routable (a rogue 0.0.0.0/0 cannot grab).
	g.SeeRoutes("t", "c1", conns[0].ReachableRoutes.CIDRs, now)
	if got := g.Apply("t", conns)[0].ReachableRoutes.CIDRs; len(got) != 0 {
		t.Fatalf("CP-configured: self-reported subnets must NOT be routable until adopted, got %v", got)
	}
	// The view shows them as pending (discovered, awaiting adoption), not routable.
	pendingCount := 0
	for _, r := range g.Routes("t", "c1", conns[0].ReachableRoutes.CIDRs, nil) {
		if r.Source == "connector" && r.Pending && !r.Routable {
			pendingCount++
		}
	}
	if pendingCount != 2 {
		t.Fatalf("both discovered subnets must be pending + not routable, got %d", pendingCount)
	}

	// Adopt (approve) one -> only it becomes routable.
	g.SetApproved("t", "c1", "10.0.0.0/24", true)
	eff := g.Apply("t", conns)[0].ReachableRoutes.CIDRs
	if len(eff) != 1 || eff[0] != "10.0.0.0/24" {
		t.Fatalf("only the adopted subnet must be routable, got %v", eff)
	}

	// An admin-authored (CP-configured) binding routes by itself, without any discovery.
	g.AddAuthored("t", "c1", authoredRoute{CIDR: "192.168.7.0/24", Description: "cp-configured"})
	eff = g.Apply("t", conns)[0].ReachableRoutes.CIDRs
	if len(eff) != 2 {
		t.Fatalf("authored binding must route by itself, got %v", eff)
	}

	// Holding an adopted subnet drops it even though it was approved.
	g.SetHeld("t", "c1", "10.0.0.0/24", true)
	eff = g.Apply("t", conns)[0].ReachableRoutes.CIDRs
	if len(eff) != 1 || eff[0] != "192.168.7.0/24" {
		t.Fatalf("held route must be dropped, only the authored binding remains, got %v", eff)
	}
}

// Admin-authored FQDN (name) bindings: the operator can configure a name route (the preferred, namespace-free
// route) symmetric with a CIDR binding — it is injected into the effective FQDNDomains, appears as an admin
// FQDN row, and is removable by its fqdn key. (doc Remaining #2)
func TestConnectorRouteGovernance_AuthoredFQDN(t *testing.T) {
	g := newConnectorRouteGovernance()
	conns := []model.ConnectorRegistration{{ID: "c1", ConnectorGroupID: "c1", ReachableRoutes: model.ConnectorReachableRoutes{FQDNDomains: []string{"corp.internal"}, CIDRs: []string{"10.0.0.0/24"}}}}

	// Author an FQDN binding -> injected into the effective FQDN domains, alongside the self-reported one.
	g.AddAuthored("t", "c1", authoredRoute{FQDN: "wiki.corp", Description: "internal wiki"})
	effFQDN := g.Apply("t", conns)[0].ReachableRoutes.FQDNDomains
	if len(effFQDN) != 2 || effFQDN[1] != "wiki.corp" {
		t.Fatalf("authored FQDN must be injected into FQDNDomains, got %v", effFQDN)
	}
	// An FQDN binding must not leak into the CIDR set (Apply keeps the kinds separate).
	if effCIDR := g.Apply("t", conns)[0].ReachableRoutes.CIDRs; len(effCIDR) != len(conns[0].ReachableRoutes.CIDRs) {
		t.Fatalf("an FQDN binding must not add CIDRs, got %v", effCIDR)
	}

	// Routes view: an admin FQDN row + the self-reported FQDN row (informational, routable) + the self CIDR.
	var adminFQDN, connFQDN bool
	for _, r := range g.Routes("t", "c1", conns[0].ReachableRoutes.CIDRs, conns[0].ReachableRoutes.FQDNDomains) {
		if r.Kind == "fqdn" && r.FQDN == "wiki.corp" && r.Source == "admin" && r.Routable {
			adminFQDN = true
		}
		if r.Kind == "fqdn" && r.FQDN == "corp.internal" && r.Source == "connector" && r.Routable {
			connFQDN = true
		}
	}
	if !adminFQDN || !connFQDN {
		t.Fatalf("Routes view must show the admin + self-reported FQDN rows")
	}

	// Remove by fqdn key -> gone from the effective FQDN set (self-reported one remains).
	g.RemoveAuthored("t", "c1", "fqdn:wiki.corp")
	effFQDN = g.Apply("t", conns)[0].ReachableRoutes.FQDNDomains
	if len(effFQDN) != 1 || effFQDN[0] != "corp.internal" {
		t.Fatalf("removed FQDN binding must be gone, got %v", effFQDN)
	}
}

// Unified network object: a connector binding can REFERENCE a Named Network (defined once) instead of a raw
// CIDR; it expands to that network's CIDRs in the effective set, the effective-routes push, and the Routes view.
// See docs/unified_network_object_design.md.
func TestConnectorRouteGovernance_NamedNetworkReference(t *testing.T) {
	g := newConnectorRouteGovernance()
	// Fake resolver: net-tokyo -> the Tokyo server VLAN's two subnets (defined once, elsewhere).
	g.SetNetworkResolver(func(tenant, id string) (string, []string) {
		if tenant == "t" && id == "net-tokyo" {
			return "Tokyo servers", []string{"10.20.0.0/16", "10.30.0.0/16"}
		}
		return "", nil
	})
	conns := []model.ConnectorRegistration{{ID: "c1", ConnectorGroupID: "c1", ReachableRoutes: model.ConnectorReachableRoutes{}}}

	// Bind the Named Network to the connector -> its CIDRs enter the effective set (no re-typing).
	g.AddAuthored("t", "c1", authoredRoute{NetworkID: "net-tokyo", Description: "tokyo site"})
	eff := g.Apply("t", conns)[0].ReachableRoutes.CIDRs
	has := func(c string) bool {
		for _, x := range eff {
			if x == c {
				return true
			}
		}
		return false
	}
	if !has("10.20.0.0/16") || !has("10.30.0.0/16") {
		t.Fatalf("a Named Network reference must expand to its CIDRs, got %v", eff)
	}
	// (The effective-routes push to the connector's SSRF guard now serves the same Apply-governed set the
	// route layer uses, so the eff assertion above covers the push too.)
	// The Routes view shows a typed network row with the name + expanded CIDRs (for the UI).
	var netRow bool
	for _, r := range g.Routes("t", "c1", nil, nil) {
		if r.Kind == "network" && r.NetworkID == "net-tokyo" && r.NetworkName == "Tokyo servers" && len(r.NetworkCIDRs) == 2 && r.Routable {
			netRow = true
		}
	}
	if !netRow {
		t.Fatalf("Routes view must show the network-reference row with name + CIDRs")
	}
	// Remove by its network key -> gone.
	g.RemoveAuthored("t", "c1", "net:net-tokyo")
	if got := g.Apply("t", conns)[0].ReachableRoutes.CIDRs; len(got) != 0 {
		t.Fatalf("removed network binding must be gone, got %v", got)
	}
	// A reference with no resolver (or unknown id) contributes nothing (safe).
	g2 := newConnectorRouteGovernance()
	g2.AddAuthored("t", "c1", authoredRoute{NetworkID: "net-unknown"})
	if got := g2.Apply("t", conns)[0].ReachableRoutes.CIDRs; len(got) != 0 {
		t.Fatalf("unresolved network reference must contribute nothing, got %v", got)
	}
}

// Config-bundle fold (Gap B): the governance DECISIONS ride the bundle, so a pull-model Edge converges on the
// CP-configured bindings + hold/adopt state WITHOUT a shared store. Export -> ImportShared reproduces the
// decisions; an empty/nil section is lockout-safe; the generation bumps on a decision but not on discovery-only.
func TestConnectorRouteGovernance_ConfigBundleFold(t *testing.T) {
	// Edge-A (the CP-side authority) makes decisions.
	a := newConnectorRouteGovernanceWithOptions("", true)
	now := time.Now()
	a.SeeRoutes("t", "c1", []string{"10.0.0.0/24", "10.9.0.0/24"}, now) // discovered, none routable yet
	a.SetApproved("t", "c1", "10.0.0.0/24", true)                       // adopt one
	a.AddAuthored("t", "c1", authoredRoute{CIDR: "192.168.4.0/24"})     // CP-configured binding
	a.AddAuthored("t", "c1", authoredRoute{FQDN: "wiki.corp"})          // CP-configured name binding

	state := a.Export()
	if state == nil {
		t.Fatal("Export must return the decisions")
	}

	// Edge-B pulls the bundle: fresh governance adopts the distributed decisions and routes identically.
	b := newConnectorRouteGovernanceWithOptions("", true)
	b.ImportShared(state)
	conns := []model.ConnectorRegistration{{ID: "c1", ConnectorGroupID: "c1", ReachableRoutes: model.ConnectorReachableRoutes{CIDRs: []string{"10.0.0.0/24", "10.9.0.0/24"}, FQDNDomains: []string{"corp.internal"}}}}
	eff := b.Apply("t", conns)[0].ReachableRoutes
	hasCIDR := func(c string) bool {
		for _, x := range eff.CIDRs {
			if x == c {
				return true
			}
		}
		return false
	}
	if !hasCIDR("10.0.0.0/24") || hasCIDR("10.9.0.0/24") || !hasCIDR("192.168.4.0/24") {
		t.Fatalf("pull-model Edge must route the adopted + authored bindings only, got %v", eff.CIDRs)
	}
	hasFQDN := false
	for _, f := range eff.FQDNDomains {
		if f == "wiki.corp" {
			hasFQDN = true
		}
	}
	if !hasFQDN {
		t.Fatalf("authored FQDN binding must distribute, got %v", eff.FQDNDomains)
	}

	// Lockout-safe: a nil / empty section never wipes local decisions.
	before := b.Export()
	b.ImportShared(nil)
	b.ImportShared(&governancePersistState{})
	after := b.Export()
	if before == nil || after == nil || len(after.Authored["t"]["c1"]) != len(before.Authored["t"]["c1"]) {
		t.Fatal("nil/empty import must keep local decisions (lockout-safe)")
	}

	// Generation: bumps on a decision, NOT on a discovery-only observation.
	g := newConnectorRouteGovernanceWithOptions("", true)
	g0 := g.ConfigGeneration()
	g.SeeRoutes("t", "c1", []string{"10.0.0.0/24"}, now) // first-sight (cpConfigured): discovery only, no decision
	if g.ConfigGeneration() != g0 {
		t.Fatalf("a discovery-only observation must not bump the generation")
	}
	g.SetApproved("t", "c1", "10.0.0.0/24", true) // a real decision
	if g.ConfigGeneration() == g0 {
		t.Fatalf("a decision must bump the generation")
	}
}
