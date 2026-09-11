package connector

import (
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

// ★★★ AN HA PAIR HAD ONE MEMBER IN THE DATAPATH (2026-09-01, measured by stopping one connector of a pair and
// watching the whole site go dark for as long as it was off).
//
// ResolveConnectorsForHost — the multi-candidate resolver the egress dialer walks — matched FQDN domains only.
// A private asset is published as a Named Network, which is a CIDR, so a destination inside one produced no
// matches, the caller fell back to the single-connector resolver, and every flow had exactly one candidate.
// The pair existed on the screen and in the catalogue and nowhere that carried traffic.
func TestBothMembersOfASiteAreCandidatesForASubnetTheyBothFront(t *testing.T) {
	pair := []model.ConnectorRegistration{
		{ID: "conn-a", ReachableRoutes: model.ConnectorReachableRoutes{CIDRs: []string{"10.60.0.0/16"}}},
		{ID: "conn-b", ReachableRoutes: model.ConnectorReachableRoutes{CIDRs: []string{"10.60.0.0/16"}}},
	}
	got := ResolveConnectorsForHost("10.60.1.176", pair)
	if len(got) != 2 {
		t.Fatalf("a destination both members front produced %d candidate(s): %v — losing one loses the site", len(got), got)
	}

	// ★ A MORE SPECIFIC ROUTE STILL WINS, the way a longer domain suffix does. Ordering is what makes a
	// deliberate override work; without it this fix would trade an outage for a mis-route.
	specific := append(append([]model.ConnectorRegistration{}, pair...),
		model.ConnectorRegistration{ID: "conn-narrow", ReachableRoutes: model.ConnectorReachableRoutes{CIDRs: []string{"10.60.1.0/24"}}})
	if first := ResolveConnectorsForHost("10.60.1.176", specific); len(first) == 0 || first[0] != "conn-narrow" {
		t.Errorf("longest prefix did not win: %v", first)
	}

	// ★ AND A DESTINATION NOBODY FRONTS IS STILL NOBODY'S. The fallback that hid this defect must not be
	// replaced by a resolver that matches too much.
	if got := ResolveConnectorsForHost("192.0.2.1", pair); len(got) != 0 {
		t.Errorf("an address outside every route matched %v", got)
	}
	// A name is unaffected: this adds a way to match, it does not change the existing one.
	named := []model.ConnectorRegistration{
		{ID: "conn-fqdn", ReachableRoutes: model.ConnectorReachableRoutes{FQDNDomains: []string{"hq.internal"}}},
	}
	if got := ResolveConnectorsForHost("app.hq.internal", named); len(got) != 1 || got[0] != "conn-fqdn" {
		t.Errorf("domain matching changed: %v", got)
	}
}
