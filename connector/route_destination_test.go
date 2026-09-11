package connector

import (
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

// TestResolveConnectorForDestinationPrefersNameThenIP proves the unified entry point: a NAME destination resolves
// by FQDN (no namespace needed), an IP destination resolves by CIDR within its namespace, and an unknown
// destination is fail-closed.
func TestResolveConnectorForDestinationPrefersNameThenIP(t *testing.T) {
	all := []model.ConnectorRegistration{
		{ID: "conn-name", ReachableRoutes: model.ConnectorReachableRoutes{FQDNDomains: []string{"tokyo.corp"}}},
		{ID: "conn-ip-tok", ReachableRoutes: model.ConnectorReachableRoutes{CIDRs: []string{"10.0.0.0/8"}, Namespace: "tokyo"}},
		{ID: "conn-ip-osa", ReachableRoutes: model.ConnectorReachableRoutes{CIDRs: []string{"10.0.0.0/8"}, Namespace: "osaka"}},
	}
	cases := []struct {
		dest, ns, wantID string
		wantOK           bool
	}{
		{"host.tokyo.corp", "", "conn-name", true}, // name wins, namespace irrelevant
		{"10.1.2.3", "tokyo", "conn-ip-tok", true}, // IP fallback, tokyo namespace
		{"10.1.2.3", "osaka", "conn-ip-osa", true}, // same IP, osaka namespace (overlap handled)
		{"10.1.2.3", "", "", false},                // IP with no namespace -> no CIDR match -> fail-closed
		{"unknown.example.com", "tokyo", "", false},
	}
	for _, tc := range cases {
		id, ok := ResolveConnectorForDestination(tc.dest, tc.ns, all)
		if ok != tc.wantOK || id != tc.wantID {
			t.Errorf("ResolveConnectorForDestination(%q,%q) = (%q,%v), want (%q,%v)", tc.dest, tc.ns, id, ok, tc.wantID, tc.wantOK)
		}
	}
}
