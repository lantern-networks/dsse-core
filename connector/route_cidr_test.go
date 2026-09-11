package connector

import (
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

func cidrConn(id, namespace string, cidrs ...string) model.ConnectorRegistration {
	return model.ConnectorRegistration{ID: id, ReachableRoutes: model.ConnectorReachableRoutes{CIDRs: cidrs, Namespace: namespace}}
}

// TestResolveConnectorForIPNamespaceScoped proves the overlap guarantee: the SAME CIDR in two site namespaces
// resolves to DIFFERENT connectors based on the flow's namespace, and longest-prefix wins within a namespace.
func TestResolveConnectorForIPNamespaceScoped(t *testing.T) {
	all := []model.ConnectorRegistration{
		cidrConn("conn-tokyo", "tokyo", "10.0.0.0/8"),
		cidrConn("conn-osaka", "osaka", "10.0.0.0/8"),      // SAME cidr, different site
		cidrConn("conn-tokyo-dc", "tokyo", "10.10.0.0/16"), // more specific, tokyo only
	}
	cases := []struct {
		ip, ns, wantID string
		wantOK         bool
	}{
		{"10.1.2.3", "tokyo", "conn-tokyo", true},     // tokyo namespace -> tokyo connector
		{"10.1.2.3", "osaka", "conn-osaka", true},     // SAME ip, osaka namespace -> osaka (overlap disambiguated)
		{"10.10.5.6", "tokyo", "conn-tokyo-dc", true}, // longest-prefix wins within tokyo
		{"10.10.5.6", "osaka", "conn-osaka", true},    // osaka only has /8
		{"192.0.2.1", "tokyo", "", false},             // no route -> fail-closed
		{"10.1.2.3", "nagoya", "", false},             // namespace with no connector
		{"not-an-ip", "tokyo", "", false},
	}
	for _, tc := range cases {
		id, ok := ResolveConnectorForIP(tc.ip, tc.ns, all)
		if ok != tc.wantOK || id != tc.wantID {
			t.Errorf("ResolveConnectorForIP(%q,%q) = (%q,%v), want (%q,%v)", tc.ip, tc.ns, id, ok, tc.wantID, tc.wantOK)
		}
	}
}

func TestResolveConnectorForIPTieBreakByID(t *testing.T) {
	all := []model.ConnectorRegistration{cidrConn("conn-b", "ns", "10.0.0.0/8"), cidrConn("conn-a", "ns", "10.0.0.0/8")}
	if id, ok := ResolveConnectorForIP("10.1.1.1", "ns", all); !ok || id != "conn-a" {
		t.Fatalf("tie-break: got (%q,%v), want conn-a", id, ok)
	}
}
