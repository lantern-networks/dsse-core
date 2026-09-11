package connector

import (
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

func routeConn(id string, domains ...string) model.ConnectorRegistration {
	return model.ConnectorRegistration{ID: id, ReachableRoutes: model.ConnectorReachableRoutes{FQDNDomains: domains}}
}

func TestResolveConnectorForHostFQDN(t *testing.T) {
	all := []model.ConnectorRegistration{
		routeConn("conn-tokyo", "tokyo.corp.internal"),
		routeConn("conn-osaka", "osaka.corp.internal"),
		routeConn("conn-wild", "*.dev.corp.internal"),
		routeConn("conn-app", "app.tokyo.corp.internal"), // more specific than tokyo.corp.internal
	}
	cases := []struct {
		host   string
		wantID string
		wantOK bool
	}{
		{"a.tokyo.corp.internal", "conn-tokyo", true},   // subdomain of a bare domain
		{"TOKYO.corp.internal.", "conn-tokyo", true},    // apex; case + trailing dot normalized
		{"db.osaka.corp.internal", "conn-osaka", true},  // routed to OSAKA, not tokyo (same shape, different site)
		{"x.dev.corp.internal", "conn-wild", true},      // wildcard subdomain
		{"dev.corp.internal", "", false},                // wildcard does NOT match its own apex
		{"app.tokyo.corp.internal", "conn-app", true},   // most-specific route wins over tokyo.corp.internal
		{"a.app.tokyo.corp.internal", "conn-app", true}, // subdomain of the most-specific route
		{"nope.example.com", "", false},                 // no route -> fail-closed (no implicit reach)
		{"", "", false},
	}
	for _, tc := range cases {
		id, ok := ResolveConnectorForHost(tc.host, all)
		if ok != tc.wantOK || id != tc.wantID {
			t.Errorf("ResolveConnectorForHost(%q) = (%q,%v), want (%q,%v)", tc.host, id, ok, tc.wantID, tc.wantOK)
		}
	}
}

// TestResolveConnectorTieBreakByID: when two connectors front the same domain, the result is deterministic
// (lexicographically smallest id) so routing is stable.
func TestResolveConnectorTieBreakByID(t *testing.T) {
	all := []model.ConnectorRegistration{routeConn("conn-b", "ha.corp"), routeConn("conn-a", "ha.corp")}
	if id, ok := ResolveConnectorForHost("x.ha.corp", all); !ok || id != "conn-a" {
		t.Fatalf("tie-break: got (%q,%v), want conn-a", id, ok)
	}
}

func ipConn(id, namespace string, cidrs ...string) model.ConnectorRegistration {
	return model.ConnectorRegistration{ID: id, ReachableRoutes: model.ConnectorReachableRoutes{Namespace: namespace, CIDRs: cidrs}}
}

func TestResolveConnectorForIP_UnscopedResolvesWhenUnambiguous(t *testing.T) {
	// A raw steered IP flow carries NO namespace; a single connector covers the CIDR -> resolves.
	conns := []model.ConnectorRegistration{ipConn("conn_lab_001", "lab-dc", "10.20.0.0/16")}
	if id, ok := ResolveConnectorForIP("10.20.0.10", "", conns); !ok || id != "conn_lab_001" {
		t.Fatalf("unscoped IP should resolve to conn_lab_001, got %q ok=%v", id, ok)
	}
}

func TestResolveConnectorForIP_ScopedStrictNamespace(t *testing.T) {
	// When the caller names a namespace, only that namespace's routes are eligible (multi-site guarantee).
	conns := []model.ConnectorRegistration{ipConn("conn_tokyo", "tokyo", "10.20.0.0/16")}
	if _, ok := ResolveConnectorForIP("10.20.0.10", "osaka", conns); ok {
		t.Fatalf("scoped lookup in the wrong namespace must NOT resolve")
	}
	if id, ok := ResolveConnectorForIP("10.20.0.10", "tokyo", conns); !ok || id != "conn_tokyo" {
		t.Fatalf("scoped lookup in the right namespace should resolve, got %q ok=%v", id, ok)
	}
}

func TestResolveConnectorForIP_UnscopedCrossNamespaceIsAmbiguous(t *testing.T) {
	// Two sites advertise the SAME overlapping CIDR; an unscoped lookup can't pick a site -> refuse.
	conns := []model.ConnectorRegistration{
		ipConn("conn_tokyo", "tokyo", "10.0.0.0/8"),
		ipConn("conn_osaka", "osaka", "10.0.0.0/8"),
	}
	if _, ok := ResolveConnectorForIP("10.20.0.10", "", conns); ok {
		t.Fatalf("unscoped lookup over overlapping cross-site CIDRs must be ambiguous (refuse), not guess")
	}
}
