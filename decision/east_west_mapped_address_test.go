package decision

import (
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

func TestConnectorAccessRuleMatchesIPv4MappedWindowsDestination(t *testing.T) {
	rules := []EastWestRule{{
		ID: "private-deny", Destinations: []string{"10.200.0.11"},
		ServiceTransportPorts: map[string][]int{"tcp": {18082}}, Mode: "deny",
	}}
	for _, destination := range []string{"10.200.0.11", "::ffff:10.200.0.11", "::ffff:ac8:b"} {
		req := model.DecisionRequest{Destination: destination, DestinationPort: 18082, Protocol: "tcp"}
		if rule, ok := MatchedEastWestRule(rules, req); !ok || rule.ID != "private-deny" {
			t.Fatalf("mapped Windows destination %q did not match Connector Access rule: %+v, %t", destination, rule, ok)
		}
	}
	for _, destination := range []string{"::ffff:10.200.0.12", "10.200.0.12", "not-an-address"} {
		req := model.DecisionRequest{Destination: destination, DestinationPort: 18082, Protocol: "tcp"}
		if _, ok := MatchedEastWestRule(rules, req); ok {
			t.Fatalf("unrelated destination %q matched a private app rule", destination)
		}
	}
}
