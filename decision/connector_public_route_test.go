package decision

import (
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

func TestVerifiedConnectorRouteCannotFallThroughToInternetAllow(t *testing.T) {
	e := Evaluator{
		EastWestEnabled: true,
		Policies:        []model.Policy{{ID: "internet-allow", TenantID: "tenant", Status: "active", Action: model.PolicyAction{Decision: "allow"}}},
		EastWestRules:   []EastWestRule{{ID: "connector-deny", Destinations: []string{"203.0.113.10"}, Mode: EastWestModeDeny}},
	}
	for _, family := range []string{"tcp", "https", "ssh"} {
		t.Run(family, func(t *testing.T) {
			req := model.DecisionRequest{TenantID: "tenant", Destination: "203.0.113.10", DestinationPort: 18081, Protocol: "tcp", ServiceFamily: family}
			// The same public destination reached directly remains Internet Access.
			if got := e.Evaluate(req); got.Decision != "allow" || got.PolicyID != "internet-allow" {
				t.Fatalf("direct route changed: %s/%s", got.Decision, got.PolicyID)
			}
			// The server's selected Connector is authoritative even if the cached
			// declared-network list is empty or has not yet caught up with routes.
			req.ConnectorRouteVerified = true
			if got := e.Evaluate(req); got.Decision != "deny" || !hasReasonCode(got.ReasonCodes, "east_west_policy_deny") {
				t.Fatalf("Connector Access denial bypassed: %s/%s", got.Decision, got.PolicyID)
			}
			req.Destination = "203.0.113.11"
			if got := e.Evaluate(req); got.Decision != "deny" || !hasReasonCode(got.ReasonCodes, "east_west_default_deny") {
				t.Fatalf("unmatched Connector Access escaped default denial: %s/%s", got.Decision, got.PolicyID)
			}
		})
	}
}
