package main

import (
	"testing"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
)

func TestConnectorAccessUsesVerifiedFlowTenantOnSharedEdge(t *testing.T) {
	store := policy.NewStore(nil)
	for _, tenant := range []string{"node", "customer"} {
		store.SetEastWestEnabled(tenant, true)
		store.SetEastWestAllowUnmatched(tenant, true)
	}
	store.SetCompiledEastWestRules("customer", []decision.EastWestRule{{
		ID: "deny-private-app", Priority: 1, Destinations: []string{"10.200.0.11"},
		ServiceTransportPorts: map[string][]int{"tcp": {18082}}, Mode: "deny",
	}})
	base := decision.Evaluator{PolicyBundle: model.PolicyBundle{TenantID: "node"}}
	request := model.DecisionRequest{
		TenantID: "customer", Destination: "10.200.0.11", DestinationPort: 18082,
		Protocol: "tcp", ConnectorRouteVerified: true, ActorType: "human",
	}
	if got := runtimeEvaluatorForTenant(base, store, "customer").Evaluate(request); got.Decision != "deny" || got.PolicyID != "east_west_policy" {
		t.Fatalf("customer Connector Access rule must deny on a shared Edge: %+v", got)
	}
	request.DestinationPort = 18081
	if got := runtimeEvaluatorForTenant(base, store, "customer").Evaluate(request); got.Decision != "allow" {
		t.Fatalf("unmatched private app remains allowed in partial mode: %+v", got)
	}
	request.TenantID = "node"
	request.DestinationPort = 18082
	if got := runtimeEvaluatorForTenant(base, store, "node").Evaluate(request); got.Decision != "allow" {
		t.Fatalf("one tenant's deny must not leak into the node tenant: %+v", got)
	}
}
