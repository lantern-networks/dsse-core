package main

import (
	"testing"

	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
)

// Reproduces what the Windows steer path decides for a normal 443 HTTPS flow, with the reference-style
// general egress allow (actor_type=human, destination_port=443, service_family=https) and an observe
// learning posture — to confirm whether the deny is no-policy-match + missing observe-defer.
func TestSteerEgress443Decision(t *testing.T) {
	tenant := testEvaluator().PolicyBundle.TenantID
	allow := model.Policy{
		ID: "pol_general_egress_allow", TenantID: tenant, Priority: 10, Status: "active",
		Conditions: map[string]any{"actor_type": "human", "destination_port": 443, "service_family": "https"},
		Action:     model.PolicyAction{Decision: "allow"},
	}
	store := policy.NewStore([]model.Policy{allow})
	eval := store.RuntimeEvaluator(testEvaluator())

	req := steerDecisionRequest(tenant, "cloudflare.com", 443)
	t.Logf("steer req: actor=%q port=%d family=%q steering=%q", req.ActorType, req.DestinationPort, req.ServiceFamily, req.SteeringMode)
	dec := eval.Evaluate(req)
	t.Logf("matching request: decision=%q policy=%q reasons=%v", dec.Decision, dec.PolicyID, dec.ReasonCodes)

	// A non-matching port (e.g. 8443 -> https but port!=443): the default-deny path. Policy Learning used to
	// turn this into decision "observe"; with it removed (2026-08-05) an unmatched request is denied.
	req3 := steerDecisionRequest(tenant, "internal.host", 9999)
	dec3 := eval.Evaluate(req3)
	t.Logf("port 9999 (no match): decision=%q reasons=%v", dec3.Decision, dec3.ReasonCodes)
}
