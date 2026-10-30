package main

import (
	"context"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// A grant is evidence for an authentication requirement, not permission to bypass
// a newer deny or stronger requirement. The caller rebuilds the request from live
// posture/directory state and provides the current policy generation.
func authorizeAuthenticatedResume(gate *federatedAuthGate, tenant, device, destination string, attempt time.Time, generation func() uint64, evaluate func() (model.AccessDecision, bool), requestID ...string) (model.AccessDecision, bool) {
	before := generation()
	dec, ok := evaluate()
	if !ok || dec.TenantID != tenant {
		return dec, false
	}
	allowed := dec.Decision == "allow" || decisionPermitsConnectorRoute(dec.Decision)
	if decisionRequiresOIDCRedirect(dec.Decision) {
		requirements := authFlowRequirements(dec, destination)
		requirements.AuthenticationStartedAt = attempt
		if len(requestID) >= 1 {
			requirements.RequestID = requestID[0]
			if len(requestID) == 3 {
				requirements.OSPrincipal, requirements.OSSession = requestID[1], requestID[2]
			}
		}
		allowed = gate.hasLiveGrantWithRequirements(tenant, device, requirements)
	}
	if !allowed || before != generation() {
		return dec, false
	}
	if decisionRequiresOIDCRedirect(dec.Decision) {
		requirements := authFlowRequirements(dec, destination)
		if requirements.MaxAgeSeconds != nil && *requirements.MaxAgeSeconds == 0 {
			if len(requestID) < 1 {
				return dec, false
			}
			requirements.RequestID = requestID[0]
			if len(requestID) == 3 {
				requirements.OSPrincipal, requirements.OSSession = requestID[1], requestID[2]
			}
			grant, ok := gate.liveGrantWithRequirements(tenant, device, requirements)
			if !ok {
				return dec, false
			}
			consumed, err := gate.grants.ConsumeAuthenticationRequest(context.Background(), grant, time.Now())
			if err != nil || !consumed || before != generation() {
				return dec, false
			}
		}
	}
	return dec, true
}
