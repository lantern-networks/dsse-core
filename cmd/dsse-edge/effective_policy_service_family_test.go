package main

import (
	"testing"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

// ★★★ THE PREVIEW MUST ANSWER THE QUESTION THAT WAS ASKED. Measured on the two-region lab: a flow to port 8080
// was denied by the Edge ("no active policy matched"), and this preview — the screen an operator opens BECAUSE
// something is denied — answered ALLOW, naming the starting "Allow HTTPS" rule. It took the port and defaulted
// the service family to https, so it was answering about HTTPS while the operator was asking about 8080.
func TestThePreviewDerivesTheServiceFamilyFromThePortTheOperatorGave(t *testing.T) {
	eval := decision.Evaluator{
		PolicyBundle: model.PolicyBundle{ID: "pb_test", TenantID: "tenant_a"},
		Policies: []model.Policy{{
			ID: "pol_allow_https", TenantID: "tenant_a", Priority: 100, Status: "active",
			Conditions: map[string]any{"actor_type": "human", "service_family": "https"},
			Action:     model.PolicyAction{Decision: "allow"},
		}},
	}

	// Port 443 is HTTPS, and the starting rule allows it.
	https := effectivePolicyForDestination(eval, "tenant_a",
		effectivePolicyQuery{Destination: "example.test", DestinationPort: 443}, inspectionSources{})
	if https.ServiceFamily != "https" || https.FinalDecision != "allow" {
		t.Fatalf("port 443: family=%q decision=%q; want https/allow", https.ServiceFamily, https.FinalDecision)
	}

	// ★ Port 8080 is NOT. The rule that allows HTTPS must not decide this one, and the answer must say which
	// family it was computed for so an operator can see why it differs from what the Edge did.
	http := effectivePolicyForDestination(eval, "tenant_a",
		effectivePolicyQuery{Destination: "example.test", DestinationPort: 8080}, inspectionSources{})
	if http.ServiceFamily != "http" {
		t.Fatalf("port 8080 was answered as %q — the operator asked about 8080", http.ServiceFamily)
	}
	if http.FinalDecision == "allow" && http.FinalPolicyID == "pol_allow_https" {
		t.Fatalf("the HTTPS rule decided a flow that is not HTTPS: %+v", http)
	}
	if http.ServiceFamilySource == "" {
		t.Fatalf("the answer does not say where the service family came from: %+v", http)
	}

	// An explicit family still wins — this derives a default, it does not override the caller.
	asked := effectivePolicyForDestination(eval, "tenant_a",
		effectivePolicyQuery{Destination: "example.test", DestinationPort: 8080, ServiceFamily: "https"},
		inspectionSources{})
	if asked.ServiceFamily != "https" || asked.ServiceFamilySource != "asked" {
		t.Fatalf("an explicitly asked family was not honoured: %+v", asked)
	}

	// A port this deployment maps to nothing must not become https by omission. Family-scoped rules then
	// cannot match, which is exactly what the datapath does.
	unknown := effectivePolicyForDestination(eval, "tenant_a",
		effectivePolicyQuery{Destination: "example.test", DestinationPort: 61234}, inspectionSources{})
	if unknown.ServiceFamily != "" {
		t.Fatalf("an unmapped port was answered as %q", unknown.ServiceFamily)
	}
}
