package main

import (
	"testing"

	"github.com/lantern-networks/dsse-core/policyrule"
)

type namedFlowResolver struct{ addr map[string][]string }

func (namedFlowResolver) SourceDeviceTokens(string, []string) []string { return nil }
func (r namedFlowResolver) EndpointAddresses(_ string, ids []string) []string {
	var out []string
	for _, id := range ids {
		out = append(out, r.addr[id]...)
	}
	return out
}
func (namedFlowResolver) ServicePorts(string, string) []int                     { return nil }
func (namedFlowResolver) ServiceTransportPorts(string, string) map[string][]int { return nil }

// The 0.4.3 acceptance: a deny for example.org authored in the Console, and an "allow, not inspected" for
// everything added below it to reproduce. A device that names its destination (the macOS agent does) reached
// example.org raw, because the steered flow's decision carried the name only as Destination and the rule's
// fqdn condition reads FQDN.
func TestASteeredFlowNamedByTheDeviceIsDecidedByItsName(t *testing.T) {
	rules := []policyrule.Rule{
		{ID: "deny-example", Plane: policyrule.PlaneEgress, Status: policyrule.StatusActive, Priority: 1,
			Source: []string{"*"}, Destination: []string{"ep-example"},
			Action: policyrule.Action{Access: policyrule.AccessDeny, Inspection: policyrule.InspectionInspect}},
		{ID: "allow-everything-raw", Plane: policyrule.PlaneEgress, Status: policyrule.StatusActive, Priority: 50,
			Source: []string{"*"}, Destination: []string{"*"},
			Action: policyrule.Action{Access: policyrule.AccessAllow, Inspection: policyrule.InspectionBypass}},
	}
	policies := policyrule.CompileEgressPolicies("tenant_lab_001", rules,
		namedFlowResolver{addr: map[string][]string{"ep-example": {"example.org"}}})
	evaluator := testEvaluatorWithPolicies(policies)

	for _, named := range []string{"example.org", "Example.ORG."} {
		got := evaluator.Evaluate(steerDecisionRequest("tenant_lab_001", named, 443))
		if got.Decision != "deny" {
			t.Fatalf("a flow the device named %q was decided %q by %q, want the deny written for example.org",
				named, got.Decision, got.PolicyID)
		}
	}
	if got := evaluator.Evaluate(steerDecisionRequest("tenant_lab_001", "www.iana.org", 443)); got.Decision != "allow" {
		t.Fatalf("a name no rule denies was decided %q by %q, want the allow", got.Decision, got.PolicyID)
	}
	// An address is not given a name it did not come with.
	if req := steerDecisionRequest("tenant_lab_001", "93.184.215.14", 443); req.FQDN != "" {
		t.Fatalf("an address flow was given the name %q", req.FQDN)
	}
}
