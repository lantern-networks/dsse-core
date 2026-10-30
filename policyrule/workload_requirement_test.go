package policyrule

import (
	"testing"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

func TestAuthoredWorkloadRequirementSurvivesCompilation(t *testing.T) {
	for _, plane := range []string{PlaneEgress, PlaneEastWest} {
		t.Run(plane, func(t *testing.T) {
			r := Rule{ID: "machine", TenantID: "tenant", Plane: plane, Direction: DirectionOutbound, Status: StatusActive, Source: []string{"*"}, Destination: []string{"*"}, Action: Action{Access: AccessAllow, RequireWorkloadAttestation: true}}
			e := decision.Evaluator{}
			if plane == PlaneEgress {
				e.Policies = CompileEgressPolicies("tenant", []Rule{r}, fakeEgressResolver{})
			} else {
				e.EastWestEnabled = true
				e.EastWestRules = CompileEastWest("tenant", []Rule{r}, stubEWResolver{})
			}
			req := model.DecisionRequest{TenantID: "tenant", Destination: "10.0.0.1", ServiceFamily: "ssh", ActorType: "nhi", ActorNHIID: "machine"}
			if got := e.Evaluate(req); got.Decision != "require_workload_attestation" {
				t.Fatalf("unverified workload was %s", got.Decision)
			}
			req.WorkloadAttestationState = "verified"
			if got := e.Evaluate(req); got.Decision != "allow" {
				t.Fatalf("verified workload was %s", got.Decision)
			}
		})
	}
}

func TestCompilersDoNotAdoptOtherTenantRules(t *testing.T) {
	for _, plane := range []string{PlaneEgress, PlaneEastWest} {
		r := Rule{ID: "foreign", TenantID: "acme", Plane: plane, Direction: DirectionOutbound, Status: StatusActive, Source: []string{"*"}, Destination: []string{"*"}, Action: Action{Access: AccessAllow}}
		if plane == PlaneEgress && len(CompileEgressPolicies("Acme", []Rule{r}, fakeEgressResolver{})) != 0 {
			t.Error("foreign egress rule adopted")
		}
		if plane == PlaneEastWest && len(CompileEastWest("Acme", []Rule{r}, stubEWResolver{})) != 0 {
			t.Error("foreign east-west rule adopted")
		}
	}
}

func TestAuthoredAuthenticationAlsoRequiresWorkloadProof(t *testing.T) {
	for _, plane := range []string{PlaneEgress, PlaneEastWest} {
		r := Rule{ID: "both", TenantID: "tenant", Plane: plane, Direction: DirectionOutbound, Status: StatusActive, Source: []string{"*"}, Destination: []string{"*"}, Action: Action{Access: AccessAuthenticate, RequireWorkloadAttestation: true}}
		e := decision.Evaluator{}
		wantAuth := "require_reauthentication"
		if plane == PlaneEgress {
			e.Policies = CompileEgressPolicies("tenant", []Rule{r}, fakeEgressResolver{})
		} else {
			e.EastWestEnabled = true
			e.EastWestRules = CompileEastWest("tenant", []Rule{r}, stubEWResolver{})
			wantAuth = "authenticate_required"
		}
		req := model.DecisionRequest{TenantID: "tenant", Destination: "10.0.0.1", ServiceFamily: "ssh", ActorType: "nhi", ActorNHIID: "machine"}
		if got := e.Evaluate(req); got.Decision != "require_workload_attestation" {
			t.Errorf("%s: unverified workload reached grant-releasable decision %s", plane, got.Decision)
		}
		req.WorkloadAttestationState = "verified"
		if got := e.Evaluate(req); got.Decision != wantAuth {
			t.Errorf("%s: verified workload skipped user authentication: %s", plane, got.Decision)
		}
	}
}
