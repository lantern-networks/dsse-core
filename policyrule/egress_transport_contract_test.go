package policyrule_test

import (
	"fmt"
	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policyrule"
	"strings"
	"testing"
)

func TestEgressServiceTransportPairsAndMissingReferences(t *testing.T) {
	a := assetcatalog.NewStore()
	for _, tenant := range []string{"a", "b"} {
		_, err := a.UpsertEndpoint(assetcatalog.Endpoint{ID: "dest", TenantID: tenant, Kind: assetcatalog.KindNetwork, Address: "service.invalid"})
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err := a.UpsertService(assetcatalog.Service{ID: "svc", TenantID: "b", Ports: []assetcatalog.PortProto{{Protocol: "tcp", Port: 443}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{policyrule.AccessAllow, policyrule.AccessDeny, policyrule.AccessAuthenticate} {
		t.Run(action, func(t *testing.T) {
			r := policyrule.Rule{ID: "authored", TenantID: "a", Plane: policyrule.PlaneEgress, Status: policyrule.StatusActive, Priority: 1, Source: []string{"*"}, Destination: []string{"dest"}, ServiceID: "svc", Action: policyrule.Action{Access: action, RequiredIdPID: "test-idp", MinACR: "phr"}}
			assertRequests := func(want map[string]bool) {
				t.Helper()
				compiled := policyrule.CompileEgressPolicies("a", []policyrule.Rule{r}, a)
				if len(compiled) == 0 {
					t.Fatal("authored rule disappeared")
				}
				ids := map[string]bool{}
				for _, p := range compiled {
					if ids[p.ID] {
						t.Fatal("duplicate policy ID", p.ID)
					}
					ids[p.ID] = true
				}
				ev := decision.Evaluator{Policies: compiled}
				for _, proto := range []string{"tcp", "udp", "", "sctp"} {
					for _, port := range []int{0, 22, 53, 443, 8443, 65535} {
						req := model.DecisionRequest{TenantID: "a", ActorType: "human", Destination: "service.invalid", FQDN: "service.invalid", SNI: "service.invalid", Protocol: proto, DestinationPort: port}
						d := ev.Evaluate(req)
						got := strings.HasPrefix(ev.ExplainDecision(req).WinnerPolicyID, "rule-egress-authored")
						if got != want[fmt.Sprintf("%s/%d", proto, port)] {
							t.Fatalf("%s/%d authored=%v want=%v decision=%+v", proto, port, got, want, d)
						}
						if got {
							expected := action
							if action == policyrule.AccessAuthenticate {
								expected = "require_reauthentication"
							}
							if d.Decision != expected {
								t.Fatalf("wrong action %s", d.Decision)
							}
						}
					}
				}
				req := model.DecisionRequest{TenantID: "b", ActorType: "human", FQDN: "service.invalid", SNI: "service.invalid", Protocol: "tcp", DestinationPort: 443}
				if strings.HasPrefix(ev.ExplainDecision(req).WinnerPolicyID, "rule-egress-authored") {
					t.Fatal("foreign tenant match")
				}
			}
			_, err := a.UpsertService(assetcatalog.Service{ID: "svc", TenantID: "a", Ports: []assetcatalog.PortProto{{Protocol: " TCP ", Port: 22}, {Protocol: "tcp", Port: 8443}, {Protocol: "udp", Port: 53}, {Protocol: "udp", Port: 443}, {Protocol: "tcp", Port: 22}}})
			if err != nil {
				t.Fatal(err)
			}
			assertRequests(map[string]bool{"tcp/22": true, "tcp/8443": true, "udp/53": true, "udp/443": true})
			_, err = a.DeleteService("a", "svc")
			if err != nil {
				t.Fatal(err)
			}
			assertRequests(nil)
			if !policyrule.EgressServiceUnresolved("a", "svc", a) || policyrule.EgressServiceUnresolved("b", "svc", a) {
				t.Fatal("resolution crossed tenant")
			}
			r.ServiceID = " "
			assertRequests(nil)
			r.ServiceID = ""
			all := map[string]bool{}
			for _, proto := range []string{"tcp", "udp", "", "sctp"} {
				for _, port := range []int{0, 22, 53, 443, 8443, 65535} {
					all[fmt.Sprintf("%s/%d", proto, port)] = true
				}
			}
			assertRequests(all)
		})
	}
}

// Old integrations exposing ports only must not silently drop the protocol.
type legacyPortResolver struct{}

func (legacyPortResolver) SourceDeviceTokens(string, []string) []string { return nil }
func (legacyPortResolver) EndpointAddresses(string, []string) []string {
	return []string{"service.invalid"}
}
func (legacyPortResolver) ServicePorts(string, string) []int { return []int{443} }
func TestEgressServicePortOnlyResolverDoesNotAuthorize(t *testing.T) {
	r := policyrule.Rule{ID: "legacy", TenantID: "a", Plane: policyrule.PlaneEgress, Status: policyrule.StatusActive, Source: []string{"*"}, Destination: []string{"dest"}, ServiceID: "svc", Action: policyrule.Action{Access: policyrule.AccessAllow}}
	ev := decision.Evaluator{Policies: policyrule.CompileEgressPolicies("a", []policyrule.Rule{r}, legacyPortResolver{})}
	for _, protocol := range []string{"tcp", "udp", ""} {
		req := model.DecisionRequest{TenantID: "a", ActorType: "human", FQDN: "service.invalid", SNI: "service.invalid", Protocol: protocol, DestinationPort: 443}
		if ev.ExplainDecision(req).WinnerPolicyID != "" || ev.Evaluate(req).Decision != "deny" {
			t.Fatal("port-only resolver authorized", protocol)
		}
	}
}
