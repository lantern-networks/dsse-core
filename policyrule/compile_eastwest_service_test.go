package policyrule_test

import (
	"encoding/json"
	"testing"

	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policyrule"
)

func TestEastWestServiceMatchesTransportAndPortNotDisplayName(t *testing.T) {
	s := assetcatalog.NewStore()
	svc, err := s.UpsertService(assetcatalog.Service{ID: "db", TenantID: "a", Alias: "Finance database", Ports: []assetcatalog.PortProto{{Protocol: "tcp", Port: 5432}, {Protocol: "udp", Port: 3306}}})
	if err != nil {
		t.Fatal(err)
	}
	rule := policyrule.Rule{ID: "r", TenantID: "a", Plane: policyrule.PlaneEastWest, Direction: policyrule.DirectionOutbound, Status: policyrule.StatusActive, Source: []string{"*"}, Destination: []string{"*"}, ServiceID: svc.ID, Action: policyrule.Action{Access: "allow"}}
	check := func(protocol string, port int, want bool) {
		t.Helper()
		rules := policyrule.CompileEastWest("a", []policyrule.Rule{rule}, s)
		// Compiled policies are persisted/distributed as JSON. Empty and nil selectors
		// must remain distinct after that boundary.
		raw, err := json.Marshal(rules)
		if err != nil {
			t.Fatal(err)
		}
		var restored []decision.EastWestRule
		if err := json.Unmarshal(raw, &restored); err != nil {
			t.Fatal(err)
		}
		if rule.ServiceID != "" {
			// Simulate the old JSON reader discarding the unknown condition.
			legacy := append([]decision.EastWestRule(nil), restored...)
			legacy[0].ServiceTransportPorts = nil
			for _, family := range []string{"ssh", "smb", "rdp", "database", "management_tcp"} {
				if _, matched := decision.MatchedEastWestRule(legacy, model.DecisionRequest{ServiceFamily: family}); matched {
					t.Fatal("legacy reader widened a named service")
				}
			}
		}
		_, ok := decision.MatchedEastWestRule(restored, model.DecisionRequest{Protocol: protocol, DestinationPort: port, ServiceFamily: "database"})
		if ok != want {
			t.Fatalf("%s/%d: matched %v, want %v", protocol, port, ok, want)
		}
	}
	check("tcp", 5432, true)
	check("tcp", 3306, false)
	check("udp", 3306, true)
	check("udp", 5432, false)
	check("", 5432, false)
	check("tcp", 0, false)
	svc.Alias = "Renamed inventory label"
	if _, err := s.UpsertService(svc); err != nil {
		t.Fatal(err)
	}
	check("tcp", 5432, true)
	if _, err := s.DeleteService("a", svc.ID); err != nil {
		t.Fatal(err)
	}
	check("tcp", 5432, false)
	check("tcp", 3306, false)
	rule.ServiceID = ""
	check("tcp", 3306, true)
}
