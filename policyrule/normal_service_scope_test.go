package policyrule_test

import (
	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policyrule"
	"testing"
)

func TestNamedServiceEditAndDeleteKeepExactAccessScope(t *testing.T) {
	s := assetcatalog.NewStore()
	service := assetcatalog.Service{ID: "db", TenantID: "tenant", Alias: "database", Ports: []assetcatalog.PortProto{{Protocol: "tcp", Port: 5432}}}
	if _, err := s.UpsertService(service); err != nil {
		t.Fatal(err)
	}
	rule := policyrule.Rule{ID: "allow-db", TenantID: "tenant", Plane: policyrule.PlaneEastWest, Direction: policyrule.DirectionOutbound, Status: policyrule.StatusActive, Source: []string{"*"}, Destination: []string{"*"}, ServiceID: "db", Action: policyrule.Action{Access: policyrule.AccessAllow}}
	check := func(label string, allowed int) {
		t.Helper()
		compiled := policyrule.CompileEastWest("tenant", []policyrule.Rule{rule}, s)
		for _, port := range []int{5432, 6432, 22} {
			for _, proto := range []string{"tcp", "udp"} {
				_, matched := decision.MatchedEastWestRule(compiled, model.DecisionRequest{TenantID: "tenant", Protocol: proto, DestinationPort: port, ServiceFamily: "database"})
				want := allowed == port && proto == "tcp"
				if matched != want {
					t.Errorf("%s: %s/%d matched=%v want=%v", label, proto, port, matched, want)
				}
			}
		}
	}
	check("create", 5432)
	service.Ports[0].Port = 6432
	if _, err := s.UpsertService(service); err != nil {
		t.Fatal(err)
	}
	check("port edit", 6432)
	service.Alias = "Finance database"
	if _, err := s.UpsertService(service); err != nil {
		t.Fatal(err)
	}
	check("rename", 6432)
	if _, err := s.DeleteService("tenant", "db"); err != nil {
		t.Fatal(err)
	}
	check("delete", 0)
}
