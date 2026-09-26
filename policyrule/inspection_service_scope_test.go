package policyrule

import (
	"github.com/lantern-networks/dsse-core/assetcatalog"
	"reflect"
	"testing"
)

func TestInspectionHostProjectionRespectsServiceTransport(t *testing.T) {
	catalog := assetcatalog.NewStore()
	catalog.SetBuiltInServices(assetcatalog.BuiltInServices())
	for _, tenant := range []string{"a", "b"} {
		if _, err := catalog.UpsertEndpoint(assetcatalog.Endpoint{ID: "destination", TenantID: tenant, Kind: assetcatalog.KindNetwork, Address: tenant + ".invalid", Alias: "target"}); err != nil {
			t.Fatal(err)
		}
	}
	for _, svc := range []assetcatalog.Service{
		{ID: "udp", TenantID: "a", Alias: "UDP", Ports: []assetcatalog.PortProto{{Protocol: "udp", Port: 443}}},
		{ID: "mixed", TenantID: "a", Alias: "mixed", Ports: []assetcatalog.PortProto{{Protocol: "udp", Port: 53}, {Protocol: "tcp", Port: 443}}},
		{ID: "same", TenantID: "a", Alias: "same", Ports: []assetcatalog.PortProto{{Protocol: "tcp", Port: 443}}},
		{ID: "same", TenantID: "b", Alias: "same", Ports: []assetcatalog.PortProto{{Protocol: "tcp", Port: 22}}},
	} {
		if _, err := catalog.UpsertService(svc); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name, tenant, service string
		contributes           bool
	}{
		{"any", "a", "", true}, {"https", "a", "builtin-svc-https", true}, {"ssh", "a", "builtin-svc-ssh", false},
		{"http", "a", "builtin-svc-http", false}, {"udp443", "a", "udp", false}, {"mixed", "a", "mixed", true},
		{"unresolved", "a", "missing", false}, {"blank named service", "a", " ", false},
		{"tenant a https", "a", "same", true}, {"tenant b ssh", "b", "same", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, inspection := range []string{InspectionBypass, InspectionInspect} {
				r := Rule{ID: "r", TenantID: tc.tenant, Plane: PlaneEgress, Status: StatusActive, Source: []string{SubjectAny}, Destination: []string{"destination"}, ServiceID: tc.service, Action: Action{Access: AccessAllow, Inspection: inspection}}
				var got []string
				if inspection == InspectionBypass {
					got = EgressBypassFQDNs(tc.tenant, []Rule{r}, catalog)
				} else {
					got = EgressInspectFQDNs(tc.tenant, []Rule{r}, catalog)
				}
				want := []string{}
				if tc.contributes {
					want = []string{tc.tenant + ".invalid"}
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("%s got=%v want=%v", inspection, got, want)
				}
			}
		})
	}
	// Resolution must be current; deleting a service does not make it Any.
	if ok, err := catalog.DeleteService("a", "same"); !ok || err != nil {
		t.Fatal(ok, err)
	}
	r := Rule{Plane: PlaneEgress, Status: StatusActive, Source: []string{SubjectAny}, Destination: []string{"destination"}, ServiceID: "same", Action: Action{Access: AccessAllow, Inspection: InspectionBypass}}
	if got := EgressBypassFQDNs("a", []Rule{r}, catalog); len(got) != 0 {
		t.Fatal("deleted service widened bypass", got)
	}
	// Address-only callers cannot positively resolve a named service.
	if got := EgressBypassFQDNs("a", []Rule{r}, fakeResolver{"destination": {"a.invalid"}}); len(got) != 0 {
		t.Fatal("missing transport resolver widened bypass", got)
	}
}
