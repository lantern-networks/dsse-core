package policyrule

import (
	"github.com/lantern-networks/dsse-core/assetcatalog"
	"reflect"
	"testing"
)

func TestInspectionSourcesPreserveDeviceSelectors(t *testing.T) {
	a := assetcatalog.NewStore()
	for _, tenant := range []string{"a", "b"} {
		for _, id := range []string{"one", "two", "idgroup:staff"} {
			if _, err := a.UpsertEndpoint(assetcatalog.Endpoint{ID: id, TenantID: tenant, Kind: assetcatalog.KindSteeredDevice, Identity: tenant + "-" + id, Alias: id}); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := a.UpsertEndpoint(assetcatalog.Endpoint{ID: "target", TenantID: tenant, Kind: assetcatalog.KindNetwork, Address: tenant + ".invalid", Alias: "target"}); err != nil {
			t.Fatal(err)
		}
		if _, err := a.UpsertGroup(assetcatalog.Group{ID: "group", TenantID: tenant, Alias: "group", StaticMembers: []string{"one", "two"}}); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name    string
		source  []string
		devices []string
		all     bool
		warning string
	}{
		{name: "any", source: []string{SubjectAny}, all: true},
		{name: "one", source: []string{"one"}, devices: []string{"a-one"}},
		{name: "group", source: []string{"group"}, devices: []string{"a-one", "a-two"}},
		{name: "missing", source: []string{"missing"}, warning: "no_resolved_device"},
		{name: "empty", warning: "no_resolved_device"},
		{name: "identity namespace collision", source: []string{"idgroup:staff"}, warning: "identity_context_unavailable"},
		{name: "user", source: []string{"iduser:alice"}, warning: "identity_context_unavailable"},
		{name: "agent", source: []string{"nhi:agent"}, warning: "identity_context_unavailable"},
		{name: "mixed sources", source: []string{"one", "idgroup:staff"}, devices: []string{"a-one"}, warning: "identity_context_unavailable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, axis := range []string{InspectionBypass, InspectionInspect} {
				r := Rule{ID: "r", TenantID: "a", Plane: PlaneEgress, Status: StatusActive, Source: tc.source, Destination: []string{"target"}, Action: Action{Access: AccessAllow, Inspection: axis}}
				got := EgressInspectionHosts("a", []Rule{r}, a, axis)
				want := InspectionHostSelection{AnySource: []string{}}
				if tc.all {
					want.AnySource = []string{"a.invalid"}
				}
				if len(tc.devices) > 0 {
					want.ByDevice = map[string][]string{}
					for _, d := range tc.devices {
						want.ByDevice[d] = []string{"a.invalid"}
					}
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("%s got=%+v want=%+v", axis, got, want)
				}
				if warning := InspectionSourceWarning("a", r, a); warning != tc.warning {
					t.Fatalf("warning=%q", warning)
				}
				if got := EgressInspectionHosts("b", []Rule{r}, a, axis); len(got.AnySource)+len(got.ByDevice) != 0 {
					t.Fatal("foreign tenant rule contributed", got)
				}
			}
		})
	}
	// A removed group does not broaden its old member-scoped exception.
	if ok, err := a.DeleteGroup("a", "group"); !ok || err != nil {
		t.Fatal(ok, err)
	}
	r := Rule{TenantID: "a", Plane: PlaneEgress, Status: StatusActive, Source: []string{"group"}, Destination: []string{"target"}, Action: Action{Access: AccessAllow, Inspection: InspectionBypass}}
	got := EgressInspectionHosts("a", []Rule{r}, a, InspectionBypass)
	if len(got.AnySource)+len(got.ByDevice) != 0 {
		t.Fatal("deleted group became broad", got)
	}
	if got := EgressInspectionHosts("a", []Rule{r}, fakeResolver{"target": {"target.invalid"}}, InspectionBypass); len(got.AnySource)+len(got.ByDevice) != 0 {
		t.Fatal("address-only resolver widened source", got)
	}
}
