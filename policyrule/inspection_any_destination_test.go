package policyrule

import (
	"reflect"
	"testing"

	"github.com/lantern-networks/dsse-core/assetcatalog"
)

func TestInspectionAnyDestinationPreservesScope(t *testing.T) {
	assets := assetcatalog.NewStore()
	if _, err := assets.UpsertEndpoint(assetcatalog.Endpoint{ID: "device", TenantID: "customer", Kind: assetcatalog.KindSteeredDevice, Identity: "device-one", Alias: "one"}); err != nil {
		t.Fatal(err)
	}
	for _, axis := range []string{InspectionBypass, InspectionInspect} {
		for _, source := range [][]string{{"*"}, {"device"}} {
			rule := Rule{TenantID: "customer", Plane: PlaneEgress, Status: StatusActive, Source: source, Destination: []string{"*"}, Action: Action{Access: AccessAllow, Inspection: axis}}
			got := EgressInspectionHosts("customer", []Rule{rule}, assets, axis)
			want := InspectionHostSelection{AnySource: []string{"*"}}
			if source[0] == "device" {
				want = InspectionHostSelection{AnySource: []string{}, ByDevice: map[string][]string{"device-one": {"*"}}}
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("%s source=%v: got %+v want %+v", axis, source, got, want)
			}
			if other := EgressInspectionHosts("other", []Rule{rule}, assets, axis); len(other.AnySource)+len(other.ByDevice) != 0 {
				t.Fatal("wildcard crossed tenants", other)
			}
			rule.Status = StatusDisabled
			if disabled := EgressInspectionHosts("customer", []Rule{rule}, assets, axis); len(disabled.AnySource)+len(disabled.ByDevice) != 0 {
				t.Fatal("disabled rule still applied", disabled)
			}
		}
	}
	for _, destination := range [][]string{nil, {}, {"unknown"}} {
		rule := Rule{TenantID: "customer", Plane: PlaneEgress, Status: StatusActive, Source: []string{"*"}, Destination: destination, Action: Action{Access: AccessAllow, Inspection: InspectionBypass}}
		got := EgressInspectionHosts("customer", []Rule{rule}, assets, InspectionBypass)
		if len(got.AnySource)+len(got.ByDevice) != 0 {
			t.Fatal("missing destination widened to Any", destination, got)
		}
	}
}
