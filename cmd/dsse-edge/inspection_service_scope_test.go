package main

import (
	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/inspectionposture"
	"github.com/lantern-networks/dsse-core/knownbypass"
	"github.com/lantern-networks/dsse-core/policyrule"
	"testing"
)

func TestInspectionServiceScopeRebuildsBothModes(t *testing.T) {
	e := edgeplane.NewNetworkExtensionLabTLSInterceptionMatchOnly([]string{"*"})
	p := inspectionposture.NewStore()
	r := policyrule.NewStore()
	a := assetcatalog.NewStore()
	o := knownbypass.NewOverrideStore()
	a.SetBuiltInServices(assetcatalog.BuiltInServices())
	if _, err := a.UpsertEndpoint(assetcatalog.Endpoint{ID: "destination", TenantID: "a", Kind: assetcatalog.KindNetwork, Address: "target.invalid", Alias: "target"}); err != nil {
		t.Fatal(err)
	}
	apply := newTenantInspectionApplier(e, p, r, a, o, func() []knownbypass.Group { return nil }, []string{"*"}, nil)
	route := edgeplane.NetworkExtensionRuntimeCopyTCPRoute{TenantID: "a", Host: "target.invalid", Port: 443}
	for _, mode := range []string{inspectionposture.ModeDecryptAll, inspectionposture.ModeBypassDefault} {
		if _, err := p.Set(inspectionposture.Posture{Mode: mode, DecryptAllowlistHosts: []string{"selected.invalid"}}); err != nil {
			t.Fatal(err)
		}
		inspection := policyrule.InspectionBypass
		if mode == inspectionposture.ModeBypassDefault {
			inspection = policyrule.InspectionInspect
		}
		for _, service := range []string{"builtin-svc-https", "builtin-svc-ssh", "missing", "", "builtin-svc-ssh"} {
			if _, err := r.Upsert(policyrule.Rule{ID: "rule", TenantID: "a", Plane: policyrule.PlaneEgress, Source: []string{"*"}, Destination: []string{"destination"}, ServiceID: service, Action: policyrule.Action{Access: policyrule.AccessAllow, Inspection: inspection}}); err != nil {
				t.Fatal(err)
			}
			apply("a")
			applies := service == "" || service == "builtin-svc-https"
			want := applies
			if mode == inspectionposture.ModeDecryptAll {
				want = !applies
			}
			if got := e.Matches(route); got != want {
				t.Fatalf("%s/%s: inspection=%v want %v", mode, service, got, want)
			}
			other := route
			other.TenantID = "b"
			if got := e.Matches(other); got != (mode == inspectionposture.ModeDecryptAll) {
				t.Fatal("service change crossed tenant")
			}
		}
	}
}
