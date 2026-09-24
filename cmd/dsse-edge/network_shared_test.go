package main

import (
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/vlan"
	"net/http"
	"testing"
)

func TestNetworkSharedPeerPreservation(t *testing.T) {
	p := &entitlementReviewPersister{}
	a, b := vlan.NewStore(), vlan.NewStore()
	if e := a.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	if e := b.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	if _, e := a.UpsertObject(model.VLANObject{ID: "first", TenantID: "one", Class: "server", CIDRs: []string{"10.1.0.0/24"}}); e != nil {
		t.Fatal(e)
	}
	if _, e := b.UpsertObject(model.VLANObject{ID: "second", TenantID: "two", Class: "server", CIDRs: []string{"10.2.0.0/24"}}); e != nil {
		t.Fatal(e)
	}
	restored := vlan.NewStore()
	if e := restored.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	if len(restored.ListObjects()) != 2 {
		t.Fatal("acknowledged peer network erased")
	}
}
func TestNetworkForeignIDCannotBeClaimed(t *testing.T) {
	declareOperatorTenantForTest(t, "operator")
	for _, kind := range []string{"object", "policy"} {
		t.Run(kind, func(t *testing.T) {
			s := vlan.NewStore()
			s.UpsertObject(model.VLANObject{ID: "foreign", TenantID: "other", Class: "server", CIDRs: []string{"10.1.0.0/24"}})
			s.UpsertPolicy(model.VLANBoundaryPolicy{ID: "foreign", TenantID: "other", SourceClass: "server", DestClass: "server", Mode: "observe"})
			mux := http.NewServeMux()
			registerVLANRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, s, "")
			path, body := "/admin/vlan-objects", `{"id":"foreign","class":"server","cidrs":["10.2.0.0/24"]}`
			if kind == "policy" {
				path = "/admin/vlan-boundary-policies"
				body = `{"id":"foreign","source_class":"server","dest_class":"server","mode":"observe"}`
			}
			code, body := vlanScopeCall(t, mux, "POST", path, body, adminIdentity{TenantID: "own", PrincipalID: "admin", Roles: []string{"admin"}, AuthMethod: "admin_session"})
			if code != 404 {
				t.Fatalf("foreign id takeover: %d %s", code, body)
			}
			if s.ListObjects()[0].TenantID != "other" || s.ListPolicies()[0].TenantID != "other" {
				t.Fatal("owner changed")
			}
		})
	}
}

func TestNetworkLatestOwnerAndAuthorityFailure(t *testing.T) {
	declareOperatorTenantForTest(t, "operator")
	p := &entitlementReviewPersister{}
	s, peer := vlan.NewStore(), vlan.NewStore()
	if e := s.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	if e := peer.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	mux := http.NewServeMux()
	registerVLANRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, s, "")
	own := adminIdentity{TenantID: "own", PrincipalID: "admin", Roles: []string{"admin"}, AuthMethod: "admin_session"}
	if _, e := peer.UpsertObject(model.VLANObject{ID: "late", TenantID: "foreign", Class: "server", CIDRs: []string{"10.1.0.0/24"}}); e != nil {
		t.Fatal(e)
	}
	for _, c := range []struct{ method, path, body string }{
		{"POST", "/admin/vlan-objects", `{"id":"late","class":"server","cidrs":["10.2.0.0/24"]}`},
		{"DELETE", "/admin/vlan-objects/late", ""},
	} {
		if code, body := vlanScopeCall(t, mux, c.method, c.path, c.body, own); code != 404 {
			t.Fatalf("late owner %d %s", code, body)
		}
	}
	if e := s.RefreshShared(); e != nil {
		t.Fatal(e)
	}
	gen := s.ConfigGeneration()
	saved := append([]byte(nil), p.raw...)
	for _, raw := range [][]byte{nil, []byte(`{}`), []byte(`{"objects":{},"policies":null}`)} {
		p.raw = raw
		if e := s.RefreshShared(); e == nil {
			t.Fatal("missing/corrupt authority read as empty")
		}
		if _, e := s.UpsertObject(model.VLANObject{ID: "new", Class: "server", CIDRs: []string{"10.2.0.0/24"}}); e == nil {
			t.Fatal("authority overwritten")
		}
		if s.ConfigGeneration() != gen || len(s.ListObjects()) != 1 {
			t.Fatal("failed change published")
		}
	}
	p.raw = saved
	if e := s.ReplaceAll(nil, nil); e == nil {
		t.Fatal("shared authority replaced by cached bundle")
	}
	p.fail = true
	if _, e := s.DeleteObject("late"); e == nil {
		t.Fatal("failed delete accepted")
	}
	if _, ok := s.GetObject("late"); !ok {
		t.Fatal("failed delete published")
	}
	p.fail = false
	if objects, policies, e := s.RemoveTenant("foreign"); e != nil || objects != 1 || policies != 0 {
		t.Fatalf("purge: %d %d %v", objects, policies, e)
	}
	if e := peer.RefreshShared(); e != nil || len(peer.ListObjects()) != 0 {
		t.Fatalf("purged object resurrected %v", e)
	}
}
