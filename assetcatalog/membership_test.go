package assetcatalog

import (
	"reflect"
	"testing"
)

func strptr(s string) *string { return &s }
func boolptr(b bool) *bool    { return &b }

func TestResolveGroupMembersStaticPlusDynamic(t *testing.T) {
	s := NewStore()
	mac, _ := s.UpsertEndpoint(Endpoint{ID: "ep-mac", TenantID: "acme", Alias: "alice-mac", Kind: KindSteeredDevice, Platform: "macos", Steered: true, Tags: []string{"eng"}})
	win, _ := s.UpsertEndpoint(Endpoint{ID: "ep-win", TenantID: "acme", Alias: "bob-win", Kind: KindSteeredDevice, Platform: "windows", Steered: true, Tags: []string{"finance"}})
	srv, _ := s.UpsertEndpoint(Endpoint{ID: "ep-srv", TenantID: "acme", Alias: "prod-db", Kind: KindNetwork, Steered: false, Address: "10.2.0.7/32"})
	_ = win

	// Dynamic: platform=macos -> only the mac.
	g, _ := s.UpsertGroup(Group{TenantID: "acme", Alias: "macs", Dynamic: &MembershipRule{Platform: strptr("macos")}})
	if got := s.ResolveGroupMembers("acme", g.ID); !reflect.DeepEqual(got, []string{mac.ID}) {
		t.Fatalf("platform=macos members = %v, want [%s]", got, mac.ID)
	}

	// Dynamic: steered=false -> only the (network) server.
	g2, _ := s.UpsertGroup(Group{TenantID: "acme", Alias: "unmanaged", Dynamic: &MembershipRule{Steered: boolptr(false)}})
	if got := s.ResolveGroupMembers("acme", g2.ID); !reflect.DeepEqual(got, []string{srv.ID}) {
		t.Fatalf("steered=false members = %v, want [%s]", got, srv.ID)
	}

	// Dynamic: tag=eng -> only the mac (tag match).
	g3, _ := s.UpsertGroup(Group{TenantID: "acme", Alias: "eng", Dynamic: &MembershipRule{Tag: "eng"}})
	if got := s.ResolveGroupMembers("acme", g3.ID); !reflect.DeepEqual(got, []string{mac.ID}) {
		t.Fatalf("tag=eng members = %v, want [%s]", got, mac.ID)
	}

	// Dynamic: subnet 10.2.0.0/24 -> only the server (IP in range).
	g4, _ := s.UpsertGroup(Group{TenantID: "acme", Alias: "prod-net", Dynamic: &MembershipRule{Subnet: "10.2.0.0/24"}})
	if got := s.ResolveGroupMembers("acme", g4.ID); !reflect.DeepEqual(got, []string{srv.ID}) {
		t.Fatalf("subnet members = %v, want [%s]", got, srv.ID)
	}

	// Static + dynamic union, deduped: static includes the server; dynamic platform=macos adds the mac.
	g5, _ := s.UpsertGroup(Group{TenantID: "acme", Alias: "mixed", StaticMembers: []string{srv.ID}, Dynamic: &MembershipRule{Platform: strptr("macos")}})
	if got := s.ResolveGroupMembers("acme", g5.ID); !reflect.DeepEqual(got, []string{mac.ID, srv.ID}) {
		t.Fatalf("static+dynamic members = %v, want sorted [%s %s]", got, mac.ID, srv.ID)
	}
}

func TestResolveGroupMembersAndedRule(t *testing.T) {
	s := NewStore()
	a, _ := s.UpsertEndpoint(Endpoint{ID: "a", TenantID: "acme", Alias: "a", Kind: KindSteeredDevice, Platform: "macos", Steered: true, Tags: []string{"eng"}})
	_, _ = s.UpsertEndpoint(Endpoint{ID: "b", TenantID: "acme", Alias: "b", Kind: KindSteeredDevice, Platform: "macos", Steered: true, Tags: []string{"finance"}})
	// platform=macos AND tag=eng -> only a (both conditions).
	g, _ := s.UpsertGroup(Group{TenantID: "acme", Alias: "eng-macs", Dynamic: &MembershipRule{Platform: strptr("macos"), Tag: "eng"}})
	if got := s.ResolveGroupMembers("acme", g.ID); !reflect.DeepEqual(got, []string{a.ID}) {
		t.Fatalf("ANDed rule members = %v, want [%s]", got, a.ID)
	}
}
