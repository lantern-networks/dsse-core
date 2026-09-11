package assetcatalog

import (
	"reflect"
	"testing"
)

func TestResolvePlatforms(t *testing.T) {
	s := NewStore()
	mac, _ := s.UpsertEndpoint(Endpoint{TenantID: "acme", Alias: "alice-mac", Kind: KindSteeredDevice, Platform: "macos", Steered: true})
	win, _ := s.UpsertEndpoint(Endpoint{TenantID: "acme", Alias: "bob-win", Kind: KindSteeredDevice, Platform: "windows", Steered: true})
	net, _ := s.UpsertEndpoint(Endpoint{TenantID: "acme", Alias: "prod-db", Kind: KindNetwork, Address: "10.0.0.1"})
	// A dynamic group of all macs.
	macsGroup, _ := s.UpsertGroup(Group{TenantID: "acme", Alias: "macs", Dynamic: &MembershipRule{Platform: strptr("macos")}})

	// A single windows endpoint -> windows only, no mac aliases.
	plats, macs := s.ResolvePlatforms("acme", []string{win.ID})
	if !reflect.DeepEqual(plats, []string{"windows"}) || len(macs) != 0 {
		t.Fatalf("windows endpoint = (%v, %v), want ([windows], [])", plats, macs)
	}

	// The macs group expands to the mac endpoint.
	plats, macs = s.ResolvePlatforms("acme", []string{macsGroup.ID})
	if !reflect.DeepEqual(plats, []string{"macos"}) || !reflect.DeepEqual(macs, []string{"alice-mac"}) {
		t.Fatalf("macs group = (%v, %v), want ([macos], [alice-mac])", plats, macs)
	}

	// Mixed: a windows endpoint + the macs group -> both platforms, mac alias named.
	plats, macs = s.ResolvePlatforms("acme", []string{win.ID, macsGroup.ID})
	if !reflect.DeepEqual(plats, []string{"macos", "windows"}) || !reflect.DeepEqual(macs, []string{"alice-mac"}) {
		t.Fatalf("mixed = (%v, %v), want ([macos windows], [alice-mac])", plats, macs)
	}

	// A network endpoint contributes no platform; an unknown id is ignored.
	plats, macs = s.ResolvePlatforms("acme", []string{net.ID, "ep-nonexistent"})
	if len(plats) != 0 || len(macs) != 0 {
		t.Fatalf("network+unknown = (%v, %v), want empty", plats, macs)
	}

	_ = mac
}

func TestEndpointAddresses(t *testing.T) {
	s := NewStore()
	a, _ := s.UpsertEndpoint(Endpoint{TenantID: "acme", Alias: "db", Kind: KindNetwork, Address: "10.0.0.1"})
	b, _ := s.UpsertEndpoint(Endpoint{TenantID: "acme", Alias: "cdn", Kind: KindNetwork, Address: "cdn.example.com"})
	s.UpsertEndpoint(Endpoint{TenantID: "acme", Alias: "alice-mac", Kind: KindSteeredDevice, Platform: "macos", Steered: true})
	grp, _ := s.UpsertGroup(Group{TenantID: "acme", Alias: "nets", StaticMembers: []string{a.ID, b.ID}})

	// A group of two network endpoints -> both addresses, sorted.
	if got := s.EndpointAddresses("acme", []string{grp.ID}); !reflect.DeepEqual(got, []string{"10.0.0.1", "cdn.example.com"}) {
		t.Fatalf("group addresses = %v, want both", got)
	}
	// A single network endpoint id.
	if got := s.EndpointAddresses("acme", []string{a.ID}); !reflect.DeepEqual(got, []string{"10.0.0.1"}) {
		t.Fatalf("endpoint address = %v", got)
	}
	// Steered devices (no address) and unknown ids contribute nothing.
	if got := s.EndpointAddresses("acme", []string{"ep-missing"}); len(got) != 0 {
		t.Fatalf("unknown id = %v, want empty", got)
	}
}

func TestDestinationTokensAndServiceProtocols(t *testing.T) {
	s := NewStore()
	net, _ := s.UpsertEndpoint(Endpoint{TenantID: "acme", Alias: "prod-db", Kind: KindNetwork, Address: "db.internal"})
	dev, _ := s.UpsertEndpoint(Endpoint{TenantID: "acme", Alias: "bob-win", Kind: KindSteeredDevice, Platform: "windows", Steered: true})
	grp, _ := s.UpsertGroup(Group{TenantID: "acme", Alias: "targets", StaticMembers: []string{net.ID, dev.ID}})
	svc, _ := s.UpsertService(Service{TenantID: "acme", Alias: "SMB", Ports: []PortProto{{Protocol: "tcp", Port: 445}}})

	// Network endpoint -> address token; steered device (no address) -> alias token; group -> union.
	if got := s.DestinationTokens("acme", []string{grp.ID}); !reflect.DeepEqual(got, []string{"bob-win", "db.internal"}) {
		t.Fatalf("group destination tokens = %v, want [bob-win db.internal]", got)
	}
	if got := s.DestinationTokens("acme", []string{net.ID}); !reflect.DeepEqual(got, []string{"db.internal"}) {
		t.Fatalf("network destination token = %v", got)
	}
	// Service alias lowercased is the protocol token; empty/unknown -> nil (any).
	if got := s.ServiceProtocols("acme", svc.ID); !reflect.DeepEqual(got, []string{"smb"}) {
		t.Fatalf("service protocols = %v, want [smb]", got)
	}
	if got := s.ServiceProtocols("acme", ""); got != nil {
		t.Fatalf("empty service = %v, want nil", got)
	}
}

func TestSourceDeviceTokens(t *testing.T) {
	s := NewStore()
	// Enrolled steered devices carry a device identity; a network endpoint does not.
	s.UpsertEndpoint(Endpoint{TenantID: "acme", Alias: "alice-mac", Kind: KindSteeredDevice, Platform: "macos", Steered: true, Identity: "dev-alice", Source: SourceEnrolled})
	s.UpsertEndpoint(Endpoint{TenantID: "acme", Alias: "bob-win", Kind: KindSteeredDevice, Platform: "windows", Steered: true, Identity: "dev-bob", Source: SourceEnrolled})
	net, _ := s.UpsertEndpoint(Endpoint{TenantID: "acme", Alias: "db", Kind: KindNetwork, Address: "db.internal"})
	grp, _ := s.UpsertGroup(Group{TenantID: "acme", Alias: "clients", Dynamic: &MembershipRule{Steered: boolptr(true)}})

	// A dynamic group of steered devices -> both device identities.
	if got := s.SourceDeviceTokens("acme", []string{grp.ID}); !reflect.DeepEqual(got, []string{"dev-alice", "dev-bob"}) {
		t.Fatalf("group source devices = %v, want [dev-alice dev-bob]", got)
	}
	// A network endpoint has no device identity.
	if got := s.SourceDeviceTokens("acme", []string{net.ID}); len(got) != 0 {
		t.Fatalf("network source devices = %v, want empty", got)
	}
}
