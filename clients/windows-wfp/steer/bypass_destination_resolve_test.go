package main

import (
	"net"
	"net/netip"
	"testing"
)

func TestExplicitDestinationBypassPreservesAddressFamilyAndPort(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"192.0.2.10:22", "192.0.2.10:22"},
		{"[2001:db8::10]:22", "[2001:db8::10]:22"},
		{"192.0.2.10", "192.0.2.10:0"},
		{"2001:db8::10", "[2001:db8::10]:0"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			got := parseAddrPorts([]string{tc.input})
			if len(got) != 1 || got[0] != netip.MustParseAddrPort(tc.want) {
				t.Fatalf("signed destination %q became %v; want exactly %s", tc.input, got, tc.want)
			}
		})
	}
}

func TestDestinationBypassResolvesBothDNSFamiliesWithoutBroadeningPorts(t *testing.T) {
	lookup := func(host string) ([]net.IP, error) {
		if host != "dual.example" {
			t.Fatalf("unexpected lookup %q", host)
		}
		return []net.IP{net.ParseIP("2001:db8::10"), net.ParseIP("192.0.2.10"), net.ParseIP("192.0.2.10")}, nil
	}
	got := resolveBypassDestinations("dual.example:22", lookup)
	want := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.10:22"), netip.MustParseAddrPort("[2001:db8::10]:22")}
	if len(got) != len(want) {
		t.Fatalf("got %v; want both DNS families", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v; want %v", got, want)
		}
	}
}

func TestDestinationBypassRejectsInvalidPortAndUnsupportedScopedAddress(t *testing.T) {
	for _, input := range []string{"192.0.2.10:22junk", "[2001:db8::10]:0", "[2001:db8::10]:65536", "[fe80::1%ethernet]:22", ":22"} {
		if got := parseAddrPorts([]string{input}); len(got) != 0 {
			t.Errorf("%q produced bypass %v", input, got)
		}
	}
}
