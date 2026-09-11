package main

import (
	"net/netip"
	"testing"
)

// ★ THE GUARD FIRST, IN BOTH DIRECTIONS. Reading "no document" as "carry nothing" would stop a fleet
// steering; reading "IPv4 only" as "carry everything" leaves the defect this exists to fix.
func TestOnlyADeclaredFamilyIsCarried(t *testing.T) {
	v4 := netip.MustParseAddrPort("1.1.1.1:443")
	v6 := netip.MustParseAddrPort("[2606:4700:4700::1111]:443")
	// 4-in-6 is how a v4 destination often arrives from the capture layer; it must count as IPv4 or a
	// v4-only deployment would refuse its own traffic.
	v4in6 := netip.MustParseAddrPort("[::ffff:1.1.1.1]:443")

	carriedFamilies.Store(nil)
	for _, dst := range []netip.AddrPort{v4, v6, v4in6} {
		if !deploymentCarries(dst) {
			t.Fatalf("with no posture document %s was refused — silence must mean unchanged", dst)
		}
	}

	setCarriedFamilies([]string{"ipv4"})
	if !deploymentCarries(v4) || !deploymentCarries(v4in6) {
		t.Fatal("an IPv4-only deployment refused an IPv4 destination")
	}
	if deploymentCarries(v6) {
		t.Fatal("an IPv4-only deployment carried an IPv6 destination — the flow this exists to stop")
	}

	setCarriedFamilies([]string{"ipv4", "ipv6"})
	if !deploymentCarries(v6) {
		t.Fatal("a dual-stack deployment refused IPv6")
	}

	// A document that names neither is one we do not understand, not an instruction to stop.
	setCarriedFamilies([]string{"quic-only"})
	if !deploymentCarries(v6) || !deploymentCarries(v4) {
		t.Fatal("an unrecognised family list stopped this agent steering")
	}
	// Same for an empty list.
	setCarriedFamilies(nil)
	if !deploymentCarries(v6) {
		t.Fatal("an empty family list stopped this agent steering")
	}
	carriedFamilies.Store(nil)
}
