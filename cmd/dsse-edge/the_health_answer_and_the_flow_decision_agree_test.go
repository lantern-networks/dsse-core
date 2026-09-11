package main

import (
	"net"
	"testing"

	"github.com/lantern-networks/dsse-core/edgeplane"
)

// ★★★ THE ANSWER THAT IS LOGGED AND THE ANSWER THAT MOVES PACKETS MUST BE THE SAME ONE (2026-08-30).
//
// This deployment logged `egress_address_family ipv4=true ipv6=true` — a real dial, from inside the Edge
// container, that succeeded — while every IPv6 destination was being re-fetched by name over IPv4, because the
// dialer answered the same question for itself by listing interface addresses. Behind NAT66 the container's
// only v6 address is a ULA, which counts as private, so the dialer called the node v6-less. Nothing was broken
// enough to log: the health answer said IPv6 was carried and the flows quietly were not.
//
// The test is deliberately at the CALL SITE. A unit test of either half passes today; what failed was that the
// measurement never reached the decision.
func TestTheMeasuredEgressFamilyReachesTheDialer(t *testing.T) {
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback on this machine; the measurement cannot be exercised here")
	}
	defer listener.Close()
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	// A node that can open an IPv6 socket must be dialled dual-stack, whatever its interface addresses say.
	measureAndPublishEgressFamilies("", listener.Addr().String())
	if !edgeplane.EdgeHasIPv6Egress() {
		t.Fatalf("the measurement reached IPv6 (%+v) and the dialer still reports no IPv6 egress — "+
			"the health answer and the flow decision have diverged again", egressFamilies.Load())
	}
	if network, unreachable := edgeplane.DialNetworkForEgress(edgeplane.EdgeHasIPv6Egress(), "example.com"); network != "tcp" || unreachable {
		t.Fatalf("egress network = (%q, %v), want (\"tcp\", false) on a node measured as IPv6-capable", network, unreachable)
	}

	// And the reverse, in the same run: a node that cannot must stop being called dual-stack. One direction
	// alone cannot tell an implementation that measures from one that always says yes.
	//
	// Port 1 rather than a just-closed ephemeral port: the first version closed a listener and reused its
	// address, and in a package that opens listeners constantly another test bound that port before the probe
	// reached it, so the "unreachable" dial connected.
	measureAndPublishEgressFamilies("", "[::1]:1")
	if edgeplane.EdgeHasIPv6Egress() {
		t.Fatalf("the measurement found no IPv6 egress (%+v) and the dialer still reports IPv6 egress",
			egressFamilies.Load())
	}
}
