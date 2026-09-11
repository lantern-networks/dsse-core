package main

// recovering_the_name_is_not_a_property_of_inspection.go — when this Edge cannot egress the family a
// destination literal is written in, it reads the name out of the ClientHello and fetches by name instead.
//
// ★★★ THE DEVICE CHOSE THE FAMILY; THE EDGE IS THE ONE THAT HAS TO FETCH (the operator's framing, relayed by
// win-dev-1 in letter 107, 2026-08-26). The browser asked for a NAME. Its OS picked IPv6 because of the
// network the DEVICE is on. What comes out of this Edge depends on the network the EDGE is on, and those are
// two different networks:
//
//	device and Edge can both egress v6   ->  fetch over v6
//	either one cannot                    ->  fetch over v4
//
// The agent hands over an ADDRESS (OrigDst netip.AddrPort), not a name, so on the face of it there is nothing
// to re-resolve. But a TLS flow carries the name in its ClientHello, and this Edge already knows how to read
// it — it just only did so when TLS INTERCEPTION was configured, to decide intercept vs forward. Measured on
// the deployment this installer generates, with interception off:
//
//	dest [2606:4700:4700::1111]:443, no name          -> closed, 0 bytes  (correct: nothing to re-resolve)
//	dest [2606:4700:4700::1111]:443, sni one.one.one.one -> closed, 0 bytes, and the Edge's own error names
//	                                                        the v6 literal — the name was never looked at
//
// Which family to fetch on and whether to decrypt are different questions, and the answer to the first was
// wired behind the second. This is the same shape as the connector-aware dialer that was only assigned inside
// the interception branch, found on the same deployment the same day.
//
// ★ IT COSTS NOTHING ON THE HEALTHY PATH. The peek happens only when the destination is a literal in a family
// this Edge has no egress in — a flow that is otherwise closed with no bytes. Anywhere else, nothing is read
// and nothing is delayed.

import (
	"net"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/interception"
)

// steerCanEgressIPv6 is what this node can actually reach the internet by. A variable so the decision can be
// exercised on a host that HAS IPv6 egress — the case this exists for cannot otherwise be tested anywhere the
// build machine is dual-stack, and a check that skips itself proves nothing.
var steerCanEgressIPv6 = edgeplane.EdgeHasIPv6Egress

// steerNameRecoveryPeekTimeout bounds the wait for a client that may never send a ClientHello. A TLS client
// sends one immediately after CONNECT 200; a plaintext flow to an unreachable literal is already doomed, so
// the wait is short and the flow fails the way it would have anyway.
const steerNameRecoveryPeekTimeout = 3 * time.Second

// recoverTheDestinationName gives route a SNI when the destination is an unreachable literal and the client's
// first bytes carry a name. It returns the client conn to use afterwards — the peeked bytes are replayed
// through it, so the flow is untouched from the client's point of view.
func recoverTheDestinationName(clientConn net.Conn, route edgeplane.NetworkExtensionRuntimeCopyTCPRoute) (net.Conn, edgeplane.NetworkExtensionRuntimeCopyTCPRoute) {
	if route.SNI != "" || clientConn == nil {
		return clientConn, route
	}
	if _, unreachable := edgeplane.DialNetworkForEgress(steerCanEgressIPv6(), route.Host); !unreachable {
		return clientConn, route
	}
	// ★ RESTORE THE DEADLINE. This conn is bridged for the life of the flow afterwards; leaving a three-second
	// read deadline on it would close every long-lived session three seconds in.
	_ = clientConn.SetReadDeadline(time.Now().Add(steerNameRecoveryPeekTimeout))
	sni, buffered, err := interception.PeekClientHelloSNI(clientConn)
	_ = clientConn.SetReadDeadline(time.Time{})
	replay := net.Conn(&edgeplane.NetworkExtensionLabTLSPrefixedConn{Conn: clientConn, Prefix: buffered})
	if err != nil || sni == "" {
		logWarnf("steer_name_not_recoverable host=%s dst_port=%d — this node has no egress in that address "+
			"family and the flow carries no name to fetch by, so there is no reachable path to it (%v)",
			route.Host, route.Port, err)
		return replay, route
	}
	logInfof("steer_fetching_by_name host=%s dst_port=%d name=%s — this node has no egress in that address "+
		"family, and the flow named its destination, so it is fetched by name on the family this node does have",
		route.Host, route.Port, sni)
	route.SNI = sni
	return replay, route
}
