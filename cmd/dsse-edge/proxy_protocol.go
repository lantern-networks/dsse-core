package main

import (
	"flag"
	"net"

	"github.com/lantern-networks/dsse-core/frontdoor"
)

// proxy_protocol.go — recovering the device's address from behind an L4 front door.
//
// ★★★ THE FRONT DOOR MUST BE L4, AND THAT COSTS THE SOURCE ADDRESS. A device's transport is mTLS and its
// identity comes from the verified client certificate, so a layer-7 load balancer that terminates TLS
// destroys the identity every decision rests on — what reaches the Edge is then "the balancer said so". The
// front door therefore passes TCP through untouched.
//
// The cost is that every connection arrives from the front door. The rate limiter's own flag says what that
// does: "so clients behind a LB don't all collapse to the LB's IP". Without something, every device shares
// one bucket, and one noisy device throttles the fleet.
//
// ★ X-Forwarded-For IS NOT AVAILABLE HERE. That is an HTTP header, and the transport plane is not HTTP. The
// PROXY protocol is the equivalent one layer down: the front door states the original address before the
// first byte of TLS, and the connection continues untouched.
//
// ★★★ AND IT IS ACCEPTED ONLY FROM DECLARED ADDRESSES. A listener that lets anyone announce their own source
// address is worse than one that loses it: an attacker would choose an address, and every per-address
// decision — rate limiting, and anything that follows it — would be theirs to set. Empty means the header is
// never read, which is the safe default and what a deployment without a front door wants.

// The listener, the header parser and the address list live in package frontdoor, which the Admin Console
// shares: it stands behind the same front door and reads the same header (review R2). These names keep this
// package's call sites and tests as they were.

const proxyProtocolV1MaxLine = frontdoor.ProxyProtocolV1MaxLine

func newProxyProtocolListener(ln net.Listener, trusted []*net.IPNet) net.Listener {
	return frontdoor.NewProxyProtocolListener(ln, trusted)
}

func proxyProtocolConn(conn net.Conn) (net.Conn, error) { return frontdoor.ProxyProtocolConn(conn) }

func parseProxyProtocolV1(line string) net.Addr { return frontdoor.ParseProxyProtocolV1(line) }

func parseTrustedFrontDoors(raw string) []*net.IPNet { return frontdoor.ParseTrustedNets(raw) }

// agentPlaneFrontDoors is the trusted set for the AGENT-FACING door of the main listener. It is a package
// variable for the same reason the node's own region id is: it is decided once at startup and read by a
// function whose signature already carries everything else about how to serve.
var agentPlaneFrontDoors []*net.IPNet

func setTrustedFrontDoors(nets []*net.IPNet) { agentPlaneFrontDoors = nets }

// wrapAgentPlaneListener reads the PROXY header on the door devices arrive at, and on no other.
//
// ★★★ WHICH DOOR THIS IS COST A WALK (2026-08-24, found by running it). The PROXY header was accepted on the
// secure transport listener only — and the generated deployment does not use it: devices enrol and steer on
// the MAIN listener's agent-facing door. So the front door sent a header nobody consumed, TLS read "PROXY
// TCP4 ..." as a ClientHello, and every device got EOF. The unit tests were green the whole time, because
// they exercised the parser and not the door the deployment actually opens.
//
// ★★ AND NOT THE ADMIN DOOR, DELIBERATELY. Nothing fronts the admin surface — it is answered per node,
// because per-node observation is what it is for. Accepting a PROXY header there would let anyone who can
// reach it name the address that lands in the audit log, which is the one place a wrong address is a lie
// rather than a degradation.
func wrapAgentPlaneListener(ln net.Listener, door string) net.Listener {
	if door != "agent-plane" {
		return ln
	}
	return newProxyProtocolListener(ln, agentPlaneFrontDoors)
}

// trustedFrontDoorsFlag names the front door(s) whose PROXY header this Edge believes.
//
// ★ IT LIVES HERE AND NOT IN main.go, because a ratchet says new flags do. The rule is worth keeping: a
// flag beside the code that reads it is a flag whose meaning can be checked without leaving the file.
var trustedFrontDoorsFlag = flag.String("trusted-front-doors", "", "comma-separated IPs or CIDRs of the L4 front door(s) in front of this region's Edges. A connection FROM one of these may state the device's original address with a PROXY protocol v1 header, and that address is what every per-address decision uses. Empty = no PROXY header is read from anyone (correct with no front door; never means 'trust anyone')")
