package main

// connector_reached_this_node.go — the Edge tells a connector WHICH node of the fleet it just reached.
//
// ★★★ A CONNECTOR ATTACHES TO ONE EDGE; EVERY EDGE ACCEPTS FLOWS FOR WHAT IT FRONTS (measured 2026-08-26 on
// the deployment the installer generates).
//
// A region's Edges sit behind one L4 front door and share one address, so a connector's tunnel lands on
// whichever node the door picks — and only that node can bridge a flow into it. The other nodes of the same
// fleet answer "fronts this destination but has no live tunnel". Measured on a two-node region: ten probes to
// a private destination, five served, five refused, alternating exactly with the door's leastconn rotation.
// Across regions it is worse than a coin flip: the mesh link is itself pinned to one node of the far fleet, so
// if that node is not the one holding the connector, EVERY relayed flow fails — measured 0 of 8.
//
// The connector cannot see this. It dialled one address, it got one tunnel, and both ends report health. So
// the Edge says the one thing the connector cannot work out for itself: the name of the node that answered.
// With that, a connector can keep dialling the same door until it holds a tunnel on every node behind it —
// which is what "the connector connects to the Edge FLEET, and is never bound to a single Edge" means in the
// data path, not just in who will authenticate it.

import (
	"net/http"
	"strconv"
	"strings"

	"sync/atomic"

	"github.com/lantern-networks/dsse-core/tunnel"
)

// connectorReachedNodeHeader carries this node's identity on the tunnel handshake's 101 response.
const connectorReachedNodeHeader = tunnel.EdgeNodeHeader

// siblingsRelayProbe answers "will the other Edge nodes of my region relay to me for a connector I hold?".
// Set once at start-up from the peer-Edge registry, and asked at handshake time because a link can be down.
var siblingsRelayProbe atomic.Value // func() bool

func setSiblingsRelayProbe(f func() bool) {
	if f != nil {
		siblingsRelayProbe.Store(f)
	}
}

func siblingsRelayNow() bool {
	if f, ok := siblingsRelayProbe.Load().(func() bool); ok && f != nil {
		return f()
	}
	return false
}

// connectorTunnelHandshakeHeaders is what this Edge adds to a connector tunnel's 101. Kept as a function so
// there is one place to add to when the fleet learns to advertise more about itself (its size, for one — the
// denominator a connector needs before it can claim to cover the fleet rather than merely to spread over it).
func connectorTunnelHandshakeHeaders(nodeID string, regionNodes int, siblingsRelay bool) http.Header {
	h := http.Header{}
	if nodeID != "" {
		h.Set(connectorReachedNodeHeader, nodeID)
	}
	// ★ ONLY WHEN IT IS KNOWN. A count of zero is this node not having been told yet, and sending it as a
	// denominator would let a connector conclude it covers a fleet of none.
	if regionNodes > 0 {
		h.Set(tunnel.EdgeFleetNodesHeader, strconv.Itoa(regionNodes))
	}
	// ★ SAID ONLY WHEN TRUE. Absent means "this node cannot promise that", which is what a connector should
	// assume of a deployment that has not told it — the warning is right in that case.
	if siblingsRelay {
		h.Set(tunnel.EdgeSiblingsRelayHeader, "true")
	}
	if len(h) == 0 {
		return nil
	}
	return h
}

// connectorAlreadyHoldsThisNode reports whether the dialling connector has declared, in the upgrade request,
// that it already holds a tunnel on THIS node.
//
// ★★★ REFUSING HERE IS THE WHOLE POINT, AND IT MUST HAPPEN BEFORE THE UPGRADE (measured 2026-08-26). The
// tunnel manager keeps ONE session per connector, replacing and closing the previous one. So a connector
// walking its fleet — dial, read the node name off the 101, hang up if it is a node already held — killed the
// very tunnel it was probing, every time, before it had read a byte. What should have been coverage became a
// permanent flap: connect, EOF, connect, EOF. Nothing registers until this has said no.
//
// ★ AN UNDECLARED CONNECTOR IS NEVER REFUSED. An older connector sends no declaration, and a connector that
// has just restarted declares nothing because it holds nothing. Both must connect normally.
func connectorAlreadyHoldsThisNode(r *http.Request, nodeID string) bool {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return false
	}
	for _, declared := range r.Header.Values(tunnel.ConnectorHoldsHeader) {
		for _, held := range strings.Split(declared, ",") {
			if strings.EqualFold(strings.TrimSpace(held), nodeID) {
				return true
			}
		}
	}
	return false
}
