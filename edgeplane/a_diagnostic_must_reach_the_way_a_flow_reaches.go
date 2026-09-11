package edgeplane

import (
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tunnel"
)

// ★★★ THE DIAGNOSTIC SAID UNREACHABLE WHILE THE FLOW WAS REACHING (2026-09-03, measured on a three-region
// deployment from a steered Windows device, with the Console open beside it).
//
// "Test reachability" on a published private app answered:
//
//	Reachability: Connector tunnel not connected
//	Suggested action: The connector is registered but its tunnel is not connected. Check connector health
//	                  and heartbeat.
//
// while a device steered to that same region fetched the app through that same Edge:
//
//	curl http://10.60.1.221:8080/ -> HTTP 200, mux_in_bytes=482, 39ms
//
// Both connectors of the site were on the OSAKA door at the time (their logs show no tunnel event after
// 01:38:59, and the measurement was at 01:55:50), and the flow arrived on TOKYO-EAST. It worked because this
// package relays: an Edge that holds no tunnel for a connector reaches it over the peer-Edge link. The
// diagnostic did not — it asked its own tunnel manager and stopped.
//
// So the screen reported a failure for a path that works, about a product whose whole point is that a
// connector may live in another region. An operator following its "suggested action" would go and check a
// healthy connector's heartbeat.
//
// ★ THE FIX IS NOT A SECOND OPINION, IT IS THE SAME ONE. This is the resolution the data path itself uses,
// exported so a diagnostic cannot answer a different question from the flow it is diagnosing. Residency still
// denies before the mesh is consulted, exactly as for a real flow.
func ConnectorProbeSession(conn model.ConnectorRegistration, destination, localRegion string,
	allowedRegions []string, meshEligible func(host string) bool, tunnels ConnectorTunnelProvider,
	peerEdges PeerEdgeProvider) (*tunnel.Session, error) {
	return connectorEgressSessionFor(conn, destination, localRegion, allowedRegions, meshEligible, tunnels, peerEdges)
}

// ConnectorTunnelProvider is the exported name for what a caller outside this package can supply: a live
// connector tunnel lookup. *tunnel.Manager satisfies it.
type ConnectorTunnelProvider = connectorTunnelProvider
