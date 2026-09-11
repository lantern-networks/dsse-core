package edgeplane

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/model"
	swg "github.com/lantern-networks/dsse-core/swg"
	"github.com/lantern-networks/dsse-core/tunnel"
)

// ConnectorResolveFunc resolves which live connector serves a destination for a
// tenant. The composition root binds it to its connector registry (+ route
// governance); edgeplane never sees the registry itself.
type ConnectorResolveFunc func(ctx context.Context, tenantID, destination, namespace string) (model.ConnectorRegistration, bool, error)

// ConnectorCandidatesFunc returns EVERY connector that fronts a destination, most specific first.
//
// ★★★ A SITE HOLDS MORE THAN ONE CONNECTOR ON PURPOSE (the operator's reminder, 2026-08-26). Route bindings
// are authored on the SITE, so an HA pair fronts the same names. Resolving to one of them and stopping sends
// every flow to the same member, and fails outright when that member is the one this Edge cannot reach — no
// tunnel here, no mesh link to its region — while its partner sits live holding the identical route. Which
// member is reachable is knowable only HERE, in the dialer, so the route layer offers candidates and this
// takes the first that answers.
type ConnectorCandidatesFunc func(ctx context.Context, tenantID, destination, namespace string) ([]model.ConnectorRegistration, error)

// connectorTunnelProvider is the slice of *tunnel.Manager the connector egress dialer needs: look up a LIVE
// connector tunnel session by connector id. *tunnel.Manager satisfies it.
type connectorTunnelProvider interface {
	Get(connectorID string) (*tunnel.Session, bool)
}

// PeerEdgeProvider looks up the authenticated inter-region link to a sibling Edge in another region, used for
// the MESH path : a mesh-eligible flow is relayed Y->X over this link, and X's Edge bridges it into its
// local connector. Empty/nil until the multi-region fabric is up, so mesh fails closed by default.
type PeerEdgeProvider interface {
	PeerEdgeFor(region string) (*tunnel.Session, bool)
}

// ConnectorEgressDialer makes the steered bypass-egress chokepoint connector-aware. Before dialing a steered
// flow's destination directly, it consults the connector ROUTE layer (reachable_routes): if a LIVE connector
// fronts the destination by FQDN, the flow egresses THROUGH that connector's tunnel — the Edge has no direct
// route to a private destination. Every flow whose destination matches NO connector route falls back to the
// direct dialer, byte-identical to today (self-gating: with no reachable_routes configured the resolver never
// matches). This is the reachability decision only; policy still authorizes the flow upstream.
// ResidencyResolver returns the regions a tenant is allowed to occupy (its residency boundary), or nil/empty for
// an unpinned tenant (no restriction). *adminTenantModelStore-backed in production; a stub in tests.
type ResidencyResolver func(tenantID string) []string

type ConnectorEgressDialer struct {
	ResolveConnector ConnectorResolveFunc
	Tunnels          connectorTunnelProvider
	TenantID         string
	LocalRegion      string                 // this edge's region; a connector in another region is not served from here
	Residency        ResidencyResolver      // the flow tenant's allowed regions; nil = no residency restriction
	PeerEdges        PeerEdgeProvider       // inter-region links for the MESH path; nil = mesh fails closed (no fabric)
	MeshEligible     func(host string) bool // whether a destination opted into inter-region mesh; nil = never (hairpin default)
	// ListConnectors offers EVERY connector fronting a destination, most specific first. nil keeps the
	// single-answer behaviour. See ConnectorCandidatesFunc: a site's HA pair fronts the same names.
	ListConnectors ConnectorCandidatesFunc
	Direct         NetworkExtensionRuntimeCopyTCPDialer
}

// connectorRegionForDecision is the region the reach decision actually uses: where the deployment last SAW
// this connector, falling back to where it registered.
//
// ★★★ THE LINE HAS TO NAME THE REGION THE DECISION USED (2026-08-26, measured). These log lines exist so a
// refused or relayed flow says why, and both of them printed the REGISTERED region while the decision was
// made on the reported one. A real failover therefore produced "connector_region=region-b this_region=region-b"
// on a node that had correctly relayed the flow to region-a — a line that reads like the bug it was proving
// fixed. A decision that reports a different input than it used is worse than no line at all.
func connectorRegionForDecision(conn model.ConnectorRegistration) string {
	if reported := strings.TrimSpace(conn.AttachedRegionID); reported != "" {
		return reported
	}
	return strings.TrimSpace(conn.EdgeRegionID)
}

// connectorRegionForLog names the region the decision used, and says where the connector registered when that
// is somewhere else — the difference is the fact a reader needs, not a detail to leave out.
func ConnectorRegionForLog(conn model.ConnectorRegistration) string {
	using := connectorRegionForDecision(conn)
	registered := strings.TrimSpace(conn.EdgeRegionID)
	if registered == "" || strings.EqualFold(registered, using) {
		return using
	}
	return using + " (registered in " + registered + ")"
}

// connectorEgressSession picks the tunnel session a fronted flow egresses over, applying the region reach
// decision : LOCAL -> the connector's own tunnel; MESH -> the connector-region peer-Edge link (the flow is
// relayed Y->X and X bridges it into its local connector); HAIRPIN -> fail closed (hairpin is the agent's
// steering decision, not an Edge data path); OUT-OF-BOUNDARY -> residency denial.
func (d ConnectorEgressDialer) connectorEgressSession(conn model.ConnectorRegistration, destination string, allowedRegions []string) (*tunnel.Session, error) {
	return connectorEgressSessionFor(conn, destination, d.LocalRegion, allowedRegions, d.MeshEligible, d.Tunnels, d.PeerEdges)
}

// connectorEgressSessionFor applies the region reach decision  and returns the tunnel session the flow
// egresses over. It is shared by BOTH egress paths — the bypass dialer and the intercept DialContext — so mesh /
// hairpin / residency behave identically whether the flow is bypassed or decrypted. LOCAL -> the connector's own
// tunnel; MESH -> the connector-region peer-Edge link; HAIRPIN -> fail closed (a steering decision, not an Edge
// data path); OUT-OF-BOUNDARY -> residency denial.
func connectorEgressSessionFor(conn model.ConnectorRegistration, destination, localRegion string, allowedRegions []string, meshEligible func(host string) bool, tunnels connectorTunnelProvider, peerEdges PeerEdgeProvider) (*tunnel.Session, error) {
	mesh := meshEligible != nil && meshEligible(destination)
	// ★★★ A DESTINATION THE ROUTE LAYER ALREADY SENDS TO A CONNECTOR DOES NOT HAVE TO BE LISTED AGAIN
	// (2026-09-01, measured on a three-region deployment with a customer's connector in its own VPC).
	//
	// Which of MESH and HAIRPIN applies was decided solely by -mesh-eligible-hosts, and NOTHING PRODUCES THAT
	// LIST — so on every multi-region deployment this installer has built, every connector-fronted destination
	// was hairpin. A device that failed over to another region lost its private access, silently: measured
	// from both platforms independently as "Empty reply from server", with the request bytes going up, zero
	// coming back, and the reason only ever in the EDGE's log:
	//
	//	connector_unreachable host="10.60.1.176" candidates=1 this_region="tokyo-east":
	//	connector conn-… is in region "osaka"; cross-region reach (hairpin) is a steering decision
	//
	// ★ AND LISTING THEM WOULD RESTATE WHAT THIS FUNCTION ALREADY HOLDS. The eligible-hosts list is hostnames
	// matched by suffix; a connector fronts SUBNETS, authored as Named Networks and bound to a Site. Keeping a
	// second list in a different vocabulary in step with the first is bookkeeping whose failure is invisible
	// until somebody fails over. Reaching here at all means the route layer chose this connector for this
	// destination — that IS the opt-in.
	//
	// ★★ HAIRPIN REMAINS FOR THE CASE IT DESCRIBES: no mesh link to that region. "This deployment has no mesh"
	// then still refuses, by name, and the operator is told which region. What is removed is the state where a
	// deployment HAS a link, the flow is allowed to cross, and it is refused anyway for want of a list.
	//
	// ★★★ RESIDENCY IS UNTOUCHED. ResolveConnectorReach denies an out-of-boundary region before it asks about
	// the mesh at all, so an organization pinned away from the connector's region is refused exactly as
	// before — this only chooses between MESH and HAIRPIN inside a boundary that already permits both.
	if !mesh && peerEdges != nil {
		if _, live := peerEdges.PeerEdgeFor(connectorRegionForDecision(conn)); live {
			mesh = true
		}
	}
	// ★★★ A LIVE TUNNEL HERE IS THE CONNECTOR, HERE — WHATEVER THE CATALOG SAYS (2026-08-26, measured on the
	// deployment the installer generates, one day after connector region failover was implemented).
	//
	// The catalog's region is what the connector DECLARED when it first registered. Give a connector more than
	// one door and that stops being where it is: when its home region goes away it fails over to another, and
	// the deployment's map does not move with it. Every Edge then routes to the region the connector LEFT — the
	// far side answers "fronts this destination but has no live tunnel" and the flow dies, while the connector
	// sits healthy one hop away holding the tunnel. Failover kept the connector alive and made everything behind
	// it unreachable, which is worse than not failing over at all, because both sides report themselves well.
	//
	// This node cannot fix the map, but it never needs the map for its OWN region: holding the tunnel IS the
	// answer to "is this connector local". So a live local session substitutes THIS region into the reach
	// decision, and a connector that moved here is served exactly as one that registered here.
	//
	// ★ THE SUBSTITUTION NEVER WIDENS RESIDENCY. A local region matches itself, so ResolveConnectorReach answers
	// Local without consulting the boundary — that is its documented single-region-safe rule. Substituting into
	// it would therefore turn a refusal into a serve for a tenant pinned away from this region, which is the one
	// direction this must not move: residency beats availability. So when the tenant is pinned and this region
	// is not in the boundary, the recorded region stands and the flow fails closed exactly as before.
	// Where the deployment last SAW this connector beats where the connector said it would be. The reported
	// region is written by whichever node terminated its tunnel; the registered one is what it declared at
	// enrolment and never moves again.
	region := connectorRegionForDecision(conn)
	localSession, heldHere := (*tunnel.Session)(nil), false
	if tunnels != nil {
		localSession, heldHere = tunnels.Get(conn.ID)
	}
	if heldHere && (len(allowedRegions) == 0 || ContainsRegionFold(allowedRegions, localRegion)) {
		region = localRegion
	}
	switch dec := ResolveConnectorReach(region, localRegion, allowedRegions, mesh); dec.Disposition {
	case ReachLocal:
		if heldHere {
			return localSession, nil
		}
		// ★★★ THE CONNECTOR IS IN THIS REGION AND ON A SIBLING NODE, NOT THIS ONE (2026-09-01, measured on a
		// site with a connector pair).
		//
		// A connector must hold a tunnel on EVERY Edge node of its region, because a flow can arrive on any of
		// them. It cannot: the region's agent door balances `source` with a consistent hash — deliberately,
		// because a device's live sockets must stay on one node — and a connector dials from one address, so
		// it lands on the same node every time, for ever. Its own search says so and then has nowhere to go:
		//
		//	now on only 1 of the 2 Edge node(s) the deployment knows of here — a flow arriving on one of
		//	the others cannot reach anything behind this connector
		//
		// Measured: half the flows to a private asset were served and half answered "fronts destination but
		// has no live tunnel", decided by which node the device's own source address hashed to.
		//
		// ★ THE ANSWER IS THE ONE THIS FILE ALREADY USES ACROSS REGIONS. An Edge that cannot serve a connector
		// itself relays to the Edge that can — the same peer-Edge link, applied to a sibling in this region,
		// where nodes ARE individually addressable (they are named to each other in the door's own backend).
		// Nothing about device stickiness changes, and no new name has to appear in any certificate.
		if peerEdges != nil {
			if s, ok := peerEdges.PeerEdgeFor(localRegion); ok {
				return s, nil
			}
		}
		return nil, fmt.Errorf("connector %s fronts destination but has no live tunnel on this node, and this "+
			"node has no link to a sibling in %q that might hold one", conn.ID, localRegion)
	case ReachMesh:
		if peerEdges == nil {
			return nil, fmt.Errorf("connector %s is in region %q; no mesh link configured from this edge", conn.ID, dec.Region)
		}
		s, ok := peerEdges.PeerEdgeFor(dec.Region)
		if !ok {
			return nil, fmt.Errorf("connector %s is in region %q with no live mesh link from this edge", conn.ID, dec.Region)
		}
		return s, nil
	case ReachDenyOutOfBoundary:
		// ★ RESIDENCY IS NEVER ASKED AROUND. The sibling below is asked before REFUSING for want of a route;
		// it is not asked when the refusal is a boundary the organization drew.
		return nil, fmt.Errorf("connector %s is in region %q outside the tenant's residency boundary", conn.ID, dec.Region)
	default: // ReachHairpin
		// ★★★ ASK THE SIBLING BEFORE REFUSING, BECAUSE IT IS THE ONLY PARTY THAT KNOWS (2026-09-02, measured:
		// a customer's estate refused for two minutes by one Edge while the connector was attached to the
		// Edge beside it).
		//
		// The node that terminates a connector's tunnel is the only one that knows where that connector now
		// is; it records the change and reports it to the control plane, and its SIBLINGS learn on the next
		// config bundle. That is a two-minute window on this deployment, and in it:
		//
		//	edge-a: connector_attached_region_changed connector=… region=tokyo-east
		//	edge-b: connector … is in region "osaka"; cross-region reach (hairpin) … not served by this edge
		//
		// Both true, two minutes apart, about a connector attached to the machine they share. The catalogue is
		// the slow copy; a live tunnel is the fact. This node cannot see a sibling's tunnels, but it can hand
		// the flow to the sibling and let the one that knows answer.
		//
		// ★ IT CANNOT BE WORSE THAN REFUSING. This branch was already a refusal; the sibling either carries
		// the flow or fails, and the failure is the same one, one hop later.
		if peerEdges != nil {
			if s, ok := peerEdges.PeerEdgeFor(localRegion); ok {
				return s, nil
			}
		}
		return nil, fmt.Errorf("connector %s is in region %q; cross-region reach (hairpin) is a steering decision, not served by this edge", conn.ID, dec.Region)
	}
}

func (r ResidencyResolver) allowedRegions(tenantID string) []string {
	if r == nil {
		return nil
	}
	return r(tenantID)
}

func (d ConnectorEgressDialer) OpenTCPConnection(ctx context.Context, route NetworkExtensionRuntimeCopyTCPRoute) (io.ReadWriteCloser, error) {
	direct := d.Direct
	if direct == nil {
		direct = NetworkExtensionRuntimeCopyNetDialer{}
	}
	if d.ResolveConnector == nil || d.Tunnels == nil {
		return direct.OpenTCPConnection(ctx, route)
	}
	tenantID, tenantFrom := route.TenantID, "the flow"
	if tenantID == "" {
		// ★ WHERE THIS VALUE CAME FROM IS THE WHOLE QUESTION (2026-09-01). A connector is matched WITHIN an
		// organization, so a lookup with the wrong one finds nothing and the flow is dialled directly — and
		// "tenant_default" reads identically whether the flow brought it or this dialer fell back to what it
		// was configured with at startup. Two nodes gave different answers for one flow and nothing said why.
		tenantID, tenantFrom = d.TenantID, "this dialer's startup default (the flow carried none)"
	}
	// Names are unique across sites, so FQDN routing needs no namespace. route.SNI is the hostname even when the
	// client connected by IP literal; fall back to route.Host when there is no SNI.
	destination := strings.TrimSpace(route.SNI)
	if destination == "" {
		destination = strings.TrimSpace(route.Host)
	}
	conn, ok, err := d.ResolveConnector(ctx, tenantID, destination, "")
	if err != nil {
		// ★★★ "COULD NOT ASK" IS NOT "NO CONNECTOR FRONTS THIS" (2026-08-26). Both fell through to a direct
		// dial in silence, and for an INTERNAL destination a direct dial from an Edge reaches nothing — so the
		// flow died with a line naming a category and never a reason.
		log.Printf("connector_route_lookup_failed host=%q tenant=%q: %v — this flow is being dialled DIRECTLY, "+
			"which for an internal destination reaches nothing", destination, tenantID, err)
		return direct.OpenTCPConnection(ctx, route)
	}
	if !ok {
		// No connector fronts this destination (the common case today) -> direct dial, behavior unchanged.
		//
		// ★★★ EXCEPT FOR AN INTERNAL ADDRESS, WHERE SILENCE IS THE DEFECT (2026-09-01). A direct dial to a
		// private address is refused by the SSRF guard a moment later, with a message that names the guard and
		// not the reason. The reason is here — WHICH organization was asked, and about what name — and two
		// flows in the same second can differ only in that value. Without this line nothing tells them apart.
		if isInternalDestinationForLog(destination) {
			// ★ AND WHOSE FLOW IT IS. Two flows from what looked like one device carried different
			// organizations in the same second; without the device on the line there is no way to tell
			// whether that is one device answering twice or two devices, and those need different fixes.
			log.Printf("connector_route_not_found host=%q tenant=%q tenant_from=%q device=%q built_by=%q — no "+
				"connector in that organization fronts this name, so the flow is dialled DIRECTLY; for an "+
				"internal address that reaches nothing and the egress guard refuses it next",
				destination, tenantID, tenantFrom, route.DeviceIdentity, route.BuiltBy)
		}
		return direct.OpenTCPConnection(ctx, route)
	}
	// Pick the egress session by the region reach decision: the connector's own tunnel (local), the connector-
	// region peer-Edge link (mesh), or a fail-closed error (hairpin / out of boundary). A connector that fronts
	// the destination is never direct-dialed.
	//
	// ★★★ AND EVERY MEMBER OF THE SITE IS TRIED (the operator's reminder, 2026-08-26). Route bindings are
	// authored on the SITE, so an HA pair fronts the same names; stopping at the first match hands every flow
	// to one member and fails outright when that member is the one this Edge cannot reach, while its partner
	// sits live holding the identical route.
	candidates := []model.ConnectorRegistration{conn}
	if d.ListConnectors != nil {
		if all, cerr := d.ListConnectors(ctx, tenantID, destination, ""); cerr == nil && len(all) > 0 {
			candidates = all
		}
	}
	// ★★★ A CANDIDATE IS TRIED TO THE POINT OF AN OPEN, NOT TO THE POINT OF A SESSION (2026-09-01, measured
	// on a connector pair after the sibling relay landed).
	//
	// Stopping one connector of a pair took the whole site down for as long as it was off. The loop below
	// picked the first candidate that yielded a SESSION and stopped there — and once an Edge that does not
	// hold a connector could relay to a sibling, a DEAD connector always yields one: the sibling link is up,
	// so the session exists, and the flow is handed to a node where nothing answers. The survivor was never
	// reached. Before the relay existed this worked by accident, because a dead connector produced an error
	// here instead of a session.
	//
	// "Every member of the site is tried" has to mean tried until one CARRIES the flow. So the open happens
	// inside the loop, and a candidate that cannot open is passed over like one that cannot be reached.
	var upstream net.Conn
	for _, candidate := range candidates {
		s, serr := d.connectorEgressSession(candidate, destination, d.Residency.allowedRegions(tenantID))
		if serr != nil {
			err = serr
			log.Printf("connector_candidate_unreachable host=%q connector=%q connector_region=%q this_region=%q: %v",
				destination, candidate.ID, ConnectorRegionForLog(candidate), d.LocalRegion, serr)
			continue
		}
		c, oerr := openConnectorTunnelTCPConn(ctx, s, destination, route.Port, tenantID)
		if oerr != nil {
			err = oerr
			log.Printf("connector_candidate_would_not_open host=%q connector=%q connector_region=%q this_region=%q: %v — "+
				"the flow could not open through this member, so the next member is tried",
				destination, candidate.ID, ConnectorRegionForLog(candidate), d.LocalRegion, oerr)
			// Retire an unresponsive tunnel so an abandoned Connector connection can
			// recover. An explicit backend refusal proves the Connector answered;
			// closing its shared tunnel would disconnect unrelated applications.
			// Caller cancellation also says nothing about tunnel health.
			if errors.Is(oerr, tunnel.ErrTCPOpenTimeout) {
				_ = s.Close()
				log.Printf("connector_session_ended connector=%q this_region=%q — it did not answer an open, so "+
					"this node stopped holding it; the connector may dial again", candidate.ID, d.LocalRegion)
			}
			continue
		}
		upstream, conn, err = c, candidate, nil
		break
	}
	if upstream != nil {
		log.Printf("connector_route_chosen host=%q connector=%q connector_region=%q this_region=%q",
			destination, conn.ID, ConnectorRegionForLog(conn), d.LocalRegion)
		return upstream, nil
	}
	// ★ FAIL-CLOSED, AND SAID. A destination DID resolve to a connector and the deployment could not reach any
	// of the ones fronting it: no tunnel here, no mesh link to their regions, nothing answering behind one, or
	// outside the organization's boundary. Four causes, four different fixes, and without this line the flow
	// simply ends.
	log.Printf("connector_unreachable host=%q candidates=%d this_region=%q: %v",
		destination, len(candidates), d.LocalRegion, err)
	return nil, err
}

// openConnectorTunnelTCPConn opens a raw TCP stream to host:port THROUGH a connector tunnel and adapts it to an
// io.ReadWriteCloser the steered copy loop can use like an ordinary dialed conn. It reuses the exact relay
// helpers the clientless CONNECT path uses (CopyEdgeTCPClientToTunnel / CopyEdgeTCPTunnelToClient) by bridging
// an in-memory net.Pipe: the caller drives one end, the relay goroutines bridge the other end to the tunnel.
func openConnectorTunnelTCPConn(ctx context.Context, session *tunnel.Session, host string, port int, tenantID string) (net.Conn, error) {
	// The tunnel open-frame contract requires a non-empty application_id. A steered bypass flow is destination-
	// driven, not app-scoped, so the destination host stands in as the application id; the connector dials
	// host:port regardless. (Connector-side authorization BY route — host:port instead of app id — is a
	// follow-on connector change.)
	target := EdgeTCPConnectTarget{ApplicationID: host, Host: host, Port: port}
	// Steered East-West flows are interactive (ssh/rdp) — use the generous idle/lifetime so a session isn't torn
	// down at a prompt (the 30s default connector-stream idle dropped ssh after ~30s).
	openFrame, err := EdgeTCPOpenFrameForTarget(randomEdgeID("req_tcp_", time.Now().UTC()), target, InteractiveEastWestEdgeTCPConnectLimits())
	if err != nil {
		return nil, err
	}
	// ★ WHOSE FLOW THIS IS, so a relay at the far end can look the connector up in the right organization. On
	// the connector's own tunnel it is redundant and harmless; on a peer-Edge link it is the whole difference
	// between finding the connector and dialling the destination directly into the egress guard.
	openFrame.TenantID = strings.TrimSpace(tenantID)
	streamCh, cleanup, _, err := session.OpenTCP(ctx, openFrame)
	if err != nil {
		return nil, err
	}
	edgeSide, callerSide := net.Pipe()
	// BOTH bridge goroutines run cleanup (it is idempotent), because either side can be the one that ends the
	// stream and each must release the other. The connector replies NOTHING to an edge-sent tcp_close, so when
	// the caller closes first (an idle pooled conn reaped, an interactive client disconnecting) the ONLY thing
	// that ends the tunnel->client goroutine's channel receive is cleanup closing the stream channel; without
	// the client->tunnel side calling it, that goroutine and the stream registration leaked until session
	// teardown.
	go func() {
		_ = CopyEdgeTCPClientToTunnel(ctx, session, openFrame.RequestID, edgeSide)
		edgeSide.Close()
		cleanup()
	}()
	go func() {
		_ = CopyEdgeTCPTunnelToClient(streamCh, edgeSide)
		edgeSide.Close()
		cleanup()
	}()
	return callerSide, nil
}

// ConnectorEgressDialContext is the connector-aware DialContext for the INTERCEPT (decrypt-all) egress path: the
// Edge terminates TLS and re-originates the request to the upstream via an http.Client, and this dialer routes
// that upstream connection THROUGH the fronting connector's tunnel when a live connector fronts the host (the
// Edge then runs TLS to the backend over the connector-relayed raw TCP). Every host fronted by no connector
// route dials via `base`, byte-identical to today. The intercept path is the counterpart of ConnectorEgressDialer
// (the bypass path); together they make BOTH steered egress paths connector-aware.
func ConnectorEgressDialContext(base func(ctx context.Context, network, addr string) (net.Conn, error), resolveConnector ConnectorResolveFunc, tunnels connectorTunnelProvider, tenantID, localRegion string, residency ResidencyResolver, peerEdges PeerEdgeProvider, meshEligible func(host string) bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return ConnectorEgressDialContextWithCandidates(base, resolveConnector, nil, tunnels, tenantID, localRegion, residency, peerEdges, meshEligible)
}

// ConnectorEgressDialContextWithCandidates is ConnectorEgressDialContext that tries every connector fronting
// the destination. See ConnectorCandidatesFunc.
func ConnectorEgressDialContextWithCandidates(base func(ctx context.Context, network, addr string) (net.Conn, error), resolveConnector ConnectorResolveFunc, listCandidates ConnectorCandidatesFunc, tunnels connectorTunnelProvider, tenantID, localRegion string, residency ResidencyResolver, peerEdges PeerEdgeProvider, meshEligible func(host string) bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if base == nil {
		base = (&net.Dialer{Control: swg.EgressControl}).DialContext
	}
	// SWG forward-proxy SSRF guard on the direct-egress path (caller-controlled destination). Wrapped
	// UNCONDITIONALLY: production callers pass a non-nil base dialer, so a guard only on the nil-base default
	// is dead code and connector-less destinations dial internal/metadata addresses unchecked. The wrapper
	// checks the actual connected peer address (so DNS rebinding is caught) and closes before any bytes are
	// sent. No-op in lab.
	base = swg.GuardDialContext(base)
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if resolveConnector == nil || tunnels == nil {
			return base(ctx, network, addr)
		}
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return base(ctx, network, addr)
		}
		// The flow's own organization when it brought one — see WithFlowTenant. Falling back to the
		// configured value keeps a single-tenant deployment byte-identical.
		flowTenant := tenantID
		if t := FlowTenantFromContext(ctx); t != "" {
			flowTenant = t
		}
		conn, ok, err := resolveConnector(ctx, flowTenant, host, "")
		if err != nil {
			// ★★★ "COULD NOT ASK" IS NOT "NO CONNECTOR FRONTS THIS" (2026-08-26). Both fell through to a
			// direct dial in silence, and for an INTERNAL destination a direct dial from an Edge is a
			// connection to nothing — so the flow failed with a line naming a category and never the reason.
			// A destination that a connector fronts, dialled directly, is the exact shape of "the private app
			// is unreachable and every screen looks correct".
			log.Printf("connector_route_lookup_failed host=%q tenant=%q: %v — this flow is being dialled "+
				"DIRECTLY, which for an internal destination reaches nothing", host, tenantID, err)
			return base(ctx, network, addr)
		}
		if !ok {
			// The ordinary case for the public web, and far too frequent to log per flow. Left silent on
			// purpose; the line above covers the case that is actually a fault.
			return base(ctx, network, addr)
		}
		// Same region reach decision as the bypass path: local connector tunnel, mesh peer-Edge link, or a
		// fail-closed error (hairpin / out of boundary).
		//
		// ★ EVERY MEMBER OF THE SITE IS TRIED, most specific first. The one this Edge can reach is not
		// knowable to the route layer, and an HA pair exists precisely so that one of them being unreachable
		// is not an outage.
		candidates := []model.ConnectorRegistration{conn}
		if listCandidates != nil {
			if all, cerr := listCandidates(ctx, tenantID, host, ""); cerr == nil && len(all) > 0 {
				candidates = all
			}
		}
		var session *tunnel.Session
		var lastErr error
		for _, candidate := range candidates {
			s, serr := connectorEgressSessionFor(candidate, host, localRegion, residency.allowedRegions(tenantID), meshEligible, tunnels, peerEdges)
			if serr == nil {
				session, conn, lastErr = s, candidate, nil
				break
			}
			lastErr = serr
			if len(candidates) > 1 {
				log.Printf("connector_candidate_unreachable host=%q connector=%q connector_region=%q: %v — "+
					"trying the next connector that fronts this name", host, candidate.ID, ConnectorRegionForLog(candidate), serr)
			}
		}
		err = lastErr
		if err != nil {
			// ★ NAMED, BECAUSE THIS IS THE FAIL-CLOSED ONE. A destination DID resolve to a connector and the
			// deployment could not reach it — no local tunnel, no mesh link, or outside the organization's
			// region boundary. Without this the flow simply ends, and the three causes need different fixes.
			log.Printf("connector_unreachable host=%q connector=%q connector_region=%q this_region=%q: %v",
				host, conn.ID, ConnectorRegionForLog(conn), localRegion, err)
			return nil, err
		}
		log.Printf("connector_route_chosen host=%q connector=%q connector_region=%q this_region=%q",
			host, conn.ID, ConnectorRegionForLog(conn), localRegion)
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, err
		}
		return openConnectorTunnelTCPConn(ctx, session, host, port, flowTenant)
	}
}

// ConnectorAwareProxyClient returns a clone of `base` whose transport routes upstream connections through the
// connector route layer (ConnectorEgressDialContext). It clones the transport so the shared proxy client is not
// mutated; a non-*http.Transport base falls back to a clone of http.DefaultTransport. Self-gating: with no
// connector fronting a host, the dial is the base transport's dial, unchanged.
func ConnectorAwareProxyClient(base *http.Client, resolveConnector ConnectorResolveFunc, tunnels connectorTunnelProvider, tenantID, localRegion string, residency ResidencyResolver, peerEdges PeerEdgeProvider, meshEligible func(host string) bool) *http.Client {
	if base == nil {
		base = http.DefaultClient
	}
	clientCopy := *base
	var transport *http.Transport
	if t, ok := base.Transport.(*http.Transport); ok {
		transport = t.Clone()
	} else {
		transport = http.DefaultTransport.(*http.Transport).Clone()
	}
	transport.DialContext = ConnectorEgressDialContext(transport.DialContext, resolveConnector, tunnels, tenantID, localRegion, residency, peerEdges, meshEligible)
	clientCopy.Transport = transport
	return &clientCopy
}

// isInternalDestinationForLog reports whether a destination is one an Edge cannot usefully dial itself — a
// private, loopback or link-local address. Used only to decide whether a not-found connector lookup is worth
// a line: for the public web it is the ordinary case and far too frequent to log.
func isInternalDestinationForLog(destination string) bool {
	ip := net.ParseIP(strings.TrimSpace(destination))
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}
