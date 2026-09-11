package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
	interception "github.com/lantern-networks/dsse-core/interception"
	"github.com/lantern-networks/dsse-core/model"
)

// steer: W3 generic steer-judgment path. Unlike the connector-app route (which needs a pre-registered
// application and authority == route Destination), this accepts a transparently-steered flow to an
// ARBITRARY original destination, applies policy (default-deny + east-west + tenant
// restriction) to that destination, and -- on allow -- the Edge dials the original destination directly
// (a policy-enforcing forward proxy). This is what lets a Windows steer-all agent send any outbound TCP
// flow to the Edge. See docs/handoff_windows_steering_agent_design.md (W3).

// steerServiceFamilyForPort maps a destination TCP port to a service family for the steer decision.
func steerServiceFamilyForPort(port int) string {
	switch port {
	case 443, 8443:
		return "https"
	case 80, 8080:
		return "http"
	case 22:
		return "ssh"
	case 3389:
		return "rdp"
	case 445, 139:
		return "smb"
	case 5985, 5986:
		return "winrm"
	case 135:
		return "wmi_rpc"
	case 5900:
		return "vnc"
	case 1433, 3306, 5432, 1521, 27017:
		return "database"
	default:
		return ""
	}
}

// steerInteractiveHalfCloseLinger bounds how long a HALF-CLOSED interactive East-West flow (an abandoned ssh whose
// client sent EOF) may sit silent before the Edge reclaims it. It is generous (unlike the browsing /8 linger)
// because a legitimate `ssh host "<long silent command>"` half-closes stdin and then waits on output — cutting it
// short would be the very complaint we are fixing. The full-duplex idle window stays UNLIMITED; this only governs a
// flow that has ALREADY half-closed (one direction EOF'd), which is the abandoned-client signal.
const steerInteractiveHalfCloseLinger = 30 * time.Minute

// steerInteractiveEastWestFamily reports whether a steered flow is an interactive East-West protocol that a user
// may hold open (and idle) for a long time — so it must not be torn down by an idle timer while both directions
// are open. Browsing (https/http) is excluded: it keeps the default idle + half-close linger.
func steerInteractiveEastWestFamily(family string) bool {
	switch family {
	case "ssh", "rdp", "smb", "winrm", "wmi_rpc", "vnc", "database":
		return true
	default:
		return false
	}
}

// steerDecisionRequest builds a minimal decision request for a steered flow to host:port. Identity /
// device / posture enrichment is a later slice; W3 decides on destination + port-derived service family.
func steerDecisionRequest(tenantID, host string, port int) model.DecisionRequest {
	return model.DecisionRequest{
		TenantID:        strings.TrimSpace(tenantID),
		ActorType:       "human",
		Destination:     strings.TrimSpace(host),
		DestinationPort: port,
		Protocol:        "tcp",
		ServiceFamily:   steerServiceFamilyForPort(port),
		// Mark generic steered flows (Windows steer-all agent's CONNECT /steer) distinctly from the
		// macOS NE path (steering_mode=network_extension), so the committed steer-plane allow policy
		// can target steered https precisely without over-matching NE flows. Additive: existing
		// policies that do not constrain steering_mode still match.
		SteeringMode: "steer",
	}
}

// InterceptAll — make every steered (allowed) outbound flow subject to the SAME Edge TLS interception
// engine the macOS NE decrypt-all path uses, instead of a blind pass-through tunnel. When the Edge is
// configured with a lab-TLS interception engine, an allowed TLS flow (443) is routed through it
// (decrypt-all + SNI-based decision + tenant-restriction header injection); everything else falls back to
// the transparent policy-enforcing forward proxy (/). This is the Edge half of "steer-all ->
// intercept-all": a Windows steer-all agent already sends every outbound TCP flow to CONNECT /steer; this
// makes the allowed https among them decrypted and content-inspected in the reference deployment.

// steerInterceptionUpstream opens the upstream for an ALLOWED steered flow through the interception dialer.
// For TLS (443) with an SNI-based dialer it peeks the ClientHello SNI first -- so the intercept/bypass
// decision is SNI-based and robust to connect-by-IP (Chrome/IPv6 resolve themselves, leaving route.Host an
// IP) -- and replays the peeked bytes via a prefixed conn. Returns the (possibly prefix-wrapped) client
// conn alongside the upstream so the caller can bridge them. The client conn must already have received the
// CONNECT 200 (a TLS client sends its ClientHello only after that).
func steerInterceptionUpstream(ctx context.Context, clientConn net.Conn, route edgeplane.NetworkExtensionRuntimeCopyTCPRoute, dialer edgeplane.NetworkExtensionRuntimeCopyTCPDialer) (net.Conn, io.ReadWriteCloser, edgeplane.NetworkExtensionRuntimeCopyTCPRoute, error) {
	if sniDialer, ok := dialer.(edgeplane.NetworkExtensionRuntimeCopySNIPeekDialer); ok && sniDialer.SNIBasedDecisionEnabled() && route.Port == 443 {
		logDebugf("steer_peek_start port=%d", route.Port)
		sni, buffered, perr := interception.PeekClientHelloSNI(clientConn)
		logDebugf("steer_peek_done sni_len=%d buffered=%d err=%v", len(sni), len(buffered), perr)
		route.SNI = sni
		clientConn = &edgeplane.NetworkExtensionLabTLSPrefixedConn{Conn: clientConn, Prefix: buffered}
	}
	upstreamConn, err := dialer.OpenTCPConnection(ctx, route)
	if err != nil || upstreamConn == nil {
		return clientConn, nil, route, fmt.Errorf("steer interception dial failed: %w", err)
	}
	return clientConn, upstreamConn, route, nil
}

// steerEgressForward egresses an ALLOWED steered flow. With an interception dialer it routes via the TLS
// interception engine (InterceptAll); without one it transparently forwards to the original destination
// (the prior /steer policy-enforcing forward proxy). Both paths use the full-duplex tunnel bridge so
// long-lived / bidirectional flows are preserved. The client conn must already have received CONNECT 200.
func steerEgressForward(ctx context.Context, clientConn net.Conn, authority string, route edgeplane.NetworkExtensionRuntimeCopyTCPRoute, interceptionDialer edgeplane.NetworkExtensionRuntimeCopyTCPDialer) error {
	// Interactive East-West families (ssh/rdp/…) get an UNLIMITED full-duplex idle window (idle=0) plus a finite
	// half-close linger: a live session at a prompt is never reaped, but an abandoned (half-closed) flow still is.
	// Everything else (browsing https/http) keeps the default idle + /8 linger, so idle connections are reclaimed.
	bridge := func(a, b io.ReadWriteCloser) {
		edgeplane.BridgeNetworkExtensionRuntimeCopyTunnel(ctx, a, b)
	}
	if steerInteractiveEastWestFamily(steerServiceFamilyForPort(route.Port)) {
		bridge = func(a, b io.ReadWriteCloser) {
			edgeplane.BridgeNetworkExtensionRuntimeCopyTunnelWithIdleAndLinger(ctx, a, b, 0, steerInteractiveHalfCloseLinger)
		}
	}
	// ★ WHICH FAMILY TO FETCH ON IS NOT A QUESTION ABOUT DECRYPTION. See
	// recovering_the_name_is_not_a_property_of_inspection.go — a destination literal this node cannot egress
	// to is dead unless the flow names itself, and reading that name was wired behind interception.
	clientConn, route = recoverTheDestinationName(clientConn, route)
	if interceptionDialer != nil {
		cc, upstreamConn, _, err := steerInterceptionUpstream(ctx, clientConn, route, interceptionDialer)
		if err != nil {
			return err
		}
		bridge(cc, upstreamConn)
		return nil
	}
	upstream, err := net.DialTimeout("tcp", authority, 10*time.Second)
	if err != nil {
		return fmt.Errorf("steer upstream dial failed: %w", err)
	}
	bridge(clientConn, upstream)
	return nil
}

// steerEgressRepeatSuffix renders the coalescer's count without a second log line to keep in step.
func steerEgressRepeatSuffix(suppressed int) string {
	if suppressed <= 0 {
		return ""
	}
	return fmt.Sprintf(" repeated=%d window=%s", suppressed, edgeplane.EgressFailureCoalesceWindow)
}

// steerConnectorRouteNote says whether a connector fronts this destination, on the failure path only.
//
// ★★★ "EGRESS FAILED" FOR AN INTERNAL DESTINATION READS AS A NETWORK FAULT (2026-08-26, after an evening of
// reading exactly that line and learning nothing from it). Two causes wear the same message and need opposite
// fixes:
//
//	no connector claims this name  -> the Edge dialled the public internet for an internal address. The
//	                                  binding is missing, or it has not reached THIS node.
//	a connector claims it          -> the route layer chose one and could not reach it: no tunnel here, no
//	                                  mesh link to its region, or outside the organization's boundary.
//
// Resolved on the ERROR path only. A per-flow lookup would put a registry round trip on the hot path for the
// public web, where the answer is always "no" and nobody is asking.
func steerConnectorRouteNote(ctx context.Context, registry connectorRegistryStore, tenantID, host string) string {
	if registry == nil || strings.TrimSpace(host) == "" {
		return ""
	}
	conn, ok, err := connectorForDestination(ctx, registry, strings.TrimSpace(tenantID), host, "")
	switch {
	case err != nil:
		return fmt.Sprintf(" connector_route=unknown (%v)", err)
	case ok:
		return fmt.Sprintf(" connector_route=%s connector_region=%s — this destination IS fronted by a "+
			"connector, so the failure is the route layer reaching it, not the internet", conn.ID, edgeplane.ConnectorRegionForLog(conn))
	default:
		return " connector_route=none — no connector claims this name here, so it was dialled as a public " +
			"destination. For an internal address that means the binding is missing or has not reached this node"
	}
}
