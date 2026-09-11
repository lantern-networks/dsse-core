package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/tunnel"
)

func meshProbeError(frame tunnel.Frame, reason string) tunnel.Frame {
	return tunnel.Frame{Type: tunnel.FrameProbeResult, RequestID: frame.RequestID, TunnelID: frame.TunnelID, Error: reason}
}

// Only the authenticated mesh ingress calls this relay. It never dials a backend itself,
// adopts the receiving node's default tenant, or forwards to another mesh peer.
// The selected connector still applies its own effective reachable-routes guard.
func meshConnectorProber(registry connectorRegistryStore, tunnels *tunnel.Manager, region string, residency edgeplane.ResidencyResolver) reachabilityProber {
	return func(ctx context.Context, frame tunnel.Frame) (tunnel.Frame, error) {
		if err := tunnel.ValidateProbeRequestFrame(frame); err != nil {
			return tunnel.Frame{}, err
		}
		tenant, connectorID := strings.TrimSpace(frame.TenantID), strings.TrimSpace(frame.ProbeConnectorID)
		if tenant == "" || connectorID == "" {
			return tunnel.Frame{}, fmt.Errorf("mesh diagnostic requires tenant and connector identity")
		}
		ctx, cancel := context.WithTimeout(ctx, time.Duration(tunnel.ProbeTimeoutMillisOrDefault(frame.ConnectTimeoutMillis))*time.Millisecond)
		defer cancel()
		if residency != nil {
			allowed := residency(tenant)
			if len(allowed) > 0 && !edgeplane.ContainsRegionFold(allowed, region) {
				return tunnel.Frame{}, fmt.Errorf("mesh diagnostic region is outside the tenant residency boundary")
			}
		}
		if registry == nil {
			return tunnel.Frame{}, fmt.Errorf("mesh diagnostic connector registry is unavailable")
		}
		conn, found, err := connectorRegistrationForTenantWithContext(ctx, registry, connectorID, tenant)
		if err != nil {
			return tunnel.Frame{}, fmt.Errorf("mesh diagnostic connector lookup failed")
		}
		if !found || conn.TenantID != tenant || connectorRouteUnavailable(conn) || tunnels == nil {
			return tunnel.Frame{}, fmt.Errorf("mesh diagnostic connector is unavailable for this tenant")
		}
		session, ok := tunnels.Get(connectorID)
		if !ok {
			return tunnel.Frame{}, fmt.Errorf("mesh diagnostic connector has no local tunnel")
		}
		// Different peer links can use the same request ID. The shared connector session
		// needs a fresh ID, while the reply to the peer must retain its original one.
		forward := frame
		forward.RequestID = randomEdgeID("mesh_probe_", time.Now().UTC())
		result, err := session.RoundTrip(ctx, forward)
		if err != nil {
			return tunnel.Frame{}, fmt.Errorf("mesh diagnostic connector did not complete the probe")
		}
		result.RequestID, result.TunnelID = frame.RequestID, frame.TunnelID
		return result, nil
	}
}
