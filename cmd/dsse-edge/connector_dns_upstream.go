package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/tunnel"
)

// connectorDNSUpstream implements dnsresolver.ConnectorDNS: it resolves an internal forward-zone query by
// routing the RAW DNS query THROUGH whichever connector reaches the internal DNS server (the Edge cannot reach
// internal DNS directly). The connector is chosen by the route layer from the upstream address — NOT configured
// per zone — so it naturally follows the connector that fronts that subnet. See
// docs/dns_conditional_forwarding_design.md.
type connectorDNSUpstream struct {
	registry      connectorRegistryStore
	tunnelManager *tunnel.Manager
	tenantID      string
	namespace     string // flow site / virtual-network context for IP routing (usually "")
}

// ResolveViaConnector sends the raw DNS query to `upstream` (the internal DNS server) through the connector
// that reaches it, and returns the raw DNS response. Fails (so the resolver returns SERVFAIL) rather than
// leaking an internal name — no connector, no tunnel, or a connector-side error all return an error.
func (c *connectorDNSUpstream) ResolveViaConnector(ctx context.Context, upstream string, raw []byte) ([]byte, error) {
	upstream = strings.TrimSpace(upstream)
	if upstream == "" {
		return nil, fmt.Errorf("no internal dns upstream configured")
	}
	host, _, err := net.SplitHostPort(upstream)
	if err != nil {
		host = upstream // bare host/IP
	}
	// Route by the internal DNS server's address — the connector that reaches it (also applies admin route
	// governance, so a HELD route won't be used for DNS either).
	conn, ok, err := connectorForDestination(ctx, c.registry, c.tenantID, host, c.namespace)
	if err != nil {
		logWarnf("connector_dns error=route_lookup host=%s ns=%q err=%v", host, c.namespace, err)
		return nil, err
	}
	if !ok {
		logWarnf("connector_dns error=no_connector host=%s ns=%q tenant=%s", host, c.namespace, c.tenantID)
		return nil, fmt.Errorf("no connector reaches internal dns %s", host)
	}
	if c.tunnelManager == nil {
		return nil, fmt.Errorf("tunnel manager not configured")
	}
	session, connected := c.tunnelManager.Get(conn.ID)
	if !connected || session == nil {
		logWarnf("connector_dns error=no_tunnel connector=%s host=%s", conn.ID, host)
		return nil, fmt.Errorf("connector %s tunnel not connected", conn.ID)
	}
	frame := tunnel.Frame{
		Type:                 tunnel.FrameDNSQuery,
		RequestID:            randomEdgeID("dnsq_", time.Now().UTC()),
		DNSUpstream:          upstream,
		DNSQuery:             tunnel.EncodeDNSMessage(raw),
		ConnectTimeoutMillis: tunnel.DefaultDNSQueryTimeoutMillis,
	}
	resp, err := session.RoundTrip(ctx, frame)
	if err != nil {
		logWarnf("connector_dns error=roundtrip connector=%s upstream=%s err=%v", conn.ID, upstream, err)
		return nil, err
	}
	if resp.Error != "" {
		logWarnf("connector_dns error=connector_side connector=%s upstream=%s err=%s", conn.ID, upstream, resp.Error)
		return nil, fmt.Errorf("connector dns: %s", resp.Error)
	}
	return tunnel.DecodeDNSMessage(resp.DNSResponse)
}
