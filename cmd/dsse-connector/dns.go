package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tunnel"
)

// runConnectorDNS resolves a RAW internal DNS query inside the private network and returns the raw response.
// The Edge cannot reach the internal DNS directly; the connector can. The upstream server is SSRF-guarded to
// the connector's reachable routes (same posture as the reachability probe). UDP first, TCP on truncation, so
// every record type (SRV for AD DC-locator especially) is preserved. See docs/dns_conditional_forwarding_design.md.
func runConnectorDNS(ctx context.Context, frame tunnel.Frame, reachable model.ConnectorReachableRoutes) tunnel.Frame {
	if err := tunnel.ValidateDNSQueryFrame(frame); err != nil {
		return tunnel.DNSResultFrame(frame.RequestID, nil, err)
	}
	raw, _ := tunnel.DecodeDNSMessage(frame.DNSQuery)
	upstream := strings.TrimSpace(frame.DNSUpstream)
	if upstream == "" {
		return tunnel.DNSResultFrame(frame.RequestID, nil, fmt.Errorf("no internal DNS upstream configured"))
	}
	if _, _, err := net.SplitHostPort(upstream); err != nil {
		// Accept a bare host/IP; default to the standard DNS port.
		upstream = net.JoinHostPort(upstream, "53")
	}
	if !connectorDNSUpstreamInScope(upstream, reachable) {
		log.Printf("connector_dns refuse upstream=%s reason=out_of_scope ns=%q", upstream, reachable.Namespace)
		return tunnel.DNSResultFrame(frame.RequestID, nil, fmt.Errorf("dns upstream is outside the connector's reachable routes"))
	}
	timeout := time.Duration(tunnel.DNSQueryTimeoutMillisOrDefault(frame.ConnectTimeoutMillis)) * time.Millisecond
	resp, err := resolveViaInternalDNS(ctx, upstream, raw, timeout)
	if err != nil {
		log.Printf("connector_dns error upstream=%s err=%v", upstream, err)
	}
	return tunnel.DNSResultFrame(frame.RequestID, resp, err)
}

// connectorDNSUpstreamInScope enforces the SSRF guard: the internal DNS server must be within the connector's
// reachable routes, resolved the same way a steered destination is (route layer over the connector's own
// reachable_routes). Mirrors the TCP dialer's guard.
func connectorDNSUpstreamInScope(upstream string, reachable model.ConnectorReachableRoutes) bool {
	host, _, err := net.SplitHostPort(upstream)
	if err != nil {
		host = upstream
	}
	self := model.ConnectorRegistration{ID: "self", ReachableRoutes: reachable}
	_, ok := connector.ResolveConnectorForDestination(host, reachable.Namespace, []model.ConnectorRegistration{self})
	return ok
}

// resolveViaInternalDNS sends the raw query to the internal DNS: UDP first, then TCP on a UDP error or a
// truncated (TC) response.
func resolveViaInternalDNS(ctx context.Context, upstream string, query []byte, timeout time.Duration) ([]byte, error) {
	resp, truncated, err := dnsExchangeUDP(ctx, upstream, query, timeout)
	if err == nil && !truncated {
		return resp, nil
	}
	tcpResp, tcpErr := dnsExchangeTCP(ctx, upstream, query, timeout)
	if tcpErr != nil {
		if err != nil {
			return nil, fmt.Errorf("internal dns udp+tcp failed: udp=%v tcp=%w", err, tcpErr)
		}
		return nil, tcpErr
	}
	return tcpResp, nil
}

// dnsExchangeUDP does a single UDP DNS round-trip, returning the response and whether it was truncated (TC bit).
func dnsExchangeUDP(ctx context.Context, upstream string, query []byte, timeout time.Duration) ([]byte, bool, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", upstream)
	if err != nil {
		return nil, false, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(query); err != nil {
		return nil, false, err
	}
	buf := make([]byte, tunnel.MaxDNSMessageBytes)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, false, err
	}
	resp := buf[:n]
	truncated := n >= 3 && resp[2]&0x02 != 0 // header flags high byte, TC bit
	return resp, truncated, nil
}

// dnsExchangeTCP does a DNS-over-TCP round-trip (2-byte length prefix each way).
func dnsExchangeTCP(ctx context.Context, upstream string, query []byte, timeout time.Duration) ([]byte, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", upstream)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	prefixed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(prefixed[:2], uint16(len(query)))
	copy(prefixed[2:], query)
	if _, err := conn.Write(prefixed); err != nil {
		return nil, err
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	respLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if respLen == 0 || respLen > tunnel.MaxDNSMessageBytes {
		return nil, fmt.Errorf("internal dns tcp response length %d out of range", respLen)
	}
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}
