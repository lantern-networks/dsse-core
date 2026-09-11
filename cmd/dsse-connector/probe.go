package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tunnel"
)

// runConnectorProbe executes a Slice 3 reachability probe for ONE destination and returns a secret-safe
// probe_result frame. The destination MUST fall within this connector's reachable_routes; otherwise the probe
// is REFUSED at the route layer (FailureLayer="route") with NO dial — this is the SSRF / internal-scan guard,
// so a compromised or buggy edge can never make the connector probe an arbitrary internal host. It reuses the
// SAME resolver the edge uses to PICK the connector, so admission and selection share one matching rule.
//
// The probe is layered (DNS -> TCP -> TLS -> HTTP) and stops at the first failing layer, recording WHICH layer
// failed so the UI can show "Failure layer: DNS". It carries no secret material: no response body, no payload
// bytes, no certificate private key — only non-secret diagnostics (resolved IPs, latency, public cert fields,
// HTTP status).
func runConnectorProbe(ctx context.Context, frame tunnel.Frame, reachable model.ConnectorReachableRoutes) tunnel.Frame {
	host := strings.TrimSpace(frame.Host)
	protocol := frame.ProbeProtocol
	if protocol == "" {
		protocol = tunnel.ProbeProtocolWeb
	}
	result := &tunnel.ProbeResult{Host: host, Port: frame.Port, Protocol: protocol}

	if err := tunnel.ValidateProbeRequestFrame(frame); err != nil {
		result.FailureLayer = tunnel.ProbeFailureLayerRoute
		result.DNS.Error = err.Error()
		return connectorProbeResultFrame(frame, result)
	}

	// SSRF / out-of-range guard: only destinations fronted by this connector's reachable routes may be probed.
	if !reachableRouteAuthorizes(frame, reachable) {
		result.FailureLayer = tunnel.ProbeFailureLayerRoute
		result.DNS.Error = "destination is not within this connector's reachable_routes"
		return connectorProbeResultFrame(frame, result)
	}

	timeout := time.Duration(tunnel.ProbeTimeoutMillisOrDefault(frame.ConnectTimeoutMillis)) * time.Millisecond
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addr := net.JoinHostPort(host, strconv.Itoa(frame.Port))

	// --- DNS layer ---
	if ip := net.ParseIP(host); ip != nil {
		// An IP literal needs no resolution; the resolved IP is the literal itself.
		result.DNS = tunnel.ProbeLayerResult{Attempted: true, OK: true}
		result.ResolvedIPs = []string{ip.String()}
	} else {
		start := time.Now()
		addrs, err := net.DefaultResolver.LookupHost(probeCtx, host)
		result.DNS = tunnel.ProbeLayerResult{Attempted: true, LatencyMillis: msSince(start)}
		if err != nil {
			result.DNS.Error = err.Error()
			result.FailureLayer = tunnel.ProbeFailureLayerDNS
			return connectorProbeResultFrame(frame, result)
		}
		result.DNS.OK = true
		result.ResolvedIPs = addrs
	}

	// --- TCP layer ---
	{
		start := time.Now()
		dialer := net.Dialer{}
		conn, err := dialer.DialContext(probeCtx, "tcp", addr)
		result.TCP = tunnel.ProbeLayerResult{Attempted: true, LatencyMillis: msSince(start)}
		if err != nil {
			result.TCP.Error = err.Error()
			result.FailureLayer = tunnel.ProbeFailureLayerTCP
			return connectorProbeResultFrame(frame, result)
		}
		_ = conn.Close()
		result.TCP.OK = true
	}

	// A TCP app (ssh/database/etc.) is reachable once TCP connects; TLS/HTTP are web-only layers.
	if protocol == tunnel.ProbeProtocolTCP {
		result.Reachable = true
		return connectorProbeResultFrame(frame, result)
	}

	// --- TLS layer ---
	{
		start := time.Now()
		// InsecureSkipVerify lets the handshake COMPLETE against an internal CA we do not anchor here; trust is
		// not the probe's job. We still capture the public cert fields (incl. expiry) so the operator sees them.
		tlsDialer := tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true, ServerName: host}}
		conn, err := tlsDialer.DialContext(probeCtx, "tcp", addr)
		result.TLS = tunnel.ProbeLayerResult{Attempted: true, LatencyMillis: msSince(start)}
		if err != nil {
			result.TLS.Error = err.Error()
			result.FailureLayer = tunnel.ProbeFailureLayerTLS
			return connectorProbeResultFrame(frame, result)
		}
		if tlsConn, ok := conn.(*tls.Conn); ok {
			state := tlsConn.ConnectionState()
			if len(state.PeerCertificates) > 0 {
				result.TLSCert = probeTLSCertInfo(state.PeerCertificates[0])
			}
		}
		_ = conn.Close()
		result.TLS.OK = true
	}

	// --- HTTP layer ---
	{
		start := time.Now()
		client := &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				Proxy:           nil,
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: host},
			},
		}
		req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, "https://"+addr+"/", nil)
		if err != nil {
			result.HTTP = tunnel.ProbeLayerResult{Attempted: true, Error: err.Error()}
			result.FailureLayer = tunnel.ProbeFailureLayerHTTP
			return connectorProbeResultFrame(frame, result)
		}
		req.Host = host
		resp, err := client.Do(req)
		result.HTTP = tunnel.ProbeLayerResult{Attempted: true, LatencyMillis: msSince(start)}
		if err != nil {
			result.HTTP.Error = err.Error()
			result.FailureLayer = tunnel.ProbeFailureLayerHTTP
			return connectorProbeResultFrame(frame, result)
		}
		// Never read the body — a probe records the status code only (secret-safe; no payload).
		_ = resp.Body.Close()
		result.HTTP.OK = true
		result.HTTPStatus = resp.StatusCode
	}

	result.Reachable = true
	return connectorProbeResultFrame(frame, result)
}

// probeTLSCertInfo projects the NON-secret fields of a server certificate. It never exposes the private key or
// the raw certificate bytes — only public identity/validity fields an operator needs to diagnose TLS.
func probeTLSCertInfo(cert *x509.Certificate) *tunnel.ProbeTLSCertInfo {
	if cert == nil {
		return nil
	}
	now := time.Now()
	return &tunnel.ProbeTLSCertInfo{
		Subject:   cert.Subject.CommonName,
		Issuer:    cert.Issuer.CommonName,
		NotBefore: cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:  cert.NotAfter.UTC().Format(time.RFC3339),
		DNSNames:  cert.DNSNames,
		Expired:   now.Before(cert.NotBefore) || now.After(cert.NotAfter),
	}
}

func connectorProbeResultFrame(frame tunnel.Frame, result *tunnel.ProbeResult) tunnel.Frame {
	return tunnel.Frame{
		Type:      tunnel.FrameProbeResult,
		RequestID: frame.RequestID,
		TunnelID:  frame.TunnelID,
		Probe:     result,
	}
}

func msSince(start time.Time) int64 {
	elapsed := time.Since(start) / time.Millisecond
	if elapsed < 0 {
		return 0
	}
	return int64(elapsed)
}
