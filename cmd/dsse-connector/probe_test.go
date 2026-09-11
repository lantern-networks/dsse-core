package main

import (
	"context"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tunnel"
)

func probeRequestFrame(host string, port int, protocol string) tunnel.Frame {
	return tunnel.Frame{
		Type:          tunnel.FrameProbeRequest,
		RequestID:     "req_probe_001",
		Host:          host,
		Port:          port,
		ProbeProtocol: protocol,
	}
}

// TestRunConnectorProbeRefusesOutOfRangeDestination is the SSRF guard: a destination NOT fronted by the
// connector's reachable_routes must be refused at the route layer with NO dial attempt (no DNS, no TCP).
func TestRunConnectorProbeRefusesOutOfRangeDestination(t *testing.T) {
	reachable := model.ConnectorReachableRoutes{FQDNDomains: []string{"corp.internal"}}
	// Use a port nothing listens on; if the route guard failed and a dial happened, the layers would be
	// attempted. The assertion below proves they were NOT.
	frame := probeRequestFrame("169.254.169.254", 80, tunnel.ProbeProtocolWeb) // classic SSRF metadata target
	out := runConnectorProbe(context.Background(), frame, reachable)
	if out.Type != tunnel.FrameProbeResult || out.Probe == nil {
		t.Fatalf("out = %+v, want probe_result with payload", out)
	}
	if out.Probe.Reachable {
		t.Fatal("out-of-range destination must not be reachable")
	}
	if out.Probe.FailureLayer != tunnel.ProbeFailureLayerRoute {
		t.Fatalf("failure layer = %q, want route (SSRF guard)", out.Probe.FailureLayer)
	}
	// No dial may have happened: DNS/TCP layers must be un-attempted.
	if out.Probe.DNS.Attempted || out.Probe.TCP.Attempted || out.Probe.TLS.Attempted || out.Probe.HTTP.Attempted {
		t.Fatalf("out-of-range probe attempted a network layer: %+v", out.Probe)
	}
}

// TestRunConnectorProbeReachableTCP probes a real loopback listener that IS within the reachable routes (an IP
// literal under a CIDR route). DNS + TCP must succeed; TLS/HTTP are not attempted for a tcp probe.
func TestRunConnectorProbeReachableTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	reachable := model.ConnectorReachableRoutes{CIDRs: []string{"127.0.0.0/8"}, Namespace: ""}
	out := runConnectorProbe(context.Background(), probeRequestFrame("127.0.0.1", port, tunnel.ProbeProtocolTCP), reachable)
	if out.Probe == nil {
		t.Fatalf("nil probe result: %+v", out)
	}
	if !out.Probe.Reachable {
		t.Fatalf("expected reachable; got %+v", out.Probe)
	}
	if !out.Probe.DNS.OK || !out.Probe.TCP.OK {
		t.Fatalf("DNS/TCP layers not OK: %+v", out.Probe)
	}
	if out.Probe.TLS.Attempted || out.Probe.HTTP.Attempted {
		t.Fatalf("tcp probe must not attempt TLS/HTTP: %+v", out.Probe)
	}
	if len(out.Probe.ResolvedIPs) == 0 || out.Probe.ResolvedIPs[0] != "127.0.0.1" {
		t.Fatalf("resolved IPs = %+v, want [127.0.0.1]", out.Probe.ResolvedIPs)
	}
}

// TestRunConnectorProbeTCPFailureLayer probes a port with no listener (within range) -> TCP layer fails and is
// named as the failure layer; DNS still succeeded.
func TestRunConnectorProbeTCPFailureLayer(t *testing.T) {
	reachable := model.ConnectorReachableRoutes{CIDRs: []string{"127.0.0.0/8"}}
	// Port 1 is reserved and not listening on loopback in test envs.
	out := runConnectorProbe(context.Background(), probeRequestFrame("127.0.0.1", 1, tunnel.ProbeProtocolTCP), reachable)
	if out.Probe == nil || out.Probe.Reachable {
		t.Fatalf("expected unreachable result: %+v", out.Probe)
	}
	if !out.Probe.DNS.OK {
		t.Fatalf("DNS should succeed for an IP literal: %+v", out.Probe)
	}
	if out.Probe.FailureLayer != tunnel.ProbeFailureLayerTCP {
		t.Fatalf("failure layer = %q, want tcp", out.Probe.FailureLayer)
	}
}

// TestRunConnectorProbeIsSecretSafe verifies the serialized probe result carries no key material / payload —
// the struct has no field for it, so the encoded JSON must not contain private-key markers.
func TestRunConnectorProbeIsSecretSafe(t *testing.T) {
	reachable := model.ConnectorReachableRoutes{CIDRs: []string{"127.0.0.0/8"}}
	out := runConnectorProbe(context.Background(), probeRequestFrame("127.0.0.1", 1, tunnel.ProbeProtocolWeb), reachable)
	encoded, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := strings.ToLower(string(encoded))
	for _, secret := range []string{"private key", "begin rsa", "begin private", "-----begin"} {
		if strings.Contains(body, secret) {
			t.Fatalf("probe result leaked secret marker %q: %s", secret, body)
		}
	}
}
