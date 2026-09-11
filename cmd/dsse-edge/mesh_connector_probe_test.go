package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tunnel"
)

func probeConnector(t *testing.T, manager *tunnel.Manager, id string, answer bool) <-chan tunnel.Frame {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	s, _ := manager.Register(id, "local-"+id, tunnel.NewInProcessConn(a, true))
	go s.Run()
	received := make(chan tunnel.Frame, 16)
	go func() {
		transport := tunnel.NewInProcessConn(b, false)
		for {
			var f tunnel.Frame
			if transport.ReadJSON(&f) != nil {
				return
			}
			received <- f
			if !answer {
				continue
			}
			result := &tunnel.ProbeResult{Host: f.Host, Port: f.Port, Protocol: f.ProbeProtocol, Reachable: f.Host != "denied.internal"}
			if !result.Reachable {
				result.FailureLayer = tunnel.ProbeFailureLayerRoute
			}
			if transport.WriteJSON(tunnel.Frame{Type: tunnel.FrameProbeResult, RequestID: f.RequestID, TunnelID: f.TunnelID, Probe: result}) != nil {
				return
			}
		}
	}()
	return received
}

func TestMeshDiagnosticRelaysSelectedTenantConnector(t *testing.T) {
	reg := meshRegistryWithConnectorInRegion(t, "region-x")
	_, err := reg.Register(model.ConnectorRegistration{ID: "conn-b", TenantID: "tenant-b", Status: "active", PrivateBaseURL: "https://internal.invalid", EdgeRegionID: "region-x"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	m := tunnel.NewManager()
	seenA := probeConnector(t, m, "conn-x", true)
	seenB := probeConnector(t, m, "conn-b", true)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go serveMeshIngressTunnel(context.Background(), tunnel.NewInProcessConn(a, false), &recordingDirectDialer{}, "wrong-default-tenant", meshConnectorProber(reg, m, "region-x", nil))
	peers := tunnel.NewManager()
	peer, _ := peers.Register("peer-x", "peer-tunnel", tunnel.NewInProcessConn(b, true))
	go peer.Run()
	for _, tc := range []struct {
		tenant, id string
		seen       <-chan tunnel.Frame
	}{{"tenant-a", "conn-x", seenA}, {"tenant-b", "conn-b", seenB}} {
		for _, host := range []string{"same.internal", "denied.internal"} {
			f := tunnel.Frame{Type: tunnel.FrameProbeRequest, RequestID: "same-peer-request", TenantID: tc.tenant, ProbeConnectorID: tc.id, Host: host, Port: 443, ProbeProtocol: tunnel.ProbeProtocolWeb}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			got, err := peer.RoundTrip(ctx, f)
			cancel()
			if err != nil {
				t.Fatal(err)
			}
			if got.RequestID != f.RequestID || got.TunnelID != "peer-tunnel" || got.Probe == nil || got.Probe.Host != host || got.Probe.Reachable != (host != "denied.internal") {
				t.Fatalf("relay response: %+v", got)
			}
			if host == "denied.internal" && got.Probe.FailureLayer != tunnel.ProbeFailureLayerRoute {
				t.Fatal("connector route refusal was lost")
			}
			forward := <-tc.seen
			if forward.TenantID != tc.tenant || forward.ProbeConnectorID != tc.id || forward.RequestID == f.RequestID || forward.ProbeProtocol != f.ProbeProtocol {
				t.Fatalf("relay request: %+v", forward)
			}
		}
	}
}

func TestMeshDiagnosticRejectsUnscopedOrNonlocalRequests(t *testing.T) {
	reg := meshRegistryWithConnectorInRegion(t, "region-x")
	m := tunnel.NewManager()
	seen := probeConnector(t, m, "conn-x", true)
	base := tunnel.Frame{Type: tunnel.FrameProbeRequest, RequestID: "probe", TenantID: "tenant-a", ProbeConnectorID: "conn-x", Host: "corp.internal", Port: 443}
	for _, tc := range []struct {
		name   string
		change func(*tunnel.Frame)
		region string
	}{
		{"missing tenant", func(f *tunnel.Frame) { f.TenantID = "" }, "region-x"},
		{"wrong tenant", func(f *tunnel.Frame) { f.TenantID = "tenant-b" }, "region-x"},
		{"missing connector", func(f *tunnel.Frame) { f.ProbeConnectorID = "" }, "region-x"},
		{"wrong connector", func(f *tunnel.Frame) { f.ProbeConnectorID = "other" }, "region-x"},
		{"invalid protocol", func(f *tunnel.Frame) { f.ProbeProtocol = "ftp" }, "region-x"},
		{"excessive timeout", func(f *tunnel.Frame) { f.ConnectTimeoutMillis = tunnel.MaxProbeTimeoutMillis + 1 }, "region-x"},
		{"residency", func(f *tunnel.Frame) {}, "region-y"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := base
			tc.change(&f)
			_, err := meshConnectorProber(reg, m, tc.region, func(string) []string { return []string{"region-x"} })(context.Background(), f)
			if err == nil {
				t.Fatal("request accepted")
			}
			select {
			case <-seen:
				t.Fatal("refused request reached a connector")
			default:
			}
		})
	}
	_, err := meshConnectorProber(reg, tunnel.NewManager(), "region-x", nil)(context.Background(), base)
	if err == nil || !strings.Contains(err.Error(), "no local tunnel") {
		t.Fatalf("nonlocal connector: %v", err)
	}
}

func TestMeshDiagnosticDeadline(t *testing.T) {
	reg := meshRegistryWithConnectorInRegion(t, "region-x")
	m := tunnel.NewManager()
	probeConnector(t, m, "conn-x", false)
	f := tunnel.Frame{Type: tunnel.FrameProbeRequest, RequestID: "probe", TenantID: "tenant-a", ProbeConnectorID: "conn-x", Host: "corp.internal", Port: 443, ConnectTimeoutMillis: 40}
	start := time.Now()
	_, err := meshConnectorProber(reg, m, "region-x", nil)(context.Background(), f)
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("unbounded probe: %v elapsed=%v", err, time.Since(start))
	}
}

func TestMeshDiagnosticsDoNotBlockTCPAndStopWithLink(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	started, stopped := make(chan struct{}, 8), make(chan struct{}, 8)
	probe := func(ctx context.Context, f tunnel.Frame) (tunnel.Frame, error) {
		started <- struct{}{}
		<-ctx.Done()
		stopped <- struct{}{}
		return tunnel.Frame{}, ctx.Err()
	}
	go serveMeshIngressTunnel(context.Background(), tunnel.NewInProcessConn(a, false), &recordingDirectDialer{}, "unused", probe)
	m := tunnel.NewManager()
	s, _ := m.Register("peer", "peer", tunnel.NewInProcessConn(b, true))
	go s.Run()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for i := 0; i < 8; i++ {
		go s.RoundTrip(ctx, tunnel.Frame{Type: tunnel.FrameProbeRequest, RequestID: fmt.Sprintf("p%d", i)})
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal("probe did not start")
		}
	}
	_, err := s.RoundTrip(ctx, tunnel.Frame{Type: tunnel.FrameProbeRequest, RequestID: "overflow"})
	if err == nil || !strings.Contains(err.Error(), "capacity") {
		t.Fatalf("probe cap: %v", err)
	}
	// The fake dialer returns no connection. Its TCP open result must still arrive
	// while all eight diagnostic workers are waiting on their connector.
	open, err := edgeplane.EdgeTCPOpenFrameForTarget("tcp", edgeplane.EdgeTCPConnectTarget{ApplicationID: "app", Host: "corp.internal", Port: 443}, edgeplane.InteractiveEastWestEdgeTCPConnectLimits())
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = s.OpenTCP(ctx, open)
	if err == nil || !strings.Contains(err.Error(), "no connection") {
		t.Fatalf("TCP blocked by probes: %v", err)
	}
	b.Close()
	for i := 0; i < 8; i++ {
		select {
		case <-stopped:
		case <-ctx.Done():
			t.Fatal("probe survived closed mesh link")
		}
	}
}
