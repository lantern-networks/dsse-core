package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tunnel"
)

// meshRegistryWithConnectorInRegion builds a registry with one connector in the given region fronting corp.internal.
func meshRegistryWithConnectorInRegion(t *testing.T, region string) connectorRegistryStore {
	t.Helper()
	reg := connector.NewRegistry()
	if _, err := reg.Register(model.ConnectorRegistration{
		ID:              "conn-x",
		TenantID:        "tenant-a",
		Status:          "active",
		PrivateBaseURL:  "https://internal.invalid",
		EdgeRegionID:    region,
		ReachableRoutes: model.ConnectorReachableRoutes{FQDNDomains: []string{"corp.internal"}},
	}, time.Date(2026, 6, 25, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("register connector: %v", err)
	}
	return reg
}

// TestMeshIngressRelaysFlowIntoLocalConnector proves the full inter-region MESH data path in-process:
// a mesh-eligible flow on edge Y (region-y) whose connector lives in region-x is relayed Y->X over a peer-edge
// link, and edge X bridges it into its LOCAL connector — bytes round-trip end to end
// (Y dialer -> peer link -> X mesh ingress -> X local connector tunnel -> echo). This is the runtime path that
// was nil-wired before; it exercises edgeplane.PeerEdgeProvider + serveMeshIngressTunnel + the local-connector bridge.
func TestMeshIngressRelaysFlowIntoLocalConnector(t *testing.T) {
	reg := meshRegistryWithConnectorInRegion(t, "region-x")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// --- Edge X: a local connector tunnel (fake echo) + the mesh-ingress serve loop on one end of the peer link.
	xTunnels := tunnel.NewManager()
	echoEdgeRaw, echoConnectorRaw := net.Pipe()
	defer echoEdgeRaw.Close()
	defer echoConnectorRaw.Close()
	xSession, _ := xTunnels.Register("conn-x", "tun-x", tunnel.NewInProcessConn(echoEdgeRaw, true))
	go xSession.Run()
	startFakeConnectorEcho(tunnel.NewInProcessConn(echoConnectorRaw, false))

	xDialer := edgeplane.ConnectorEgressDialer{
		ResolveConnector: connectorDestinationResolver(reg),
		Tunnels:          xTunnels,
		TenantID:         "tenant-a",
		LocalRegion:      "region-x", // the connector is LOCAL to X -> edgeplane.ReachLocal -> X's own connector tunnel
		Direct:           &recordingDirectDialer{},
	}

	peerXRaw, peerYRaw := net.Pipe()
	defer peerXRaw.Close()
	defer peerYRaw.Close()
	go func() {
		_ = serveMeshIngressTunnel(ctx, tunnel.NewInProcessConn(peerXRaw, false), xDialer, "tenant-a", nil)
	}()

	// --- Edge Y: a peer-edge session over the other end of the peer link, registered for region-x.
	yPeerManager := tunnel.NewManager()
	peerSession, _ := yPeerManager.Register("peer_region-x", "tun-peer", tunnel.NewInProcessConn(peerYRaw, true))
	go peerSession.Run()
	peerReg := newPeerEdgeRegistry()
	peerReg.set("region-x", peerSession)

	yDirect := &recordingDirectDialer{}
	yDialer := edgeplane.ConnectorEgressDialer{
		ResolveConnector: connectorDestinationResolver(reg),
		Tunnels:          tunnel.NewManager(), // empty: Y has NO local connector tunnel; the only way through is the mesh
		TenantID:         "tenant-a",
		LocalRegion:      "region-y",
		PeerEdges:        peerReg,
		MeshEligible:     func(string) bool { return true }, // the app opted into mesh
		Direct:           yDirect,
	}

	conn, err := yDialer.OpenTCPConnection(ctx, edgeplane.NetworkExtensionRuntimeCopyTCPRoute{
		Host: "host.corp.internal", Port: 5432, SNI: "host.corp.internal", TenantID: "tenant-a",
	})
	if err != nil {
		t.Fatalf("mesh OpenTCPConnection: %v", err)
	}
	defer conn.Close()
	if yDirect.called {
		t.Fatal("a mesh-eligible cross-region flow must NOT direct-dial on Y")
	}

	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write through mesh: %v", err)
	}
	got := make([]byte, 5)
	if err := readFull(conn, got, 2*time.Second); err != nil {
		t.Fatalf("read echo through mesh: %v", err)
	}
	if string(got) != "HELLO" {
		t.Fatalf("mesh echo = %q, want HELLO (bytes did not round-trip Y->X->local connector)", got)
	}
}

// TestMeshFailsClosedWithoutPeerLink proves the residency-safe default: a mesh-eligible cross-region flow with no
// configured peer link is denied (not direct-dialed, not silently hairpinned to a direct egress).
func TestMeshFailsClosedWithoutPeerLink(t *testing.T) {
	reg := meshRegistryWithConnectorInRegion(t, "region-x")
	yDirect := &recordingDirectDialer{}
	yDialer := edgeplane.ConnectorEgressDialer{
		ResolveConnector: connectorDestinationResolver(reg),
		Tunnels:          tunnel.NewManager(),
		TenantID:         "tenant-a",
		LocalRegion:      "region-y",
		PeerEdges:        nil, // no fabric
		MeshEligible:     func(string) bool { return true },
		Direct:           yDirect,
	}
	_, err := yDialer.OpenTCPConnection(context.Background(), edgeplane.NetworkExtensionRuntimeCopyTCPRoute{
		Host: "host.corp.internal", Port: 5432, SNI: "host.corp.internal", TenantID: "tenant-a",
	})
	if err == nil {
		t.Fatal("mesh-eligible flow with no peer link must fail closed, got nil error")
	}
	if yDirect.called {
		t.Fatal("a connector-fronted cross-region flow must never direct-dial")
	}
}

// TestMeshOutOfBoundaryDeniedBeforeReachingPeer proves residency beats mesh: if the connector's region is outside
// the tenant's allowed regions, the flow is denied even when mesh is eligible and a peer link exists.
func TestMeshOutOfBoundaryDeniedBeforeReachingPeer(t *testing.T) {
	reg := meshRegistryWithConnectorInRegion(t, "region-x")
	peerReg := newPeerEdgeRegistry() // would serve region-x if reached
	yDirect := &recordingDirectDialer{}
	yDialer := edgeplane.ConnectorEgressDialer{
		ResolveConnector: connectorDestinationResolver(reg),
		Tunnels:          tunnel.NewManager(),
		TenantID:         "tenant-a",
		LocalRegion:      "region-y",
		Residency:        edgeplane.ResidencyResolver(func(string) []string { return []string{"region-y", "region-z"} }), // region-x NOT allowed
		PeerEdges:        peerReg,
		MeshEligible:     func(string) bool { return true },
		Direct:           yDirect,
	}
	_, err := yDialer.OpenTCPConnection(context.Background(), edgeplane.NetworkExtensionRuntimeCopyTCPRoute{
		Host: "host.corp.internal", Port: 5432, SNI: "host.corp.internal", TenantID: "tenant-a",
	})
	if err == nil {
		t.Fatal("out-of-boundary connector must be denied even with mesh eligible")
	}
	if yDirect.called {
		t.Fatal("out-of-boundary flow must never direct-dial")
	}
}
