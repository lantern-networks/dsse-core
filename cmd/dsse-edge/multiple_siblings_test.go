package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/tunnel"
)

func TestMultipleSiblingMeshLinksRemainIndependent(t *testing.T) {
	peers, err := parseMeshPeers("kiri=wss://node-b.example.test:8443/mesh/ingress/tunnel;kiri=wss://node-c.example.test:8443/mesh/ingress/tunnel")
	if err != nil || len(peers) != 2 {
		t.Fatalf("two sibling peers: %d, %v", len(peers), err)
	}
	if _, err := parseMeshPeers("kiri=wss://node-b.example.test:8443/mesh/ingress/tunnel,wss://node-c.example.test:8443/mesh/ingress/tunnel"); err == nil {
		t.Fatal("a comma-concatenated pair was accepted as one URL")
	}
	manager := tunnel.NewManager()
	a, aOther := net.Pipe()
	b, bOther := net.Pipe()
	defer a.Close()
	defer aOther.Close()
	defer b.Close()
	defer bOther.Close()
	aSession, _ := manager.Register("peer_a", "a", tunnel.NewInProcessConn(a, true))
	bSession, _ := manager.Register("peer_b", "b", tunnel.NewInProcessConn(b, true))
	registry := newPeerEdgeRegistry()
	registry.setForPeer("kiri", peers[0].url, aSession)
	registry.setForPeer("kiri", peers[1].url, bSession)
	if got := registry.PeerEdgesFor("kiri"); len(got) != 2 || got[0] != aSession || got[1] != bSession {
		t.Fatalf("live siblings: %v", got)
	}
	registry.clearForPeer("kiri", peers[0].url)
	if got := registry.PeerEdgesFor("kiri"); len(got) != 1 || got[0] != bSession {
		t.Fatalf("healthy sibling was removed with failed link: %v", got)
	}
	setMeshState([]string{"kiri", "kiri"}, 0, nil)
	defer setMeshState(nil, 0, nil)
	regions := meshStateForReport()["peer_regions"].([]string)
	if len(regions) != 1 || regions[0] != "kiri" {
		t.Fatalf("two Nodes were reported as two DSSE Regions: %v", regions)
	}
}

func TestPrivateFlowTriesSecondSiblingWhenFirstHasNoConnector(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := meshRegistryWithConnectorInRegion(t, "kiri")
	peerReg := newPeerEdgeRegistry()

	// The first sibling is alive but does not hold this Connector.
	for i := 0; i < 2; i++ {
		peerRaw, originRaw := net.Pipe()
		defer peerRaw.Close()
		defer originRaw.Close()
		tunnels := tunnel.NewManager()
		if i == 1 {
			connectorRaw, echoRaw := net.Pipe()
			defer connectorRaw.Close()
			defer echoRaw.Close()
			local, _ := tunnels.Register("conn-x", "connector", tunnel.NewInProcessConn(connectorRaw, true))
			go local.Run()
			startFakeConnectorEcho(tunnel.NewInProcessConn(echoRaw, false))
		}
		localDialer := edgeplane.ConnectorEgressDialer{
			ResolveConnector: connectorDestinationResolver(reg), Tunnels: tunnels,
			TenantID: "tenant-a", LocalRegion: "kiri", Direct: &recordingDirectDialer{},
		}
		go func() {
			_ = serveMeshIngressTunnel(ctx, tunnel.NewInProcessConn(peerRaw, false), localDialer, "tenant-a", nil)
		}()
		manager := tunnel.NewManager()
		session, _ := manager.Register("peer", "link", tunnel.NewInProcessConn(originRaw, true))
		go session.Run()
		peerReg.setForPeer("kiri", []string{"a", "b"}[i], session)
	}

	dialer := edgeplane.ConnectorEgressDialer{
		ResolveConnector: connectorDestinationResolver(reg), Tunnels: tunnel.NewManager(),
		TenantID: "tenant-a", LocalRegion: "kiri", PeerEdges: peerReg, Direct: &recordingDirectDialer{},
	}
	flow, err := dialer.OpenTCPConnection(ctx, edgeplane.NetworkExtensionRuntimeCopyTCPRoute{
		Host: "host.corp.internal", SNI: "host.corp.internal", Port: 443, TenantID: "tenant-a",
	})
	if err != nil {
		t.Fatalf("second sibling was not tried: %v", err)
	}
	defer flow.Close()
	if _, err := flow.Write([]byte("mesh")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if err := readFull(flow, got, 2*time.Second); err != nil || string(got) != "MESH" {
		t.Fatalf("relay through second sibling: %q, %v", got, err)
	}
}
