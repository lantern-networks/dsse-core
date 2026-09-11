package main

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tunnel"
)

type stubPeerEdges struct {
	region  string
	session *tunnel.Session
}

func (s stubPeerEdges) PeerEdgeFor(region string) (*tunnel.Session, bool) {
	if region == s.region && s.session != nil {
		return s.session, true
	}
	return nil, false
}

// TestConnectorEgressDialerMeshRelaysViaPeerEdge proves the MESH path: a mesh-eligible flow whose
// connector is in an in-boundary REMOTE region egresses through the peer-Edge link to that region (not the local
// connector tunnel, not direct dial), and the bytes round-trip — verified against a REAL tunnel session standing
// in for the sibling Edge that bridges to its local connector.
func TestConnectorEgressDialerMeshRelaysViaPeerEdge(t *testing.T) {
	manager := tunnel.NewManager()
	edgeRaw, peerRaw := net.Pipe()
	defer edgeRaw.Close()
	defer peerRaw.Close()
	session, _ := manager.Register("peer-jp-osaka", "tun-mesh", tunnel.NewInProcessConn(edgeRaw, true))
	go session.Run()
	startFakeConnectorEcho(tunnel.NewInProcessConn(peerRaw, false)) // the jp-osaka Edge, bridging to its connector

	reg := connector.NewRegistry()
	if _, err := reg.Register(model.ConnectorRegistration{
		ID: "c-osaka", TenantID: "tenant-a", Status: "active", PrivateBaseURL: "https://internal.invalid",
		EdgeRegionID: "jp-osaka", ReachableRoutes: model.ConnectorReachableRoutes{FQDNDomains: []string{"corp.internal"}},
	}, time.Date(2026, 6, 26, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("register: %v", err)
	}

	direct := &recordingDirectDialer{}
	dialer := edgeplane.ConnectorEgressDialer{
		ResolveConnector: connectorDestinationResolver(reg), Tunnels: tunnel.NewManager(), TenantID: "tenant-a", LocalRegion: "jp-tokyo",
		Residency:    func(string) []string { return []string{"jp-tokyo", "jp-osaka"} },
		PeerEdges:    stubPeerEdges{region: "jp-osaka", session: session},
		MeshEligible: func(string) bool { return true },
		Direct:       direct,
	}
	conn, err := dialer.OpenTCPConnection(context.Background(), edgeplane.NetworkExtensionRuntimeCopyTCPRoute{
		Host: "host.corp.internal", Port: 443, SNI: "host.corp.internal", TenantID: "tenant-a",
	})
	if err != nil {
		t.Fatalf("mesh OpenTCPConnection: %v", err)
	}
	defer conn.Close()
	if direct.called {
		t.Fatal("a mesh flow must NOT direct-dial")
	}
	if _, err := conn.Write([]byte("mesh")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, 4)
	if err := readFull(conn, got, 2*time.Second); err != nil {
		t.Fatalf("read echo through peer edge: %v", err)
	}
	if string(got) != "MESH" {
		t.Fatalf("mesh echo = %q, want MESH (bytes did not round-trip through the peer edge)", got)
	}
}

// TestConnectorEgressDialerHairpinFailsClosedWithoutMesh proves the default: an in-boundary remote connector that
// is NOT mesh-eligible is hairpin (a steering decision) and fails closed at the dialer — never meshed, never
// direct-dialed.
func TestConnectorEgressDialerHairpinFailsClosedWithoutMesh(t *testing.T) {
	reg := connector.NewRegistry()
	if _, err := reg.Register(model.ConnectorRegistration{
		ID: "c-osaka", TenantID: "tenant-a", Status: "active", PrivateBaseURL: "https://internal.invalid",
		EdgeRegionID: "jp-osaka", ReachableRoutes: model.ConnectorReachableRoutes{FQDNDomains: []string{"corp.internal"}},
	}, time.Date(2026, 6, 26, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("register: %v", err)
	}
	direct := &recordingDirectDialer{}
	dialer := edgeplane.ConnectorEgressDialer{
		ResolveConnector: connectorDestinationResolver(reg), Tunnels: tunnel.NewManager(), TenantID: "tenant-a", LocalRegion: "jp-tokyo",
		Residency:    func(string) []string { return []string{"jp-tokyo", "jp-osaka"} },
		PeerEdges:    stubPeerEdges{region: "jp-osaka", session: nil},
		MeshEligible: func(string) bool { return false }, // not opted in -> hairpin
		Direct:       direct,
	}
	_, err := dialer.OpenTCPConnection(context.Background(), edgeplane.NetworkExtensionRuntimeCopyTCPRoute{
		Host: "host.corp.internal", Port: 443, SNI: "host.corp.internal", TenantID: "tenant-a",
	})
	if err == nil || !strings.Contains(err.Error(), "hairpin") {
		t.Fatalf("in-boundary remote without mesh must fail closed as hairpin, got %v", err)
	}
	if direct.called {
		t.Fatal("must NOT direct-dial")
	}
}

// TestConnectorEgressDialerResidencyDeniesOutOfBoundary proves the residency resolver is wired into the live
// dialer: a connector whose region is outside the flow tenant's allowed regions fails closed as a residency
// denial, and is never direct-dialed.
func TestConnectorEgressDialerResidencyDeniesOutOfBoundary(t *testing.T) {
	reg := connector.NewRegistry()
	if _, err := reg.Register(model.ConnectorRegistration{
		ID: "c-useast", TenantID: "tenant-a", Status: "active", PrivateBaseURL: "https://internal.invalid",
		EdgeRegionID: "us-east", ReachableRoutes: model.ConnectorReachableRoutes{FQDNDomains: []string{"corp.internal"}},
	}, time.Date(2026, 6, 26, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("register: %v", err)
	}
	direct := &recordingDirectDialer{}
	dialer := edgeplane.ConnectorEgressDialer{
		ResolveConnector: connectorDestinationResolver(reg), Tunnels: tunnel.NewManager(), TenantID: "tenant-a", LocalRegion: "jp-tokyo",
		Residency: func(string) []string { return []string{"jp-tokyo", "jp-osaka"} }, Direct: direct,
	}
	_, err := dialer.OpenTCPConnection(context.Background(), edgeplane.NetworkExtensionRuntimeCopyTCPRoute{
		Host: "host.corp.internal", Port: 443, SNI: "host.corp.internal", TenantID: "tenant-a",
	})
	if err == nil || !strings.Contains(err.Error(), "residency boundary") {
		t.Fatalf("out-of-boundary connector must be a residency denial, got %v", err)
	}
	if direct.called {
		t.Fatal("must NOT direct-dial an out-of-boundary destination")
	}
}

func TestResolveConnectorReach(t *testing.T) {
	cases := []struct {
		name, connRegion, localRegion string
		allowed                       []string
		mesh                          bool
		want                          edgeplane.ReachDisposition
	}{
		{"unset connector region -> local", "", "jp-tokyo", nil, false, edgeplane.ReachLocal},
		{"same region -> local", "jp-tokyo", "jp-tokyo", nil, false, edgeplane.ReachLocal},
		{"same region, case-insensitive -> local", "JP-Tokyo", "jp-tokyo", nil, false, edgeplane.ReachLocal},
		{"remote, no residency set -> hairpin", "jp-osaka", "jp-tokyo", nil, false, edgeplane.ReachHairpin},
		{"remote, in boundary -> hairpin", "jp-osaka", "jp-tokyo", []string{"jp-tokyo", "jp-osaka"}, false, edgeplane.ReachHairpin},
		{"remote, in boundary, mesh-opt-in -> mesh", "jp-osaka", "jp-tokyo", []string{"jp-tokyo", "jp-osaka"}, true, edgeplane.ReachMesh},
		{"remote, OUT of boundary -> deny", "us-east", "jp-tokyo", []string{"jp-tokyo", "jp-osaka"}, false, edgeplane.ReachDenyOutOfBoundary},
		{"remote, out of boundary, mesh ignored -> deny", "us-east", "jp-tokyo", []string{"jp-tokyo"}, true, edgeplane.ReachDenyOutOfBoundary},
	}
	for _, tc := range cases {
		if got := edgeplane.ResolveConnectorReach(tc.connRegion, tc.localRegion, tc.allowed, tc.mesh); got.Disposition != tc.want {
			t.Errorf("%s: disposition = %d, want %d", tc.name, got.Disposition, tc.want)
		}
	}
}

// TestConnectorEgressDialerFailsClosedForRemoteRegion proves the residency/region guard: a connector that fronts
// the destination but terminates in ANOTHER region is not served from this edge (fail closed), and the private
// destination is never direct-dialed. A single-region deployment (unset connector region) is unaffected — covered
// by the local round-trip tests.
func TestConnectorEgressDialerFailsClosedForRemoteRegion(t *testing.T) {
	// ★ THE TUNNEL BELONGS TO A DIFFERENT CONNECTOR, AND THAT IS THE WHOLE POINT (corrected 2026-08-26).
	//
	// This fixture used to register the live tunnel under "conn-osaka" itself — the connector it then asserted
	// was in ANOTHER region. A connector whose tunnel is terminated on this Edge is not in another region; it is
	// here, and the catalog entry is simply stale (which is what happens the moment a connector fails over). So
	// the fixture contradicted the case it claimed to cover, and the assertion passed only because the region
	// field was read and the tunnel table was not. The tunnel below is a SIBLING connector, so the manager is
	// non-empty — the refusal has to come from the region decision, not from "this Edge holds no tunnels".
	manager := tunnel.NewManager()
	edgeRaw, connectorRaw := net.Pipe()
	defer edgeRaw.Close()
	defer connectorRaw.Close()
	session, _ := manager.Register("conn-tokyo-sibling", "tun-tokyo", tunnel.NewInProcessConn(edgeRaw, true))
	go session.Run()
	startFakeConnectorEcho(tunnel.NewInProcessConn(connectorRaw, false))

	reg := connector.NewRegistry()
	if _, err := reg.Register(model.ConnectorRegistration{
		ID:              "conn-osaka",
		TenantID:        "tenant-a",
		Status:          "active",
		PrivateBaseURL:  "https://internal.invalid",
		EdgeRegionID:    "jp-osaka", // remote: this edge is jp-tokyo
		ReachableRoutes: model.ConnectorReachableRoutes{FQDNDomains: []string{"corp.internal"}},
	}, time.Date(2026, 6, 26, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("register connector: %v", err)
	}

	direct := &recordingDirectDialer{}
	dialer := edgeplane.ConnectorEgressDialer{ResolveConnector: connectorDestinationResolver(reg), Tunnels: manager, TenantID: "tenant-a", LocalRegion: "jp-tokyo", Direct: direct}

	if _, err := dialer.OpenTCPConnection(context.Background(), edgeplane.NetworkExtensionRuntimeCopyTCPRoute{
		Host: "host.corp.internal", Port: 443, SNI: "host.corp.internal", TenantID: "tenant-a",
	}); err == nil {
		t.Fatal("a connector in another region must fail closed (not served from this edge)")
	}
	if direct.called {
		t.Fatal("must NOT direct-dial a remote-region connector's private destination")
	}
}
