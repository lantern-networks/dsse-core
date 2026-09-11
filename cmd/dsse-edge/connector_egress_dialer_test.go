package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tunnel"
)

// recordingDirectDialer stands in for the direct (net.Dial) egress path so the test can assert when a flow
// falls back to direct dial instead of going through a connector tunnel.
type recordingDirectDialer struct {
	called bool
	conn   io.ReadWriteCloser
}

func (d *recordingDirectDialer) OpenTCPConnection(ctx context.Context, route edgeplane.NetworkExtensionRuntimeCopyTCPRoute) (io.ReadWriteCloser, error) {
	d.called = true
	return d.conn, nil
}

// startFakeConnectorEcho plays the connector side of a tunnel: it accepts the TCP open, then echoes every
// upstream data frame back downstream UPPER-CASED so the test can prove a real round trip through the tunnel.
func startFakeConnectorEcho(transport tunnel.FrameTransport) {
	go func() {
		for {
			var frame tunnel.Frame
			if err := transport.ReadJSON(&frame); err != nil {
				return
			}
			switch frame.Type {
			case tunnel.FrameTCPOpen:
				_ = transport.WriteJSON(tunnel.Frame{Type: tunnel.FrameTCPOpenResult, RequestID: frame.RequestID, ApplicationID: frame.ApplicationID})
			case tunnel.FrameTCPData:
				payload, err := tunnel.TCPDataFramePayload(frame)
				if err != nil {
					return
				}
				down, err := tunnel.NewTCPDataFrame(frame.RequestID, tunnel.TCPDirectionDown, bytes.ToUpper(payload))
				if err != nil {
					return
				}
				_ = transport.WriteJSON(down)
			case tunnel.FrameTCPClose:
				return
			}
		}
	}()
}

func newConnectorEgressTestRegistry(t *testing.T, routes []string) connectorRegistryStore {
	t.Helper()
	reg := connector.NewRegistry()
	if _, err := reg.Register(model.ConnectorRegistration{
		ID:              "conn-tok",
		TenantID:        "tenant-a",
		Status:          "active",
		PrivateBaseURL:  "https://internal.invalid",
		ReachableRoutes: model.ConnectorReachableRoutes{FQDNDomains: routes},
	}, time.Date(2026, 6, 25, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("register connector: %v", err)
	}
	return reg
}

// TestConnectorEgressDialerRoutesThroughConnectorTunnel proves the cutover end to end against a REAL tunnel
// session: a steered bypass flow whose destination is fronted by a live connector egresses THROUGH that
// connector's tunnel (bytes round-trip via the connector), not by direct dial.
func TestConnectorEgressDialerRoutesThroughConnectorTunnel(t *testing.T) {
	manager := tunnel.NewManager()
	edgeRaw, connectorRaw := net.Pipe()
	defer edgeRaw.Close()
	defer connectorRaw.Close()
	session, _ := manager.Register("conn-tok", "tun-tok", tunnel.NewInProcessConn(edgeRaw, true)) // bool is "reconnect", not success
	go session.Run()
	startFakeConnectorEcho(tunnel.NewInProcessConn(connectorRaw, false))

	direct := &recordingDirectDialer{}
	dialer := edgeplane.ConnectorEgressDialer{
		ResolveConnector: connectorDestinationResolver(newConnectorEgressTestRegistry(t, []string{"corp.internal"})),
		Tunnels:          manager,
		TenantID:         "tenant-a",
		Direct:           direct,
	}

	conn, err := dialer.OpenTCPConnection(context.Background(), edgeplane.NetworkExtensionRuntimeCopyTCPRoute{
		Host: "host.corp.internal", Port: 443, SNI: "host.corp.internal", TenantID: "tenant-a",
	})
	if err != nil {
		t.Fatalf("OpenTCPConnection through connector: %v", err)
	}
	defer conn.Close()
	if direct.called {
		t.Fatal("a connector-fronted destination must NOT direct-dial")
	}

	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write through connector tunnel: %v", err)
	}
	got := make([]byte, 5)
	if err := readFull(conn, got, 2*time.Second); err != nil {
		t.Fatalf("read echo through connector tunnel: %v", err)
	}
	if string(got) != "HELLO" {
		t.Fatalf("connector echo = %q, want HELLO (bytes did not round-trip through the connector)", got)
	}
}

// TestConnectorEgressDialerRoutesIPLiteralThroughConnector proves IP-addressed routing already works end to end
// for non-overlapping ranges: an IP-literal destination (no SNI) resolves to a connector with a CIDR route in the
// default namespace and the bytes round-trip through the connector. (Overlapping CIDRs ACROSS sites would need a
// per-flow namespace, which the steered route does not yet carry.)
func TestConnectorEgressDialerRoutesIPLiteralThroughConnector(t *testing.T) {
	manager := tunnel.NewManager()
	edgeRaw, connectorRaw := net.Pipe()
	defer edgeRaw.Close()
	defer connectorRaw.Close()
	session, _ := manager.Register("conn-ip", "tun-ip", tunnel.NewInProcessConn(edgeRaw, true))
	go session.Run()
	startFakeConnectorEcho(tunnel.NewInProcessConn(connectorRaw, false))

	reg := connector.NewRegistry()
	if _, err := reg.Register(model.ConnectorRegistration{
		ID:              "conn-ip",
		TenantID:        "tenant-a",
		Status:          "active",
		PrivateBaseURL:  "https://internal.invalid",
		ReachableRoutes: model.ConnectorReachableRoutes{CIDRs: []string{"10.0.0.0/8"}}, // default (empty) namespace
	}, time.Date(2026, 6, 25, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("register connector: %v", err)
	}

	direct := &recordingDirectDialer{}
	dialer := edgeplane.ConnectorEgressDialer{ResolveConnector: connectorDestinationResolver(reg), Tunnels: manager, TenantID: "tenant-a", Direct: direct}

	conn, err := dialer.OpenTCPConnection(context.Background(), edgeplane.NetworkExtensionRuntimeCopyTCPRoute{
		Host: "10.1.2.3", Port: 5432, TenantID: "tenant-a", // IP literal, no SNI
	})
	if err != nil {
		t.Fatalf("OpenTCPConnection IP through connector: %v", err)
	}
	defer conn.Close()
	if direct.called {
		t.Fatal("an IP fronted by a connector CIDR route must NOT direct-dial")
	}
	if _, err := conn.Write([]byte("db")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, 2)
	if err := readFull(conn, got, 2*time.Second); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != "DB" {
		t.Fatalf("IP-route echo = %q, want DB", got)
	}
}

// TestConnectorEgressDialerFallsBackToDirect proves the self-gating safety property: a destination fronted by NO
// connector route direct-dials exactly as before.
func TestConnectorEgressDialerFallsBackToDirect(t *testing.T) {
	sentinel := &nopReadWriteCloser{}
	direct := &recordingDirectDialer{conn: sentinel}
	dialer := edgeplane.ConnectorEgressDialer{
		ResolveConnector: connectorDestinationResolver(newConnectorEgressTestRegistry(t, []string{"corp.internal"})),
		Tunnels:          tunnel.NewManager(),
		TenantID:         "tenant-a",
		Direct:           direct,
	}
	conn, err := dialer.OpenTCPConnection(context.Background(), edgeplane.NetworkExtensionRuntimeCopyTCPRoute{
		Host: "www.example.com", Port: 443, SNI: "www.example.com", TenantID: "tenant-a",
	})
	if err != nil {
		t.Fatalf("OpenTCPConnection Direct: %v", err)
	}
	if !direct.called {
		t.Fatal("a destination with no connector route must direct-dial")
	}
	if conn != sentinel {
		t.Fatal("must return the direct dialer's connection unchanged")
	}
}

// TestConnectorEgressDialerFailsClosedWhenTunnelDown proves a connector OWNS the route but its tunnel is down ->
// fail closed, never leak the flow onto the Edge's own egress.
func TestConnectorEgressDialerFailsClosedWhenTunnelDown(t *testing.T) {
	direct := &recordingDirectDialer{}
	dialer := edgeplane.ConnectorEgressDialer{
		ResolveConnector: connectorDestinationResolver(newConnectorEgressTestRegistry(t, []string{"corp.internal"})),
		Tunnels:          tunnel.NewManager(), // no session registered for conn-tok
		TenantID:         "tenant-a",
		Direct:           direct,
	}
	if _, err := dialer.OpenTCPConnection(context.Background(), edgeplane.NetworkExtensionRuntimeCopyTCPRoute{
		Host: "host.corp.internal", Port: 443, SNI: "host.corp.internal", TenantID: "tenant-a",
	}); err == nil {
		t.Fatal("a connector-fronted destination with no live tunnel must fail closed")
	}
	if direct.called {
		t.Fatal("must NOT direct-dial a private destination the connector owns")
	}
}

// TestConnectorEgressDialContextRoutesInterceptOriginThroughConnector proves the intercept (decrypt-all) egress
// path is connector-aware: the upstream DialContext routes a connector-fronted host THROUGH the connector tunnel
// (bytes round-trip), and a non-fronted host dials via the base dialer unchanged.
func TestConnectorEgressDialContextRoutesInterceptOriginThroughConnector(t *testing.T) {
	manager := tunnel.NewManager()
	edgeRaw, connectorRaw := net.Pipe()
	defer edgeRaw.Close()
	defer connectorRaw.Close()
	session, _ := manager.Register("conn-tok", "tun-tok", tunnel.NewInProcessConn(edgeRaw, true))
	go session.Run()
	startFakeConnectorEcho(tunnel.NewInProcessConn(connectorRaw, false))

	baseCalled := false
	base := func(ctx context.Context, network, addr string) (net.Conn, error) {
		baseCalled = true
		return nopConn{}, nil
	}
	dial := edgeplane.ConnectorEgressDialContext(base, connectorDestinationResolver(newConnectorEgressTestRegistry(t, []string{"corp.internal"})), manager, "tenant-a", "", nil, nil, nil)

	// Connector-fronted origin -> through the connector tunnel, not the base dialer.
	conn, err := dial(context.Background(), "tcp", "host.corp.internal:443")
	if err != nil {
		t.Fatalf("dial through connector: %v", err)
	}
	defer conn.Close()
	if baseCalled {
		t.Fatal("a connector-fronted origin must NOT use the base dialer")
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, 4)
	if err := readFull(conn, got, 2*time.Second); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != "PING" {
		t.Fatalf("intercept-origin echo = %q, want PING", got)
	}

	// Non-fronted origin -> base dialer, unchanged.
	baseCalled = false
	if _, err := dial(context.Background(), "tcp", "www.example.com:443"); err != nil {
		t.Fatalf("base dial: %v", err)
	}
	if !baseCalled {
		t.Fatal("a non-fronted origin must use the base dialer")
	}
}

// TestConnectorEgressDialContextMeshRelaysViaPeerEdge proves the INTERCEPT path meshes identically to the bypass
// path: a mesh-eligible flow whose connector is in an in-boundary remote region relays through the peer-Edge
// link (not the base dialer), and bytes round-trip.
func TestConnectorEgressDialContextMeshRelaysViaPeerEdge(t *testing.T) {
	manager := tunnel.NewManager()
	edgeRaw, peerRaw := net.Pipe()
	defer edgeRaw.Close()
	defer peerRaw.Close()
	session, _ := manager.Register("peer-osaka", "tun-mesh", tunnel.NewInProcessConn(edgeRaw, true))
	go session.Run()
	startFakeConnectorEcho(tunnel.NewInProcessConn(peerRaw, false))

	reg := connector.NewRegistry()
	if _, err := reg.Register(model.ConnectorRegistration{
		ID: "c-osaka", TenantID: "tenant-a", Status: "active", PrivateBaseURL: "https://internal.invalid",
		EdgeRegionID: "jp-osaka", ReachableRoutes: model.ConnectorReachableRoutes{FQDNDomains: []string{"corp.internal"}},
	}, time.Date(2026, 6, 26, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("register: %v", err)
	}

	baseCalled := false
	base := func(ctx context.Context, network, addr string) (net.Conn, error) {
		baseCalled = true
		return nopConn{}, nil
	}
	dial := edgeplane.ConnectorEgressDialContext(base, connectorDestinationResolver(reg), tunnel.NewManager(), "tenant-a", "jp-tokyo",
		edgeplane.ResidencyResolver(func(string) []string { return []string{"jp-tokyo", "jp-osaka"} }),
		stubPeerEdges{region: "jp-osaka", session: session},
		func(string) bool { return true })

	conn, err := dial(context.Background(), "tcp", "host.corp.internal:443")
	if err != nil {
		t.Fatalf("mesh dial: %v", err)
	}
	defer conn.Close()
	if baseCalled {
		t.Fatal("a mesh flow must NOT use the base dialer")
	}
	if _, err := conn.Write([]byte("mesh")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, 4)
	if err := readFull(conn, got, 2*time.Second); err != nil {
		t.Fatalf("read echo through peer edge: %v", err)
	}
	if string(got) != "MESH" {
		t.Fatalf("intercept-path mesh echo = %q, want MESH", got)
	}
}

type nopConn struct{ nopReadWriteCloser }

func (nopConn) LocalAddr() net.Addr                { return nil }
func (nopConn) RemoteAddr() net.Addr               { return nil }
func (nopConn) SetDeadline(t time.Time) error      { return nil }
func (nopConn) SetReadDeadline(t time.Time) error  { return nil }
func (nopConn) SetWriteDeadline(t time.Time) error { return nil }

type nopReadWriteCloser struct{}

func (nopReadWriteCloser) Read([]byte) (int, error)    { return 0, io.EOF }
func (nopReadWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (nopReadWriteCloser) Close() error                { return nil }

func readFull(r io.Reader, buf []byte, timeout time.Duration) error {
	type res struct {
		err error
	}
	done := make(chan res, 1)
	go func() {
		_, err := io.ReadFull(r, buf)
		done <- res{err}
	}()
	select {
	case r := <-done:
		return r.err
	case <-time.After(timeout):
		return io.ErrNoProgress
	}
}
