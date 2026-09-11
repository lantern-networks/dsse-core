package main

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tunnel"
)

// An unavailable backend must not disconnect other applications on the same
// Connector. Exercise the production Edge dialer and Connector dispatcher with
// real TCP backend connections and the shared WebSocket frame transport.
func TestBackendRefusalPreservesConnectorAndOtherStreams(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		for {
			c, err := backend.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	unavailable, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	badPort := unavailable.Addr().(*net.TCPAddr).Port
	unavailable.Close()
	goodPort := backend.Addr().(*net.TCPAddr).Port

	transportListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer transportListener.Close()
	edgeRaw, err := net.Dial("tcp", transportListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer edgeRaw.Close()
	connectorRaw, err := transportListener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer connectorRaw.Close()
	manager := tunnel.NewManagerWithRequestTimeout(time.Second)
	session, _ := manager.Register("isolation", "shared", tunnel.NewInProcessConn(edgeRaw, true))
	go session.Run()
	dispatcher := newConnectorTunnelTCPDispatcher([]connectorTCPRoute{
		{ApplicationID: "127.0.0.1", Host: "127.0.0.1", Port: goodPort},
		{ApplicationID: "127.0.0.1", Host: "127.0.0.1", Port: badPort},
	}, connectorTCPNetDialer{}, time.Now)
	go handleConnectorTunnelConn(context.Background(), tunnel.NewInProcessConn(connectorRaw, false), "", dispatcher)
	dialer := edgeplane.ConnectorEgressDialer{
		Tunnels: manager, TenantID: "isolation-tenant",
		ResolveConnector: func(context.Context, string, string, string) (model.ConnectorRegistration, bool, error) {
			return model.ConnectorRegistration{ID: "isolation"}, true, nil
		},
	}
	open := func(port int) (io.ReadWriteCloser, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return dialer.OpenTCPConnection(ctx, edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "127.0.0.1", Port: port, TenantID: "isolation-tenant"})
	}
	// Keep the context alive for the lifetime of the established relay.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	existing, err := dialer.OpenTCPConnection(ctx, edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "127.0.0.1", Port: goodPort, TenantID: "isolation-tenant"})
	if err != nil {
		t.Fatal(err)
	}
	defer existing.Close()
	if _, err := open(badPort); err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("expected real backend connection refusal, got %v", err)
	}
	// The previously established stream must still exchange bytes after refusal.
	if conn, ok := existing.(net.Conn); ok {
		_ = conn.SetDeadline(time.Now().Add(time.Second))
	}
	if _, err := existing.Write([]byte("alive")); err != nil {
		t.Fatalf("existing stream after refusal: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(existing, buf); err != nil || string(buf) != "alive" {
		t.Fatalf("existing stream echo after refusal: %q, %v", buf, err)
	}
	next, err := dialer.OpenTCPConnection(ctx, edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "127.0.0.1", Port: goodPort, TenantID: "isolation-tenant"})
	if err != nil {
		t.Fatalf("new stream on same Connector after refusal: %v", err)
	}
	next.Close()
}
