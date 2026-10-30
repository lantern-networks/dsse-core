package main

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/tunnel"
)

type meshCleanupDialer struct{ conn io.ReadWriteCloser }

func (d meshCleanupDialer) OpenTCPConnection(context.Context, edgeplane.NetworkExtensionRuntimeCopyTCPRoute) (io.ReadWriteCloser, error) {
	return d.conn, nil
}

type meshCleanupTransport struct {
	frame tunnel.Frame
	read  bool
}

func (c *meshCleanupTransport) ReadJSON(v any) error {
	if c.read {
		return io.EOF
	}
	c.read = true
	*(v.(*tunnel.Frame)) = c.frame
	return nil
}
func (*meshCleanupTransport) WriteJSON(any) error { return nil }
func (*meshCleanupTransport) Close() error        { return nil }

func TestMeshTransportFailureClosesOpenBackends(t *testing.T) {
	client, backend := net.Pipe()
	defer client.Close()
	defer backend.Close()
	frame, err := edgeplane.EdgeTCPOpenFrameForTarget("held", edgeplane.EdgeTCPConnectTarget{ApplicationID: "app", Host: "private.internal", Port: 443}, edgeplane.InteractiveEastWestEdgeTCPConnectLimits())
	if err != nil {
		t.Fatal(err)
	}
	transport := &meshCleanupTransport{frame: frame}
	if err := serveMeshIngressTunnel(context.Background(), transport, meshCleanupDialer{conn: client}, "tenant", nil); !errors.Is(err, io.EOF) {
		t.Fatalf("transport result: %v", err)
	}
	_ = backend.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := backend.Write([]byte("closed")); err == nil {
		t.Fatal("backend socket survived dead mesh link")
	}
}
