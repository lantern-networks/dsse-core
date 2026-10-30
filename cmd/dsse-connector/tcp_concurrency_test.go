package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/tunnel"
)

type concurrencyTestTCPDialer struct{ calls int }

func (d *concurrencyTestTCPDialer) OpenTCPConnection(ctx context.Context, route connectorTCPRoute) (io.ReadWriteCloser, error) {
	d.calls++
	return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(route.Host, strconv.Itoa(route.Port)))
}

// Keep the sockets open together: a burst of short requests can hide the old
// 32-stream limit by completing earlier requests before the 33rd is admitted.
func TestConnectorHoldsMoreThan32StreamsWithProductionEdgeLimits(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var servers sync.WaitGroup
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			servers.Add(1)
			go func() {
				defer servers.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	registry := tunnel.NewTCPConnectionRegistry()
	backendDialer := &concurrencyTestTCPDialer{}
	dialer := &connectorTCPAdmission{base: backendDialer}
	address := listener.Addr().(*net.TCPAddr)
	target := edgeplane.EdgeTCPConnectTarget{ApplicationID: "held-app", Host: "127.0.0.1", Port: address.Port}
	routes := []connectorTCPRoute{{ApplicationID: target.ApplicationID, Host: target.Host, Port: target.Port}}
	var handlers []*connectorTCPConnectionHandler
	defer func() {
		for _, handler := range handlers {
			_, _ = handler.Close(tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonEOF, time.Now())
		}
		_ = listener.Close()
		<-accepted
		servers.Wait()
	}()
	for i := 0; i < 64; i++ {
		frame, err := edgeplane.EdgeTCPOpenFrameForTarget(fmt.Sprintf("held-%d", i), target, edgeplane.InteractiveEastWestEdgeTCPConnectLimits())
		if err != nil {
			t.Fatal(err)
		}
		response, handler := handleTunnelTCPOpenConnection(context.Background(), frame, routes, dialer, registry, time.Now())
		if response.Error != "" || handler == nil {
			t.Fatalf("held stream %d rejected: %s", i+1, response.Error)
		}
		handlers = append(handlers, handler)
	}
	if registry.Count() != 64 || backendDialer.calls != 64 || dialer.snapshot()["active"] != 64 {
		t.Fatalf("active=%d dials=%d, want 64 sockets held together", registry.Count(), backendDialer.calls)
	}
	for _, handler := range handlers {
		frame, err := tunnel.NewTCPDataFrame(handler.requestID, tunnel.TCPDirectionUp, []byte("alive"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := handler.WriteFrame(frame, time.Now()); err != nil {
			t.Fatal(err)
		}
		var response [5]byte
		if _, err := io.ReadFull(handler.conn, response[:]); err != nil || string(response[:]) != "alive" {
			t.Fatalf("held stream cannot exchange bytes: %q, %v", response, err)
		}
	}
	// More capacity must not bypass the Connector's independent route check.
	denied, err := edgeplane.EdgeTCPOpenFrameForTarget("denied", edgeplane.EdgeTCPConnectTarget{ApplicationID: target.ApplicationID, Host: "127.0.0.2", Port: target.Port}, edgeplane.InteractiveEastWestEdgeTCPConnectLimits())
	if err != nil {
		t.Fatal(err)
	}
	response, handler := handleTunnelTCPOpenConnection(context.Background(), denied, routes, dialer, registry, time.Now())
	if response.Error == "" || handler != nil || registry.Count() != 64 || backendDialer.calls != 64 {
		t.Fatal("unauthorized destination changed the active streams or reached the dialer")
	}
	for _, handler := range handlers {
		if _, err := handler.Close(tunnel.TCPDirectionLocal, tunnel.TCPCloseReasonEOF, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	handlers = nil
	if registry.Count() != 0 || dialer.snapshot()["active"] != 0 {
		t.Fatalf("active streams after close=%d, want 0", registry.Count())
	}
}
