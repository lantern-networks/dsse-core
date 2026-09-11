package main

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/tunnel"
)

func TestConnectorSessionRetirementDistinguishesTimeoutFromCallerCancellation(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		name := "unanswered_open"
		if canceled {
			name = "caller_canceled"
		}
		t.Run(name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			edgeRaw, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer edgeRaw.Close()
			peerRaw, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer peerRaw.Close()
			wait := 50 * time.Millisecond
			if canceled {
				wait = 2 * time.Second
			}
			manager := tunnel.NewManagerWithRequestTimeout(wait)
			session, _ := manager.Register("conn-tok", "shared", tunnel.NewInProcessConn(edgeRaw, true))
			go session.Run()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			peerDone := make(chan error, 1)
			peer := tunnel.NewInProcessConn(peerRaw, false)
			go func() {
				for {
					var frame tunnel.Frame
					if err := peer.ReadJSON(&frame); err != nil {
						peerDone <- err
						return
					}
					if frame.Type == tunnel.FrameTCPOpen && canceled {
						cancel()
					}
				}
			}()
			dialer := edgeplane.ConnectorEgressDialer{
				ResolveConnector: connectorDestinationResolver(newConnectorEgressTestRegistry(t, []string{"corp.internal"})),
				Tunnels:          manager, TenantID: "tenant-a",
			}
			_, err = dialer.OpenTCPConnection(ctx, edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "host.corp.internal", Port: 443, TenantID: "tenant-a"})
			if canceled {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("expected caller cancellation, got %v", err)
				}
				select {
				case err := <-peerDone:
					t.Fatalf("caller cancellation closed shared tunnel: %v", err)
				case <-time.After(50 * time.Millisecond):
				}
			} else {
				if !errors.Is(err, tunnel.ErrTCPOpenTimeout) {
					t.Fatalf("expected tunnel open timeout, got %v", err)
				}
				select {
				case <-peerDone:
				case <-time.After(time.Second):
					t.Fatal("unresponsive tunnel was not retired")
				}
			}
		})
	}
}
