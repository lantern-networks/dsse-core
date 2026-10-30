package edgeplane

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func resourceTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, e := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	accepted := make(chan *net.TCPConn, 1)
	go func() {
		c, e := ln.AcceptTCP()
		if e == nil {
			accepted <- c
		}
	}()
	c, e := net.DialTCP("tcp", nil, ln.Addr().(*net.TCPAddr))
	if e != nil {
		t.Fatal(e)
	}
	select {
	case peer := <-accepted:
		t.Cleanup(func() { c.Close(); peer.Close() })
		return c, peer
	case <-time.After(time.Second):
		c.Close()
		t.Fatal("loopback pair did not connect")
		return nil, nil
	}
}

func TestDefaultHalfCloseCleanupDoesNotDependOnTheHealthyIdleQuota(t *testing.T) {
	const name = "DSSE_NE_ABANDONED_HALF_CLOSE_LINGER_MILLISECONDS"
	t.Setenv(name, "")
	for _, idle := range []time.Duration{0, time.Minute, 48 * time.Hour} {
		if networkExtensionRuntimeCopyTunnelHalfCloseLinger(idle) != 22500*time.Millisecond {
			t.Fatal("former cleanup default changed with the data idle quota")
		}
	}
	t.Setenv(name, "60")
	for _, withRequest := range []bool{false, true} {
		t.Run(map[bool]string{false: "abandoned", true: "reply-pending"}[withRequest], func(t *testing.T) {
			client, clientBridge := resourceTCPPair(t)
			upstreamBridge, server := resourceTCPPair(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{})
			go func() {
				bridgeNetworkExtensionRuntimeCopyTunnelWithIdleTimeout(ctx, clientBridge, upstreamBridge, 0)
				close(done)
			}()
			if withRequest {
				if _, e := client.Write([]byte("q")); e != nil {
					t.Fatal(e)
				}
				b := make([]byte, 1)
				if _, e := io.ReadFull(server, b); e != nil {
					t.Fatal(e)
				}
			}
			if e := client.CloseWrite(); e != nil {
				t.Fatal(e)
			}
			if !withRequest {
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("zero-byte half-close leaked with default healthy idle=0")
				}
				return
			}
			select {
			case <-done:
				t.Fatal("a sent request awaiting its response was reaped")
			case <-time.After(180 * time.Millisecond):
			}
			if _, e := server.Write([]byte("reply")); e != nil {
				t.Fatal(e)
			}
			client.SetReadDeadline(time.Now().Add(time.Second))
			b := make([]byte, 5)
			if _, e := io.ReadFull(client, b); e != nil || string(b) != "reply" {
				t.Fatal("delayed response was cut", e)
			}
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("bridge did not clean up on cancellation")
			}
		})
	}
}
