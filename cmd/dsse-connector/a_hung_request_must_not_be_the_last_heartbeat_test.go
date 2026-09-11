package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// ★★★ ONE REQUEST WITH NO DEADLINE STOPPED THE HEARTBEAT FOR EVER, IN SILENCE (2026-09-07).
//
// Measured on a three-region lab with twenty connectors: every site read "0 online, health down" while every
// connector was running with a healthy tunnel, and not one heartbeat failure had been logged. The client had a
// Transport and no Timeout — http.DefaultTransport bounds the dial and the TLS handshake and nothing after
// them — and the heartbeat loop calls it synchronously, so a request that connects and never answers is not a
// missed heartbeat but the LAST one. Nothing errors, so nothing is logged; the process stays up, the tunnel
// stays up, and the deployment cannot tell that connector from one that has gone.
//
// These pin the bound rather than the number: a hung server must produce an ERROR in bounded time.

func TestAHungEdgeDoesNotStopTheHeartbeatForEver(t *testing.T) {
	// A server that accepts, reads, and never answers — the shape of a door that went away mid-request.
	//
	// ★ THE HANDLER IS RELEASED BY THE TEST, NOT BY THE CLIENT GIVING UP. httptest.Server.Close waits for
	// outstanding handlers, and a handler parked on the REQUEST's context does not necessarily wake when the
	// client times out — so the first version of this test hung in its own teardown for seven minutes and
	// looked exactly like the defect it was written to catch. Defers run last-in-first-out, so `stop` closes
	// before Close is called.
	stop := make(chan struct{})
	hung := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-stop:
		case <-r.Context().Done():
		}
	}))
	defer hung.Close()
	defer close(stop)

	client := newConnectorEdgeHTTPClient(nil)
	if client.Timeout <= 0 {
		t.Fatal("the connector's Edge client has no overall timeout: a response that never arrives blocks the " +
			"heartbeat loop for the life of the process, and the silence is indistinguishable from health")
	}
	// Shortened for the test — the property under test is that the deadline EXISTS and is applied to the whole
	// request, not the specific value.
	client.Timeout = 300 * time.Millisecond

	done := make(chan error, 1)
	go func() {
		done <- sendHeartbeat(client, hung.URL, "conn-test", "secret", "tenant_test", "", "", false, nil)
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a server that never answered returned no error, so the loop would treat it as a delivered heartbeat")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the heartbeat did not come back: this is the defect — the loop is now blocked for ever, no " +
			"error is logged, and every site behind this connector reads as down while its tunnel is fine")
	}
}

// A door that accepts the TCP connection and then says nothing at all — no HTTP response, not even headers.
// This is closer still to a black-holed region, and the transport's TLS/dial deadlines do not cover it.
func TestASilentSocketDoesNotStopTheHeartbeatForEver(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	// Accepted and held open, never written to. Closed by the listener shutting down at the end of the test
	// rather than by a defer inside the loop, which would never run.
	var held []net.Conn
	var mu sync.Mutex
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			mu.Lock()
			held = append(held, conn)
			mu.Unlock()
		}
	}()
	defer func() {
		mu.Lock()
		for _, c := range held {
			_ = c.Close()
		}
		mu.Unlock()
	}()

	client := newConnectorEdgeHTTPClient(nil)
	client.Timeout = 300 * time.Millisecond
	done := make(chan error, 1)
	go func() {
		done <- sendHeartbeat(client, "http://"+ln.Addr().String(), "conn-test", "secret", "tenant_test", "", "", false, nil)
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a socket that answered nothing returned no error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a silent socket blocked the heartbeat past its deadline")
	}
}

// And the deadline is on the client the connector actually builds for the Edge, in both modes — a timeout
// present only on the plaintext path would leave every production connector exactly as it was.
func TestBothEdgeClientsCarryTheDeadline(t *testing.T) {
	if c := newConnectorEdgeHTTPClient(nil); c.Timeout != connectorEdgeRequestTimeout {
		t.Fatalf("dev-mode client timeout = %v, want %v", c.Timeout, connectorEdgeRequestTimeout)
	}
	dir := t.TempDir()
	certPath, _ := writeSelfSigned(t, dir, "edge.example")
	cfg, err := buildConnectorTLSConfig(connectorTransportConfig{EdgeCAFile: certPath, DevMode: true})
	if err != nil {
		t.Fatalf("build tls config: %v", err)
	}
	if c := newConnectorEdgeHTTPClient(cfg); c.Timeout != connectorEdgeRequestTimeout {
		t.Fatalf("TLS client timeout = %v, want %v", c.Timeout, connectorEdgeRequestTimeout)
	}
}
