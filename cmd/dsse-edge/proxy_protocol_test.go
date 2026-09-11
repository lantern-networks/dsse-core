package main

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// serveOneThroughProxyListener opens a real TCP listener with the given trusted set, writes wire to it from a
// real client, and returns what the Edge side sees: the address it believes the peer has, and the bytes that
// remain to be handed to TLS.
func serveOneThroughProxyListener(t *testing.T, trusted string, wire string) (remote string, payload string) {
	t.Helper()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer raw.Close()
	ln := newProxyProtocolListener(raw, parseTrustedFrontDoors(trusted))

	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := net.Dial("tcp", raw.Addr().String())
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.WriteString(c, wire)
		// Hold the connection open until the server has read; closing immediately can race the read.
		time.Sleep(200 * time.Millisecond)
	}()

	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	<-done
	return conn.RemoteAddr().String(), string(buf[:n])
}

// TestProxyProtocolRecoversTheDeviceAddressFromATrustedFrontDoor is the reason the code exists: behind an L4
// front door every connection arrives from the front door, and the device's address has to come back.
func TestProxyProtocolRecoversTheDeviceAddressFromATrustedFrontDoor(t *testing.T) {
	remote, payload := serveOneThroughProxyListener(t, "127.0.0.1",
		"PROXY TCP4 203.0.113.9 10.1.0.4 5555 8443\r\nHELLO-TLS")
	if remote != "203.0.113.9:5555" {
		t.Fatalf("the device's address did not survive the front door: remote=%s", remote)
	}
	if payload != "HELLO-TLS" {
		t.Fatalf("the header was consumed but the connection was damaged: payload=%q", payload)
	}
}

// TestProxyProtocolRefusesToBelieveAnUntrustedPeer is the guard. Without it, anyone reaching the transport
// port could choose their own source address, and every per-address decision — rate limiting first — would be
// theirs to set. The header must stay unread, which means TLS then sees it as garbage and the handshake fails.
func TestProxyProtocolRefusesToBelieveAnUntrustedPeer(t *testing.T) {
	// The client is 127.0.0.1; the trusted front door is somewhere else entirely.
	remote, payload := serveOneThroughProxyListener(t, "198.51.100.7",
		"PROXY TCP4 203.0.113.9 10.1.0.4 5555 8443\r\nHELLO-TLS")
	if strings.HasPrefix(remote, "203.0.113.9") {
		t.Fatalf("an untrusted peer chose its own source address: remote=%s", remote)
	}
	if !strings.HasPrefix(remote, "127.0.0.1:") {
		t.Fatalf("expected the peer's real address, got %s", remote)
	}
	if !strings.HasPrefix(payload, "PROXY ") {
		t.Fatalf("the header was consumed for an untrusted peer; TLS would never see it: payload=%q", payload)
	}
}

// TestProxyProtocolWithNoFrontDoorDeclaredReadsNoHeader — the empty flag must mean "never read one", not
// "read one from anyone".
func TestProxyProtocolWithNoFrontDoorDeclaredReadsNoHeader(t *testing.T) {
	remote, payload := serveOneThroughProxyListener(t, "",
		"PROXY TCP4 203.0.113.9 10.1.0.4 5555 8443\r\nHELLO-TLS")
	if strings.HasPrefix(remote, "203.0.113.9") {
		t.Fatalf("an empty trusted list was read as 'trust anyone': remote=%s", remote)
	}
	if !strings.HasPrefix(payload, "PROXY ") {
		t.Fatalf("a header was consumed with no front door declared: payload=%q", payload)
	}
}

// TestProxyProtocolTrustedPeerWithoutAHeaderIsUndamaged — a trusted address is not required to send one, and
// a connection that does not must not lose its first bytes.
func TestProxyProtocolTrustedPeerWithoutAHeaderIsUndamaged(t *testing.T) {
	remote, payload := serveOneThroughProxyListener(t, "127.0.0.0/8", "\x16\x03\x01HELLO-TLS")
	if !strings.HasPrefix(remote, "127.0.0.1:") {
		t.Fatalf("expected the peer's own address, got %s", remote)
	}
	if payload != "\x16\x03\x01HELLO-TLS" {
		t.Fatalf("bytes were eaten looking for a header that was not there: payload=%q", payload)
	}
}

// TestProxyProtocolUnknownKeepsTheFrontDoorsAddress — "UNKNOWN" is the front door admitting it does not know.
// Keeping its address is honest; inventing one is not.
func TestProxyProtocolUnknownKeepsTheFrontDoorsAddress(t *testing.T) {
	remote, payload := serveOneThroughProxyListener(t, "127.0.0.1", "PROXY UNKNOWN\r\nHELLO-TLS")
	if !strings.HasPrefix(remote, "127.0.0.1:") {
		t.Fatalf("expected the front door's own address for UNKNOWN, got %s", remote)
	}
	if payload != "HELLO-TLS" {
		t.Fatalf("UNKNOWN header not consumed cleanly: payload=%q", payload)
	}
}

func TestParseProxyProtocolV1RejectsMalformedHeaders(t *testing.T) {
	for _, line := range []string{
		"PROXY TCP4 203.0.113.9 10.1.0.4 5555",         // too few fields
		"PROXY TCP4 not-an-ip 10.1.0.4 5555 8443",      // source is not an address
		"PROXY TCP4 203.0.113.9 10.1.0.4 99999 8443",   // port out of range
		"PROXY TCP9 203.0.113.9 10.1.0.4 5555 8443",    // family this does not speak
		"NOTPROXY TCP4 203.0.113.9 10.1.0.4 5555 8443", // not a header at all
	} {
		if got := parseProxyProtocolV1(line); got != nil {
			t.Fatalf("accepted a malformed header %q as %s", line, got)
		}
	}
}
