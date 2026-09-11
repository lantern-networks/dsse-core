package main

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
)

// clientHelloFor builds a minimal TLS ClientHello carrying one server name, the way a browser's first bytes
// look after CONNECT 200.
func clientHelloFor(t *testing.T, name string) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		_ = tlsHandshakeAttempt(client, name)
	}()
	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("read ClientHello: %v", err)
	}
	_ = server.Close()
	return buf[:n]
}

// ★★★ A DESTINATION THIS NODE CANNOT REACH, WHOSE FLOW NAMES ITSELF. Measured on the generated deployment
// with interception off: the same IPv6 literal, with and without a name in the ClientHello, both closed with
// zero bytes — the name was never looked at, because reading it was wired behind the decision to decrypt.
func TestAnUnreachableLiteralIsFetchedByTheNameTheFlowCarries(t *testing.T) {
	// This node has no IPv6 egress — the whole premise. Forced, so the check runs on a dual-stack build host
	// too: a test that skips itself where the defect cannot occur is a test that never runs.
	restore := steerCanEgressIPv6
	steerCanEgressIPv6 = func() bool { return false }
	defer func() { steerCanEgressIPv6 = restore }()

	hello := clientHelloFor(t, "one.one.one.one")

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() { _, _ = client.Write(hello) }()

	route := edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "2606:4700:4700::1111", Port: 443}
	got, out := recoverTheDestinationName(server, route)
	if out.SNI != "one.one.one.one" {
		t.Fatalf("the name the flow carried was not recovered: %q", out.SNI)
	}
	if got == nil {
		t.Fatal("the client conn must come back so the peeked bytes can be replayed")
	}

	// ★ AND THE PEEKED BYTES ARE REPLAYED. Consuming the ClientHello and not putting it back breaks every
	// flow this is meant to rescue.
	buf := make([]byte, len(hello))
	_ = got.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := readFullish(got, buf)
	if err != nil || n != len(hello) {
		t.Fatalf("replay: read %d of %d bytes: %v", n, len(hello), err)
	}
}

// A destination this node CAN reach is not peeked at all: nothing is read, nothing is delayed.
func TestAReachableDestinationIsNotPeeked(t *testing.T) {
	restore := steerCanEgressIPv6
	steerCanEgressIPv6 = func() bool { return false }
	defer func() { steerCanEgressIPv6 = restore }()

	// An IPv4 literal is reachable from a node with no IPv6 egress, so nothing about it is unreachable.
	route := edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "93.184.216.34", Port: 443}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	// Nothing is ever written to this pipe. If the code peeked, it would block and the deadline below trips.
	done := make(chan edgeplane.NetworkExtensionRuntimeCopyTCPRoute, 1)
	go func() {
		_, out := recoverTheDestinationName(server, route)
		done <- out
	}()
	select {
	case out := <-done:
		if out.SNI != "" {
			t.Fatalf("a reachable destination must not be given a name: %q", out.SNI)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a reachable destination was peeked — every ordinary flow would pay for it")
	}
}

// A route that already carries a name is left alone.
func TestARouteThatAlreadyNamesItselfIsLeftAlone(t *testing.T) {
	route := edgeplane.NetworkExtensionRuntimeCopyTCPRoute{Host: "2606:4700:4700::1111", Port: 443, SNI: "already.example"}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan struct{})
	go func() {
		_, out := recoverTheDestinationName(server, route)
		if out.SNI != "already.example" {
			t.Errorf("the name was replaced: %q", out.SNI)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a route that already names itself must not be peeked")
	}
}

func tlsHandshakeAttempt(c net.Conn, name string) error {
	return tls.Client(c, &tls.Config{ServerName: name, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}).Handshake()
}

func readFullish(c net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
