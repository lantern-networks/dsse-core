package main

import (
	"testing"

	"github.com/lantern-networks/dsse-core/edgeplane"
)

// The Edge is the WebSocket server to the intercepted client, so it must mint Sec-WebSocket-Accept itself; a
// wrong or empty value makes the client reject the 101 and the WS never opens (#28, the postman-echo repro).
// The RFC 6455 worked example pins the exact bytes.
func TestNetworkExtensionLabTLSWebSocketAcceptRFC6455Vector(t *testing.T) {
	const key = "dGhlIHNhbXBsZSBub25jZQ=="
	const want = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
	if got := edgeplane.NetworkExtensionLabTLSWebSocketAccept(key); got != want {
		t.Fatalf("Sec-WebSocket-Accept = %q, want %q (RFC 6455 §1.3)", got, want)
	}
	// Surrounding whitespace on the client key must not change the digest.
	if got := edgeplane.NetworkExtensionLabTLSWebSocketAccept("  " + key + "  "); got != want {
		t.Fatalf("whitespace-trimmed key gave %q, want %q", got, want)
	}
}
