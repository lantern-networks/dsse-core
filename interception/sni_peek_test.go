package interception

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

// The SNI must be extractable from a ClientHello written by a real tls.Client. This is what lets an
// interception decision be made by hostname even on an IP connection, and it is the durable answer to Chrome
// connecting by address.
func TestPeekNetworkExtensionLabTLSClientHelloSNIExtractsServerName(t *testing.T) {
	for _, host := range []string{"accounts.google.com", "login.microsoftonline.com", "a.io"} {
		clientConn, serverConn := net.Pipe()
		go func() {
			tlsClient := tls.Client(clientConn, &tls.Config{ServerName: host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
			_ = tlsClient.Handshake() // no ServerHello comes back, but the ClientHello is sent
			_ = tlsClient.Close()
		}()
		_ = serverConn.SetReadDeadline(time.Now().Add(3 * time.Second))
		sni, buffered, err := PeekClientHelloSNI(serverConn)
		_ = serverConn.Close()
		_ = clientConn.Close()
		if err != nil {
			t.Fatalf("peek(%q): %v", host, err)
		}
		if sni != host {
			t.Fatalf("peek(%q) sni = %q, want %q", host, sni, host)
		}
		// buffered is the raw bytes read (the ClientHello) and must be replayable.
		if len(buffered) < 5 || buffered[0] != 0x16 {
			t.Fatalf("peek(%q) buffered is not a TLS handshake record: %v", host, buffered[:min(5, len(buffered))])
		}
	}
}

func TestPeekNetworkExtensionLabTLSClientHelloSNIRejectsNonHandshake(t *testing.T) {
	// Bytes that are not a handshake are not a ClientHello, and what was read is kept.
	r := bytes.NewReader([]byte{0x17, 0x03, 0x03, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'})
	sni, buffered, err := PeekClientHelloSNI(r)
	if err != errNotClientHello {
		t.Fatalf("err = %v, want errNotClientHello", err)
	}
	if sni != "" {
		t.Fatalf("sni = %q, want empty", sni)
	}
	if len(buffered) != 5 {
		t.Fatalf("buffered len = %d, want 5 (the record header)", len(buffered))
	}
}

func TestPeekNetworkExtensionLabTLSClientHelloSNIShortReadReturnsBuffered(t *testing.T) {
	// A record that declares a length and never delivers a body returns what was read in buffered, and errors.
	r := io.MultiReader(bytes.NewReader([]byte{0x16, 0x03, 0x01, 0x00, 0x10}), bytes.NewReader([]byte{0x01, 0x02}))
	_, buffered, err := PeekClientHelloSNI(r)
	if err == nil {
		t.Fatal("expected short-read error")
	}
	if len(buffered) == 0 {
		t.Fatal("buffered must retain read bytes for replay")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
