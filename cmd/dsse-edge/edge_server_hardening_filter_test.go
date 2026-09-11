package main

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

// The filter exists to drop abandonment noise, and on 2026-08-02 it also dropped the only Edge-side trace of
// the Edge refusing its own fleet's renewed certificates. The dividing line under test: a handshake the EDGE
// decided to reject must reach the log; a handshake the client or the network abandoned must not.
func TestBenignConnErrorFilterKeepsEdgeDecisionsAndDropsAbandonment(t *testing.T) {
	capture := func(line string) string {
		var buf bytes.Buffer
		prev := log.Writer()
		log.SetOutput(&buf)
		defer log.SetOutput(prev)
		if _, err := (benignConnErrorFilter{}).Write([]byte(line + "\n")); err != nil {
			t.Fatal(err)
		}
		return buf.String()
	}

	mustPass := []string{
		// The 2026-08-02 line: the Edge turning away a device whose CA fell out of the pool.
		"http: TLS handshake error from 203.0.113.10:52704: tls: failed to verify client certificate: x509: certificate signed by unknown authority",
		"http: TLS handshake error from 203.0.113.10:52704: tls: client didn't provide a certificate",
		// The device refusing OUR certificate — the mirror image, equally an event.
		"http: TLS handshake error from 203.0.113.10:52704: remote error: tls: bad certificate",
		"http: panic serving 203.0.113.10:52704: runtime error",
	}
	for _, line := range mustPass {
		if got := capture(line); !strings.Contains(got, line) {
			t.Errorf("an Edge decision was swallowed by the benign filter:\n  %s", line)
		}
	}

	mustDrop := []string{
		"http: TLS handshake error from 10.0.0.9:1234: EOF",
		"http: TLS handshake error from 10.0.0.9:1234: read tcp 10.0.0.1:18543->10.0.0.9:1234: read: connection reset by peer",
		"http: TLS handshake error from 10.0.0.9:1234: read tcp 10.0.0.1:18543->10.0.0.9:1234: i/o timeout",
		"http: TLS handshake error from 10.0.0.9:1234: tls: first record does not look like a TLS handshake",
		"http: TLS handshake error from 10.0.0.9:1234: tls: client offered only unsupported versions: [302 301]",
		"http: connection reset by peer",
	}
	for _, line := range mustDrop {
		if got := capture(line); got != "" {
			t.Errorf("abandonment noise reached the log (quiet-at-INFO broken):\n  %s\n  logged: %s", line, got)
		}
	}
}
