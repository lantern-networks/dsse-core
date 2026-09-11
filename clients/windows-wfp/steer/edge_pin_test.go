//go:build windows

package main

import (
	"sync/atomic"
	"testing"
)

func TestTransportHostIsName(t *testing.T) {
	cases := []struct {
		serverName string
		enabled    bool
		want       bool
	}{
		{"203.0.113.10", true, false},      // IPv4 literal
		{"2606:4700::1", true, false},      // IPv6 literal
		{"edge.example.com", true, true},   // hostname -> needs pinning
		{"edge.example.com", false, false}, // transport disabled
		{"", true, false},                  // empty
	}
	for _, c := range cases {
		tc := transportConfig{enabled: c.enabled, serverName: c.serverName}
		if got := transportHostIsName(tc); got != c.want {
			t.Errorf("transportHostIsName(%q, enabled=%v) = %v, want %v", c.serverName, c.enabled, got, c.want)
		}
	}
}

func TestDialTargetUsesPinsRoundRobin(t *testing.T) {
	// No pins => dial the host verbatim.
	tc := transportConfig{host: "edge.example.com:18543", serverName: "edge.example.com"}
	if got := tc.dialTarget(); got != "edge.example.com:18543" {
		t.Fatalf("no pins: dialTarget = %q, want host verbatim", got)
	}
	// With pins => round-robin across them.
	pins := &atomic.Pointer[[]string]{}
	addrs := []string{"10.0.0.1:18543", "10.0.0.2:18543"}
	pins.Store(&addrs)
	tc.pins = pins
	seen := map[string]bool{}
	for i := 0; i < 6; i++ {
		seen[tc.dialTarget()] = true
	}
	if !seen["10.0.0.1:18543"] || !seen["10.0.0.2:18543"] {
		t.Fatalf("dialTarget did not round-robin across both pins: saw %v", seen)
	}
	if seen["edge.example.com:18543"] {
		t.Fatal("dialTarget returned the hostname even though pins are set")
	}
}

func TestResolveEdgeEndpointsLocalhost(t *testing.T) {
	// localhost is a deterministic, network-free resolution that exercises the real resolve path.
	tc := transportConfig{enabled: true, host: "localhost:18543", serverName: "localhost"}
	addrs, err := resolveEdgeEndpoints(tc, true, nil)
	if err != nil {
		t.Fatalf("resolveEdgeEndpoints(localhost): %v", err)
	}
	found := false
	for _, a := range addrs {
		if a == "127.0.0.1:18543" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected 127.0.0.1:18543 among %v", addrs)
	}
}

func TestSameStrings(t *testing.T) {
	if !sameStrings([]string{"a", "b"}, []string{"a", "b"}) {
		t.Fatal("equal slices reported different")
	}
	if sameStrings([]string{"a"}, []string{"a", "b"}) {
		t.Fatal("different-length slices reported equal")
	}
	if sameStrings([]string{"a", "b"}, []string{"a", "c"}) {
		t.Fatal("different slices reported equal")
	}
}
