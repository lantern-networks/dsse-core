//go:build windows

package main

import (
	"strings"
	"testing"
)

// steer-all must capture both IPv4 and IPv6 outbound TCP and both loopback return paths, so the filter
// carries an IPv6 ::1 return clause in addition to the IPv4 127.0.0.1 one. Single-target stays IPv4-only.
func TestRedirectFilterIncludesIPv6ReturnForSteerAll(t *testing.T) {
	all := redirectFilter(captureConfig{localPort: 18099, steerAll: true})
	if !strings.Contains(all, "ip.SrcAddr == 127.0.0.1 and tcp.SrcPort == 18099") {
		t.Fatalf("steer-all filter missing IPv4 return clause: %q", all)
	}
	if !strings.Contains(all, "ipv6.SrcAddr == ::1 and tcp.SrcPort == 18099") {
		t.Fatalf("steer-all filter missing IPv6 return clause: %q", all)
	}
	if !strings.Contains(all, "outbound and loopback == 0 and tcp.DstPort != 53") {
		t.Fatalf("steer-all filter missing family-agnostic outbound clause: %q", all)
	}

	single := redirectFilter(captureConfig{localPort: 18099, targetIP: [4]byte{192, 168, 1, 63}, targetPort: 3389})
	if strings.Contains(single, "ipv6") {
		t.Fatalf("single-target filter should not include IPv6 (v4 terminator only): %q", single)
	}
}
