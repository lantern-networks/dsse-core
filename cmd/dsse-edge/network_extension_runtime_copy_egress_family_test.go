package main

import (
	"testing"

	"github.com/lantern-networks/dsse-core/edgeplane"
)

// The egress dial network adapts to the Edge's IPv6 capability: dual-stack stays "tcp" (native IPv6),
// a single-stack Edge uses "tcp4" so a dual-stack name is not stalled on IPv6 first, and an IPv6 literal
// with no name on a single-stack Edge is flagged unreachable so the caller fails fast.
func TestDialNetworkForEgress(t *testing.T) {
	cases := []struct {
		name        string
		hasIPv6     bool
		dialHost    string
		wantNet     string
		wantUnreach bool
	}{
		{"dual-stack name -> native dual-stack", true, "rr.example.com", "tcp", false},
		{"dual-stack ipv6 literal -> native", true, "2606:4700::1111", "tcp", false},
		{"single-stack name -> ipv4 only", false, "rr.example.com", "tcp4", false},
		{"single-stack ipv4 literal -> ipv4 only", false, "203.0.113.7", "tcp4", false},
		{"single-stack ipv6 literal -> unreachable", false, "2606:4700::1111", "tcp4", true},
		{"single-stack ipv6 literal padded -> unreachable", false, "  2001:db8::5 ", "tcp4", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotNet, gotUnreach := edgeplane.DialNetworkForEgress(c.hasIPv6, c.dialHost)
			if gotNet != c.wantNet || gotUnreach != c.wantUnreach {
				t.Fatalf("edgeplane.DialNetworkForEgress(%v, %q) = (%q, %v), want (%q, %v)",
					c.hasIPv6, c.dialHost, gotNet, gotUnreach, c.wantNet, c.wantUnreach)
			}
		})
	}
}
