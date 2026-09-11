package edgeplane

import (
	"testing"
)

// A regression guard for the connect-by-IP egress bug. When route.Host is an IP literal — IPv6 especially —
// and an SNI was obtained, the base dialer must dial the SNI HOSTNAME rather than the original address, so
// the resolver and happy-eyeballs can fall back to a family that is reachable. With no SNI, or a Host that is
// already a hostname, Host is used as before.
func TestNetworkExtensionRuntimeCopyDialHost(t *testing.T) {
	cases := []struct {
		name  string
		route NetworkExtensionRuntimeCopyTCPRoute
		want  string
	}{
		{
			name:  "ipv6 literal with SNI re-resolves to SNI hostname",
			route: NetworkExtensionRuntimeCopyTCPRoute{Host: "2404:6800:400b:c00e::5e", Port: 443, SNI: "www.example.com"},
			want:  "www.example.com",
		},
		{
			name:  "ipv4 literal with SNI re-resolves to SNI hostname",
			route: NetworkExtensionRuntimeCopyTCPRoute{Host: "93.184.216.34", Port: 443, SNI: "www.example.com"},
			want:  "www.example.com",
		},
		{
			name:  "ip literal without SNI keeps the literal",
			route: NetworkExtensionRuntimeCopyTCPRoute{Host: "2404:6800:400b:c00e::5e", Port: 443},
			want:  "2404:6800:400b:c00e::5e",
		},
		{
			name:  "hostname route keeps the hostname even when SNI present",
			route: NetworkExtensionRuntimeCopyTCPRoute{Host: "origin.example.net", Port: 443, SNI: "www.example.com"},
			want:  "origin.example.net",
		},
		{
			name:  "blank SNI keeps the literal",
			route: NetworkExtensionRuntimeCopyTCPRoute{Host: "93.184.216.34", Port: 443, SNI: "   "},
			want:  "93.184.216.34",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := networkExtensionRuntimeCopyDialHost(tc.route); got != tc.want {
				t.Fatalf("networkExtensionRuntimeCopyDialHost(%+v) = %q, want %q", tc.route, got, tc.want)
			}
		})
	}
}
