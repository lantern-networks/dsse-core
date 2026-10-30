package main

import "testing"

func TestPinnedEdgeDestinationsRequireEntireValidDialSet(t *testing.T) {
	addrs, ok := parsePinnedEdgeDestinations([]string{
		"192.0.2.10:18543", "[2001:db8::10]:18543", "192.0.2.10:18543",
	})
	if !ok || len(addrs) != 2 || addrs[0].String() != "192.0.2.10:18543" || addrs[1].String() != "[2001:db8::10]:18543" {
		t.Fatalf("multi-address pins parsed as %v, valid=%v", addrs, ok)
	}
	for _, invalid := range []string{"edge.example:18543", "192.0.2.11:0", "[fe80::1%eth0]:18543"} {
		if got, ok := parsePinnedEdgeDestinations([]string{"192.0.2.10:18543", invalid}); ok || got != nil {
			t.Fatalf("invalid second pin %q published a partial guard %v", invalid, got)
		}
	}
}
