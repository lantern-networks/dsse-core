//go:build windows

package main

import (
	"sort"
	"testing"
)

func keysOf(entries []resolverEntry) []string {
	var k []string
	for _, e := range entries {
		k = append(k, e.IfIndex+"|"+e.Family)
	}
	sort.Strings(k)
	return k
}

// TestPlanConvergeWiredToWifi: wired (if31) was taken over and is now idle (no longer egress); Wi-Fi (if14)
// just became the default route on its real DNS. converge must take over if14 and restore if31.
func TestPlanConvergeWiredToWifi(t *testing.T) {
	loopFor := map[string]string{"IPv4": "127.0.0.1"}
	captured := map[string]resolverEntry{
		"31|IPv4": {IfIndex: "31", Family: "IPv4", Loopback: "127.0.0.1", Servers: "192.0.2.1"},
	}
	state := []ifaceDNS{
		{Family: "IPv4", IfIndex: "31", Servers: "127.0.0.1", Egress: false},  // wired now idle, still on loopback
		{Family: "IPv4", IfIndex: "14", Servers: "8.8.8.8", Egress: true},     // Wi-Fi now default route
		{Family: "IPv4", IfIndex: "20", Servers: "10.10.0.10", Egress: false}, // internal link, untouched
	}
	toLoopback, toRestore, keep := planConverge(state, loopFor, captured)

	if got := keysOf(toLoopback); len(got) != 1 || got[0] != "14|IPv4" {
		t.Fatalf("toLoopback = %v, want [14|IPv4]", got)
	}
	if got := keysOf(toRestore); len(got) != 1 || got[0] != "31|IPv4" {
		t.Fatalf("toRestore = %v, want [31|IPv4] (idle wired handed back its own DNS)", got)
	}
	if got := keysOf(keep); len(got) != 1 || got[0] != "14|IPv4" {
		t.Fatalf("keep = %v, want [14|IPv4] (only the active egress link tracked)", got)
	}
}

// TestPlanConvergeSteadyState: the egress interface already on loopback and an idle interface on its own DNS =>
// no DNS writes at all (quiet).
func TestPlanConvergeSteadyState(t *testing.T) {
	loopFor := map[string]string{"IPv4": "127.0.0.1", "IPv6": "::1"}
	captured := map[string]resolverEntry{
		"31|IPv4": {IfIndex: "31", Family: "IPv4", Loopback: "127.0.0.1", Servers: "192.0.2.1"},
		"31|IPv6": {IfIndex: "31", Family: "IPv6", Loopback: "::1", Servers: "240d:1a::1"},
	}
	state := []ifaceDNS{
		{Family: "IPv4", IfIndex: "31", Servers: "127.0.0.1", Egress: true},
		{Family: "IPv6", IfIndex: "31", Servers: "::1", Egress: true},
		{Family: "IPv4", IfIndex: "14", Servers: "8.8.8.8", Egress: false}, // idle Wi-Fi on its own DNS
	}
	toLoopback, toRestore, keep := planConverge(state, loopFor, captured)
	if len(toLoopback) != 0 || len(toRestore) != 0 {
		t.Fatalf("steady state should write nothing: toLoopback=%v toRestore=%v", keysOf(toLoopback), keysOf(toRestore))
	}
	if len(keep) != 2 {
		t.Fatalf("keep should track the 2 egress entries, got %v", keysOf(keep))
	}
}

// TestPlanConvergeFamilyWithoutListener: an IPv6 egress interface is ignored when only IPv4 is bound.
func TestPlanConvergeFamilyWithoutListener(t *testing.T) {
	loopFor := map[string]string{"IPv4": "127.0.0.1"} // IPv6 not bound
	state := []ifaceDNS{
		{Family: "IPv6", IfIndex: "31", Servers: "240d:1a::1", Egress: true},
		{Family: "IPv4", IfIndex: "31", Servers: "192.0.2.1", Egress: true},
	}
	toLoopback, _, keep := planConverge(state, loopFor, map[string]resolverEntry{})
	if got := keysOf(toLoopback); len(got) != 1 || got[0] != "31|IPv4" {
		t.Fatalf("toLoopback = %v, want only [31|IPv4]", got)
	}
	if got := keysOf(keep); len(got) != 1 || got[0] != "31|IPv4" {
		t.Fatalf("keep = %v, want only [31|IPv4]", got)
	}
}
