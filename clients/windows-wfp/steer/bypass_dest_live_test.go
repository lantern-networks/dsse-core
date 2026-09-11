package main

import (
	"net/netip"
	"sync"
	"testing"
)

func ap(t *testing.T, s string) netip.AddrPort {
	t.Helper()
	v, err := netip.ParseAddrPort(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return v
}

func has(set []netip.AddrPort, want netip.AddrPort) bool {
	for _, d := range set {
		if d == want {
			return true
		}
	}
	return false
}

// ★★ THE REGRESSION (2026-08-18, measured on win-dev-1).
//
// The Edge destination -- the rule that stops the agent's own tunnel being steered into itself -- was resolved
// once, at arm time, into a slice the running backend could never be told about again. A UDP timeout during an
// MSI install was enough to miss it, and the box then ran with the guard absent for the whole life of the
// process, while refreshEdgePins repaired the DIAL pins sixty seconds later and reported success:
//
//	15:43:05  bypass_dests=[127.0.0.1:18090]                              <- armed without the Edge
//	15:45:01  Edge shinmac-mini... re-pinned -> [100.72.135.18:18543]      <- pins fine, rule set still wrong
//
// So the assertion is not "setEdge stores an address". It is that a resolution arriving AFTER arm time reaches
// the enforced set, which is the half that was missing.
func TestAnEdgeResolvedAfterArmTimeStillReachesTheGuard(t *testing.T) {
	base := []netip.AddrPort{ap(t, "127.0.0.1:18090"), ap(t, "203.0.113.10:22")}
	d := newLiveDests(base)

	// Arm time: resolution failed, so the Edge slot is empty. Everything configured is still enforced.
	armed := d.effective()
	if len(armed) != 2 || !has(armed, ap(t, "127.0.0.1:18090")) {
		t.Fatalf("the configured destinations must survive a failed Edge lookup: %v", armed)
	}
	if d.hasEdge() {
		t.Fatal("hasEdge is true with no Edge resolved, so a caller cannot tell the guard is missing")
	}

	// The backend arms and registers its updater.
	var mu sync.Mutex
	var pushed [][]netip.AddrPort
	d.register(func(now []netip.AddrPort) {
		mu.Lock()
		pushed = append(pushed, append([]netip.AddrPort(nil), now...))
		mu.Unlock()
	})

	// Sixty seconds later the refresher succeeds. THIS is what used to go nowhere.
	edge := ap(t, "100.72.135.18:18543")
	if !d.setEdge(edge) {
		t.Fatal("filling an empty Edge slot must report a change")
	}
	if !has(d.effective(), edge) {
		t.Fatalf("the late Edge resolution never reached the enforced set: %v", d.effective())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(pushed) != 1 {
		t.Fatalf("the backend was pushed %d times, want exactly 1 — without the push the kernel keeps the "+
			"arm-time rule set and nothing says so", len(pushed))
	}
	if !has(pushed[0], edge) || !has(pushed[0], ap(t, "203.0.113.10:22")) {
		t.Fatalf("the pushed set must carry the Edge AND the configured destinations: %v", pushed[0])
	}
}

// An A record that moves must move the rule, not add a second one. Leaving the old address enforced would keep
// a bypass for a host that is no longer the Edge — a hole that outlives the reason for it.
func TestAMovedEdgeReplacesTheRuleRatherThanAccumulating(t *testing.T) {
	d := newLiveDests([]netip.AddrPort{ap(t, "127.0.0.1:18090")})
	old, moved := ap(t, "100.72.135.18:18543"), ap(t, "100.72.135.99:18543")
	d.setEdge(old)
	if !d.setEdge(moved) {
		t.Fatal("moving the Edge must report a change")
	}
	got := d.effective()
	if has(got, old) {
		t.Fatalf("the previous Edge address is still bypassed: %v", got)
	}
	if !has(got, moved) || len(got) != 2 {
		t.Fatalf("want exactly the loopback plus the new Edge, got %v", got)
	}
}

// The steady state must be quiet. The refresher succeeds every sixty seconds and almost always finds the same
// answer; re-pushing a kernel policy on each of those, or logging it, would bury the transitions that matter.
func TestResolvingTheSameAddressAgainChangesNothing(t *testing.T) {
	d := newLiveDests(nil)
	edge := ap(t, "100.72.135.18:18543")
	d.setEdge(edge)
	pushes := 0
	d.register(func([]netip.AddrPort) { pushes++ })
	for i := 0; i < 5; i++ {
		if d.setEdge(edge) {
			t.Fatalf("re-resolving the same address reported a change on attempt %d", i+1)
		}
	}
	if pushes != 0 {
		t.Fatalf("the backend was pushed %d times for an unchanged set", pushes)
	}
}

// effectiveDests is the single read path. A consumer that reaches for cfg.bypassDests directly goes back to
// the arm-time snapshot, which is the defect; this pins that the accessor prefers the live set and still
// answers correctly on a config that has none.
func TestEffectiveDestsPrefersTheLiveSet(t *testing.T) {
	stale := []netip.AddrPort{ap(t, "10.0.0.1:443")}
	cfg := captureConfig{bypassDests: stale}
	if got := cfg.effectiveDests(); len(got) != 1 || got[0] != stale[0] {
		t.Fatalf("with no live set the static one must be used: %v", got)
	}
	cfg.dests = newLiveDests(stale)
	edge := ap(t, "100.72.135.18:18543")
	cfg.dests.setEdge(edge)
	got := cfg.effectiveDests()
	if !has(got, edge) {
		t.Fatalf("effectiveDests returned the arm-time snapshot, not the live set: %v", got)
	}
}
