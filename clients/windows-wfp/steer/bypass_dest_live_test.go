package main

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

func ap(t *testing.T, s string) netip.AddrPort {
	t.Helper()
	v, err := netip.ParseAddrPort(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return v
}

func TestEdgeRefreshPreservesActivePassthroughDestinations(t *testing.T) {
	d := newLiveDests([]netip.AddrPort{ap(t, "127.0.0.1:18090")})
	console := ap(t, "203.0.113.20:443")
	d.setPassthrough([]netip.AddrPort{console})
	var pushed []netip.AddrPort
	d.register(func(now []netip.AddrPort) { pushed = append([]netip.AddrPort(nil), now...) })
	edge := ap(t, "192.0.2.10:18543")
	d.setEdge(edge)
	if !has(pushed, console) || !has(pushed, edge) {
		t.Fatalf("Edge refresh dropped an active passthrough or Edge guard: %v", pushed)
	}
}

func TestConcurrentBypassRefreshCannotApplyAnOlderSnapshotLast(t *testing.T) {
	d := newLiveDests(nil)
	edge := ap(t, "192.0.2.10:18543")
	console := ap(t, "203.0.113.20:443")
	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	var mu sync.Mutex
	var applied []netip.AddrPort
	first := true
	d.register(func(now []netip.AddrPort) {
		mu.Lock()
		block := first
		first = false
		mu.Unlock()
		if block {
			close(firstEntered)
			<-releaseFirst
		}
		mu.Lock()
		applied = append([]netip.AddrPort(nil), now...)
		mu.Unlock()
	})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); d.setEdge(edge) }()
	select {
	case <-firstEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("first bypass apply did not begin")
	}
	wg.Add(1)
	go func() { defer wg.Done(); d.setPassthrough([]netip.AddrPort{console}) }()
	// Give the second refresh an opportunity to overtake the blocked callback.
	time.Sleep(30 * time.Millisecond)
	close(releaseFirst)
	wg.Wait()
	mu.Lock()
	got := append([]netip.AddrPort(nil), applied...)
	mu.Unlock()
	if !has(got, edge) || !has(got, console) {
		t.Fatalf("last applied bypass snapshot lost a concurrent update: %v", got)
	}
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

func TestAllPinnedEdgeAddressesReachLoopGuardAndRetiredAddressesLeave(t *testing.T) {
	d := newLiveDests([]netip.AddrPort{ap(t, "127.0.0.1:18090")})
	first := []netip.AddrPort{ap(t, "192.0.2.10:18543"), ap(t, "[2001:db8::10]:18543")}
	var applied [][]netip.AddrPort
	d.register(func(now []netip.AddrPort) {
		applied = append(applied, append([]netip.AddrPort(nil), now...))
	})
	if !d.setEdges(first) || !has(d.effective(), first[0]) || !has(d.effective(), first[1]) {
		t.Fatalf("not every round-robin Edge dial target was guarded: %v", d.effective())
	}
	if d.setEdges([]netip.AddrPort{first[1], first[0]}) {
		t.Fatal("reordered Edge answers must not republish the kernel policy")
	}
	if !d.setEdges([]netip.AddrPort{first[1]}) || has(d.effective(), first[0]) {
		t.Fatalf("retired Edge destination was not removed: %v", d.effective())
	}
	if len(applied) != 2 || !has(applied[0], first[0]) || !has(applied[0], first[1]) || has(applied[1], first[0]) {
		t.Fatalf("incorrect live backend publications: %v", applied)
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
