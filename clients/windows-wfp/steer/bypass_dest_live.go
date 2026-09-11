// bypass_dest_live.go — the live, concurrency-safe set of never-steer DESTINATIONS shared between the Edge
// pin refresher and the active capture backend. Portable Go (no build tag) so the rule unit-tests anywhere.
//
// ★★ WHY THIS EXISTS (2026-08-18, measured on win-dev-1). The destination that stops the agent's own tunnel
// from being steered into itself was resolved ONCE, while arming. When that single resolution failed -- a UDP
// timeout during an MSI install was enough -- the capture armed without it and stayed that way for the life
// of the process:
//
//	15:43:05  steer_capture ... bypass_dests=[127.0.0.1:18090]              <- Edge missing
//	15:45:01  steer: Edge shinmac-mini... re-pinned -> [100.72.135.18:18543] <- dial pins repaired
//	          (bypass_dests never changed again)
//
// refreshEdgePins already re-resolves every 60s, but it only repaired the DIAL target; the kernel rule set was
// built at arm time from a slice nobody could update afterwards. So a momentary DNS blink cost a safety rule
// permanently, and the only thing that ever said so was one warning line at startup.
//
// The shape mirrors liveExclusions deliberately, including registering the backend's updater, so the two
// live-config paths behave the same way under a supervisor restart rather than each inventing their own.
package main

import (
	"net/netip"
	"sync"
)

// liveDests is a fixed base set plus ONE replaceable Edge slot.
//
// The split is the point. The base -- packaged --bypass-dest entries, the profile's, the local mux -- is
// decided once and does not move. The Edge entry is the only one derived from a name that can resolve late,
// resolve differently, or fail; modelling it as its own slot is what lets a later resolution fill or correct
// it without disturbing anything an operator configured.
type liveDests struct {
	mu   sync.Mutex
	base []netip.AddrPort
	edge *netip.AddrPort // nil until resolved; nil is the honest state, not an empty rule
	// passthrough are the addresses of the deployment's own PASSTHROUGH DOMAINS -- the names the profile says
	// must reach the customer's network untouched, its own Console above all.
	//
	// ★★★ WINDOWS WAS NOT READING THEM AT ALL (2026-08-31). The Console reached 502 from a steered box while
	// the same profile, on macOS, reached 200 -- and the profile carried the domains correctly the whole
	// time. The same shape as steer_exclusions the day before: the document is right and one platform never
	// looks at it. A steered administrator could not open the Console of the deployment they were steering.
	//
	// ★ THEY LIVE HERE, AS ADDRESSES, ON PURPOSE. A name-shaped exception does not match a client that
	// resolves the name itself and connects by address -- which every browser and every ssh does. The capture
	// classifies flows by destination, so the names have to be resolved out of band and held as addresses.
	// And because an address-shaped exception stops matching the moment a family is added, every family the
	// name answers with is kept, not just the first.
	passthrough []netip.AddrPort
	onApply     func([]netip.AddrPort) // the active backend's live updater (wfp: re-push the kernel policy)
}

func newLiveDests(base []netip.AddrPort) *liveDests {
	return &liveDests{base: append([]netip.AddrPort(nil), base...)}
}

// effective is the set the backend should enforce right now. Backends call it at (re)creation too, so a
// supervisor-recreated capture never reverts to a set that predates the last successful Edge resolution.
func (l *liveDests) effective() []netip.AddrPort {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := append([]netip.AddrPort(nil), l.base...)
	if l.edge != nil {
		out = append(out, *l.edge)
	}
	out = append(out, l.passthrough...)
	return out
}

// register installs the active backend's updater; the latest (post-restart) backend replaces the previous.
func (l *liveDests) register(fn func([]netip.AddrPort)) {
	l.mu.Lock()
	l.onApply = fn
	l.mu.Unlock()
}

// setEdge records the resolved Edge endpoint and pushes the new set to the backend. It returns whether
// anything changed, so the caller can log a transition (absent -> present, or moved) and stay quiet on the
// sixty-second heartbeat that finds the same answer.
//
// onApply runs OUTSIDE the lock: it issues a kernel IOCTL, and holding a mutex across that would let a slow
// driver call block effective() on the arm path.
func (l *liveDests) setEdge(ap netip.AddrPort) (changed bool) {
	l.mu.Lock()
	if l.edge != nil && *l.edge == ap {
		l.mu.Unlock()
		return false
	}
	cp := ap
	l.edge = &cp
	fn := l.onApply
	out := append([]netip.AddrPort(nil), l.base...)
	out = append(out, cp)
	l.mu.Unlock()
	if fn != nil {
		fn(out)
	}
	return true
}

// hasEdge reports whether the Edge destination is currently enforced. Used to say out loud, once, that the
// guard was missing and has now been filled.
func (l *liveDests) hasEdge() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.edge != nil
}

// setPassthrough replaces the resolved addresses of the profile's passthrough domains, and reports whether
// the set actually changed (so a periodic re-resolution that finds the same answer is silent).
//
// ★ THE CALLER REPORTS THE COUNTS EVEN WHEN THEY ARE ZERO. A passthrough implementation that only speaks
// when it matches something cannot be told apart from one that was never given anything: "no line" then
// means both "this deployment authored none" and "this device is ignoring the ones it has". Saying
// domains=N addresses=M every time is what makes the second case a single line instead of a 502 nobody can
// explain.
func (l *liveDests) setPassthrough(addrs []netip.AddrPort) bool {
	l.mu.Lock()
	changed := !sameAddrPorts(l.passthrough, addrs)
	if changed {
		l.passthrough = append([]netip.AddrPort(nil), addrs...)
	}
	apply, out := l.onApply, l.effectiveLocked()
	l.mu.Unlock()
	if changed && apply != nil {
		apply(out)
	}
	return changed
}

// effectiveLocked is effective() for callers that already hold the lock.
func (l *liveDests) effectiveLocked() []netip.AddrPort {
	out := append([]netip.AddrPort(nil), l.base...)
	if l.edge != nil {
		out = append(out, *l.edge)
	}
	return append(out, l.passthrough...)
}

// sameAddrPorts compares two sets ignoring order, so a resolver that returns the same addresses in a
// different order does not look like a change and re-push the kernel policy every minute.
func sameAddrPorts(a, b []netip.AddrPort) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[netip.AddrPort]int, len(a))
	for _, x := range a {
		seen[x]++
	}
	for _, y := range b {
		seen[y]--
		if seen[y] < 0 {
			return false
		}
	}
	return true
}
