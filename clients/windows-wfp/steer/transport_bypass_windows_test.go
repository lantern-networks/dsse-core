//go:build windows

package main

import (
	"net/netip"
	"testing"
)

// ★ A HOSTNAME EDGE MUST STILL PRODUCE A DESTINATION BYPASS (2026-08-17, found on win-dev-1).
//
// The (T) transport loop guard derived its never-steer destination with netip.ParseAddrPort alone. That
// accepts an IP literal and nothing else, so the day a signed profile named the Edge by hostname
// (shinmac-mini.tail04460b.ts.net:18543 — a MagicDNS name, the whole point of which is to outlive an IP) the
// guard produced nothing and said nothing. The agent kept working, because its own process is excluded by
// AppID, which is precisely the protection the destination rule exists to complement: one classifies by
// looking up the process at connect time, the other is matched in the kernel against the address.
//
// The contrast IS the test. Asserting only that resolveAddrPort works would pass just as well against the
// broken code, since nothing there was wrong with resolveAddrPort — the defect was reaching for the parser
// where a resolver was needed.
func TestAHostnameTransportStillYieldsABypassDestination(t *testing.T) {
	const hostPort = "localhost:18543" // the one name every machine running this test resolves

	if _, err := netip.ParseAddrPort(hostPort); err == nil {
		t.Fatalf("netip.ParseAddrPort accepted %q — this test's premise is that it does NOT, and the guard "+
			"relied on it alone", hostPort)
	}

	got, ok := resolveAddrPort(hostPort)
	if !ok {
		t.Fatalf("resolveAddrPort(%q) failed, so a hostname Edge would arm with no destination loop guard", hostPort)
	}
	if got.Port() != 18543 {
		t.Fatalf("port lost: %v", got)
	}
	if !got.Addr().IsLoopback() {
		t.Fatalf("resolved %v, want the loopback address for %q", got, hostPort)
	}
}

// An IP-literal transport must keep taking the parser path unchanged — the fix above adds a fallback, it does
// not re-route the case that already worked.
func TestAnIPLiteralTransportIsUnaffected(t *testing.T) {
	ap, err := netip.ParseAddrPort("100.72.135.18:18543")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if ap.Addr().String() != "100.72.135.18" || ap.Port() != 18543 {
		t.Fatalf("parsed %v", ap)
	}
}

// A transport host that cannot be turned into an address must report false, not a zero AddrPort — a bypass
// rule for 0.0.0.0:0 is a rule matching everything, the opposite of a narrow exception.
//
// Rejected on the PORT rather than by looking up a name that does not exist: a .invalid lookup cost this
// suite 12 seconds of DNS timeout, and the local pre-push gate is the only per-push check on this box. Both
// paths return the same (netip.AddrPort{}, false), and the caller cannot tell which refused it.
func TestATransportHostThatCannotBeAddressedYieldsNoRule(t *testing.T) {
	if ap, ok := resolveAddrPort("edge.example:notaport"); ok {
		t.Fatalf("an unusable host:port produced a bypass rule %v", ap)
	}
	if ap, ok := resolveAddrPort("edge.example:0"); ok {
		t.Fatalf("port 0 must not become a rule (it is the wildcard the whole-host form uses): %v", ap)
	}
}
