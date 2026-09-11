package main

import (
	"strings"
	"testing"
)

// ★★★ THE FLAP, AS A TEST (2026-08-20). Measured on the lab: region-a announced each organization's new
// authority, region-b — same shared trust store, no control-plane material — recomputed from what it holds and
// dropped them, region-a added them back. Every advance invalidated the adoption evidence below it, so the
// gate that closes roadmap D's overlap could never open, and it looked like slow devices.
func TestANodeThatCannotSeeTheAuthoritiesDoesNotDropThem(t *testing.T) {
	fleetPromised := strings.Join([]string{
		"0ac681cd04f2d317c19e5b171650dc4cd92e6174a8a0d1e93f733a809432d5f3",
		"tenant_northwind=" + strings.Repeat("a", 64),
		"tenant_northwind=" + strings.Repeat("b", 64), // the control-plane authority region-b was never given
		"tenant_reference_lab=" + strings.Repeat("c", 64),
		"tenant_northwind@northwind.dsse.invalid",
		"recovery-sni=recovery.dsse.invalid",
	}, ",")

	// region-b: files only. It holds one anchor per organization — the older end of the overlap, which is not a
	// fault — and recomputes without the two it was never handed.
	fileNode := []string{
		"0ac681cd04f2d317c19e5b171650dc4cd92e6174a8a0d1e93f733a809432d5f3",
		"tenant_northwind=" + strings.Repeat("a", 64),
		"tenant_reference_lab=" + strings.Repeat("c", 64),
		"tenant_northwind@northwind.dsse.invalid",
		"recovery-sni=recovery.dsse.invalid",
	}
	kept := announcementKeepingWhatThisNodeCannotSee(fileNode, fleetPromised, false)
	if !announcementContains(kept, "tenant_northwind="+strings.Repeat("b", 64)) {
		t.Fatalf("a node that was never given the authority withdrew it from the whole fleet: %v", kept)
	}

	// The same node ADDING something is untouched.
	adding := append(append([]string{}, fileNode...), "tenant_acme="+strings.Repeat("d", 64))
	if got := announcementKeepingWhatThisNodeCannotSee(adding, fleetPromised, false); !announcementContains(got,
		"tenant_acme="+strings.Repeat("d", 64)) {
		t.Fatal("a node may always add to the announcement")
	}

	// ★ And the withdrawal still works, from the node that CAN see the whole answer. Without this the fix
	// would trade a flap for an anchor nobody can ever retire — the failure this repository has paid for in the
	// other direction, where a withdrawal wrote only the bookkeeping.
	cpNode := announcementKeepingWhatThisNodeCannotSee(fileNode, fleetPromised, true)
	if announcementContains(cpNode, "tenant_northwind="+strings.Repeat("b", 64)) {
		t.Fatal("a node on the material path could not withdraw an authority that is gone")
	}

	// Nothing but the per-organization anchor tokens is carried over: the names, the recovery SNI and the
	// endpoint are this node's answer about itself, and the fleet-promise guard already refuses a node that
	// cannot keep them.
	withoutRecovery := []string{"tenant_northwind=" + strings.Repeat("a", 64)}
	got := announcementKeepingWhatThisNodeCannotSee(withoutRecovery, fleetPromised, false)
	for _, token := range got {
		if strings.HasPrefix(token, "recovery-sni=") || strings.Contains(token, "@") {
			t.Fatalf("a promise about this node itself was carried over from another node: %q", token)
		}
	}
}

func announcementContains(v []string, want string) bool {
	for _, s := range v {
		if s == want {
			return true
		}
	}
	return false
}
