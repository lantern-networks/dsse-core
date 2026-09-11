package main

import (
	"testing"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
)

// ★★★ THE ROW AND ITS STATE MUST JOIN (2026-09-01, measured on a real Mac the minute it started steering).
//
// The enrolled inventory normalises a device identity; the presence map was keyed by whatever the device
// called itself. A Mac admitted as "shinnomac-mini" reported as "ShinnoMac-mini", the Console looks the second
// up with the key of the first, and a device that was steering, inspected and reporting posture rendered as
// "No report — not steering yet". Windows never showed it: its hostname was already lower-case.
func TestTheRuntimeViewJoinsTheLedgersKey(t *testing.T) {
	const asAdmitted, asReported = "shinnomac-mini", "ShinnoMac-mini"
	if enrolledinventory.NormalizeIdentity(asReported) != asAdmitted {
		t.Fatalf("this test's premise is gone: %q no longer normalises to %q", asReported, asAdmitted)
	}

	keyed := keyDeviceRuntimeTheWayTheLedgerDoes(map[string]deviceRuntimeView{
		asReported: {SteerActive: true, LastSeen: "2026-08-31T23:05:00Z"},
	})
	got, ok := keyed[asAdmitted]
	if !ok {
		t.Fatalf("a screen holding the ledger's key %q finds nothing; the map has %v — the device reads as "+
			"not steering while it is steering", asAdmitted, keysOf(keyed))
	}
	if !got.SteerActive {
		t.Error("the state was lost on the way through")
	}

	// ★ AND TWO SPELLINGS OF ONE MACHINE FOLD TO THE LIVE ONE, rather than to whichever the map happened to
	// yield first — a stale entry winning here would show a steering device as last seen hours ago.
	folded := keyDeviceRuntimeTheWayTheLedgerDoes(map[string]deviceRuntimeView{
		asReported: {SteerActive: true, LastSeen: "2026-08-31T23:05:00Z"},
		asAdmitted: {SteerActive: false, LastSeen: "2026-08-31T09:00:00Z"},
	})
	if len(folded) != 1 {
		t.Fatalf("one machine is carried as %d rows: %v", len(folded), keysOf(folded))
	}
	if !folded[asAdmitted].SteerActive {
		t.Errorf("the stale spelling won: last_seen=%q", folded[asAdmitted].LastSeen)
	}
}

func keysOf(m map[string]deviceRuntimeView) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
