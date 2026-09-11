package main

import (
	"os"
	"strings"
	"testing"
)

// Guards that were removed by an unrelated change, and had to be restored.
//
// This is a narrow gate for a narrow failure: not "all safety checks", which nobody can enumerate, but the ones
// this repository has ALREADY lost once. Each entry below is a real commit where a guard disappeared in a
// change about something else, was not noticed, and had to be put back. That history is the evidence that the
// guard is droppable, which is the only honest reason to pin it.
//
// The mechanism is the one already used 67 times here for surface wiring (requireContractMarker) — pointed at
// safety rather than at routes. It is a grep, and it says so: it proves the guard is still WRITTEN, not that it
// is still reached. A test that claimed the latter from a string match would be its own silent failure.
//
// To add one: it must have been lost at least once, or be load-bearing enough that its removal would be silent.
// Naming it is most of the value — an invariant nobody can name is one nobody is defending.

type safetyInvariant struct {
	file    string // repo-relative from cmd/edge
	marker  string // the token whose absence means the guard is gone
	lostIn  string // the commit where it was silently dropped
	whatFor string // what stops being true without it
}

var safetyInvariants = []safetyInvariant{
	{
		file:    "../../clients/macos-network-extension/Sources/DsseAppProxyProviderSkeleton/DsseRenewedIdentityStore.swift",
		marker:  "canSign(with:",
		lostIn:  "cc0e873f (restored by ea7fef2f)",
		whatFor: "a renewed identity whose private key cannot actually sign is adopted, and the device goes dark at the next handshake",
	},
	{
		file:    "../../decision/east_west.go",
		marker:  "eastWestSelectorMatches(r.RiskSeverities, req.RiskStateSeverity)",
		lostIn:  "restored by 2a1fa766",
		whatFor: "an authored east-west rule of the form risk>=high/deny stops filtering on risk and applies at every risk level, or none",
	},
}

func TestSafetyInvariantsAreStillWritten(t *testing.T) {
	for _, inv := range safetyInvariants {
		src, err := os.ReadFile(inv.file)
		if err != nil {
			t.Errorf("%s: cannot read the file this invariant lives in: %v\n"+
				"  If it moved, move the entry. If it was deleted, that is the finding.", inv.file, err)
			continue
		}
		if !strings.Contains(string(src), inv.marker) {
			t.Errorf("safety guard %q is gone from %s.\n"+
				"  Without it: %s\n"+
				"  It was silently dropped once before — %s — which is why it is pinned here.\n"+
				"  If the guard genuinely moved or was replaced, update this entry in the same commit that moves it.",
				inv.marker, inv.file, inv.whatFor, inv.lostIn)
		}
	}
}

// A marker that matches nothing would pass forever, and a marker that matches everything would too. Neither is
// a check. This asserts the entries are specific enough to be about the guard rather than about the language.
func TestSafetyInvariantMarkersAreSpecific(t *testing.T) {
	for _, inv := range safetyInvariants {
		if len(inv.marker) < 12 {
			t.Errorf("marker %q is short enough to match incidentally — pin the call, not a keyword", inv.marker)
		}
		if inv.whatFor == "" || inv.lostIn == "" {
			t.Errorf("invariant %q has no stated consequence or history; both are what make it reviewable", inv.marker)
		}
	}
}
