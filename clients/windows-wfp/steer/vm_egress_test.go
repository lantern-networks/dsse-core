package main

import (
	"strings"
	"testing"
)

// ★★★ A TYPO MUST NOT BECOME PERMISSION, AND SILENCE MUST NOT EITHER (2026-09-01, from the measurement on
// win-dev-1: a standard user imported a WSL2 distro with no elevation and egressed to the public internet
// while this agent printed target=ALL-outbound-tcp).
//
// Every profile issued before this field existed says nothing. The promise this agent makes about outbound
// traffic is what decides that case — not the fact that blocking is the newer behaviour.
func TestVirtualMachinesAreBlockedUnlessTheOrganizationSaidOtherwise(t *testing.T) {
	for _, tc := range []struct {
		name         string
		value        string
		ack          bool
		wantBlock    bool
		wantAuthored bool
	}{
		{"an older profile says nothing", "", false, true, false},
		{"the organization chose to block", "blocked", false, true, true},
		{"allowed without the acknowledgement", "allowed", false, true, true},
		{"allowed, acknowledged", "allowed", true, false, true},
		{"case and space are the same decision", "  Allowed  ", true, false, true},
		{"a word neither side knows", "permit", true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := vmEgressFromProfile(tc.value, tc.ack)
			if got.Block != tc.wantBlock || got.Authored != tc.wantAuthored {
				t.Errorf("%q/ack=%v resolved to block=%v authored=%v, want block=%v authored=%v",
					tc.value, tc.ack, got.Block, got.Authored, tc.wantBlock, tc.wantAuthored)
			}
		})
	}
}

// ★ AND THE THREE STATES READ DIFFERENTLY IN A LOG. "The organization chose to let them out" and "nobody has
// decided yet" are the same blocked/allowed pair to a machine and completely different facts to whoever is
// reading — which is the distinction this deployment keeps having to add after the fact.
func TestTheLineTellsTheThreeStatesApart(t *testing.T) {
	chosen := vmEgressFromProfile("blocked", false).Line()
	unstated := vmEgressFromProfile("", false).Line()
	allowed := vmEgressFromProfile("allowed", true).Line()

	if chosen == unstated {
		t.Error("a deliberate block and a default block read identically")
	}
	if !strings.Contains(unstated, "nobody has chosen") {
		t.Errorf("the default does not say that nobody has chosen: %s", unstated)
	}
	for _, want := range []string{"UNINSPECTED", "without administrator rights"} {
		if !strings.Contains(allowed, want) {
			t.Errorf("the allowed line does not carry %q — it is the one state an operator must not skim: %s",
				want, allowed)
		}
	}
}
