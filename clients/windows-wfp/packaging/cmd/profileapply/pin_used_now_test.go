package main

import (
	"strings"
	"testing"
)

const (
	keyPrev = "f53413bfedec3517dc46334ca3ab9762d6d77fea6e091609f98faf5c370971df"
	keyNew  = "a96e992f63a0abac6ecfe743e504dbb11d7a96644acbb8fe64952451bce4764f"
)

// ★★★ THE STATE THIS EXISTS FOR, MEASURED ON win-dev-1 2026-09-01: a provision for a NEW organization, run
// with --pin instead of the key file. The profile applies correctly. Neither record is touched, so the two
// records still agree -- with each other, on the PREVIOUS deployment's key -- and the run ends by printing
// "the recorded key and the key in force agree", which reads as reassurance at the exact moment the device
// has been pinned away from the authority that will issue its next profile.
func TestAProvisionThatLeavesTheDevicePinnedElsewhereSaysSo(t *testing.T) {
	agree := comparePins(keyPrev, []string{"--service-run", "--config-pin", keyPrev})
	if !agree.Agree {
		t.Fatal("setup wrong: the two records should agree — that agreement is what makes this dangerous")
	}
	n := usedNowNote(keyNew, agree)
	if n == "" {
		t.Fatal("a provision verified against one key, leaving a different key in force, said nothing")
	}
	if !strings.Contains(n, short(keyNew)) || !strings.Contains(n, short(keyPrev)) {
		t.Errorf("the note does not name BOTH keys, so the operator cannot tell which is which: %s", n)
	}
	// ★ It must name the artefact that actually fixes it. "Something is wrong" without a remedy is how a
	// warning becomes noise.
	if !strings.Contains(n, "--pin-file") {
		t.Errorf("the note does not name what puts a key in force: %s", n)
	}
	// ★ And it must say the install itself is fine, or an operator rolls back a correct install.
	if !strings.Contains(n, "This install is correct") {
		t.Errorf("the note does not distinguish this install from the next one: %s", n)
	}
}

// The normal path: PIN=/--pin-file was used, so the key in force was just updated to the same key. Nothing
// to say. A provision that prints a pin warning every time teaches the operator to skip pin warnings.
func TestTheOrdinaryProvisionIsSilent(t *testing.T) {
	agree := comparePins(keyNew, []string{"--config-pin", keyNew})
	if n := usedNowNote(keyNew, agree); n != "" {
		t.Errorf("a provision that put its own key in force still warned: %s", n)
	}
}

// Case differences are not disagreements: these are hex strings that travel through files, service
// arguments and command lines, and one of those will change the case sooner or later.
func TestCaseIsNotADisagreement(t *testing.T) {
	agree := comparePins(keyNew, []string{"--config-pin", keyNew})
	if n := usedNowNote("  "+strings.ToUpper(keyNew)+"\n", agree); n != "" {
		t.Errorf("the same key in a different case was reported as a mismatch: %s", n)
	}
}

// ★ Unknown is not disagreement either. A service that names no key at all is already covered, loudly, by
// comparePins ("this device verifies nothing"); saying it twice in different words helps nobody.
func TestNothingIsSaidWhenEitherSideIsUnknown(t *testing.T) {
	if n := usedNowNote(keyNew, comparePins(keyNew, nil)); n != "" {
		t.Errorf("a service naming no key produced a mismatch note: %s", n)
	}
	if n := usedNowNote("", comparePins(keyNew, []string{"--config-pin", keyNew})); n != "" {
		t.Errorf("an unknown used-now key produced a note: %s", n)
	}
}
