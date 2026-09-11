//go:build windows

package main

import (
	"strings"
	"testing"
)

// The self-test must verify against the same accepted-key set the running agent does. It used to use the pin
// alone, which is the worst direction for a diagnostic to be wrong in: mid-rotation, with the Edge signing
// under a key the device has adopted but does not pin, it reported a FAILURE on a device that was applying
// that exact policy correctly — sending whoever ran it to investigate a working system.
//
// This asserts the wiring rather than the network call: given a state dir holding an adopted key, the set the
// self-test builds is the pin plus that key, in that order.
func TestSelfTestVerifiesAgainstTheAdoptedKeySet(t *testing.T) {
	dir := t.TempDir()
	writeKeyringPointer(t, dir, []string{testNextKey})

	keys := policyVerificationKeys(testPinKey, dir)
	if len(keys) != 2 || keys[0] != testPinKey || keys[1] != testNextKey {
		t.Fatalf("keys = %v, want the pin then the adopted key", keys)
	}
}

// With no adopted state the self-test verifies against exactly the pin — unchanged behaviour for a device that
// has never adopted anything.
func TestSelfTestFallsBackToThePinAlone(t *testing.T) {
	if got := policyVerificationKeys(testPinKey, t.TempDir()); len(got) != 1 || got[0] != testPinKey {
		t.Fatalf("keys = %v, want just the pin", got)
	}
}

// policyKeyStateDir is what connects the self-test's --transport-pinned-ca argument to the directory the
// adopted keys live in; if that ever stopped resolving, the self-test would silently fall back to pin-only.
func TestSelfTestStateDirResolvesFromThePinnedCAPath(t *testing.T) {
	got := policyKeyStateDir(`C:\ProgramData\DSSE\transport_ca.pem`)
	if !strings.EqualFold(got, `C:\ProgramData\DSSE`) {
		t.Fatalf("policyKeyStateDir = %q, want the directory holding the pinned CA", got)
	}
}
