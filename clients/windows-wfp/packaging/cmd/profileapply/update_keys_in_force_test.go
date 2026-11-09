package main

import "testing"

const testUpdateKey = "f95090bb69020b27192a046e5c31918ac05c573f481c9c13c3c4a4c50cb9a0cf"

func TestProfileUpdateKeysBecomeTheUpdaterCondition(t *testing.T) {
	set := profileUpdatePinSet([]string{" " + testUpdateKey + " ", ""})
	if set.get("Updater_UpdatePin") != testUpdateKey {
		t.Fatalf("update pin = %q, want %q", set.get("Updater_UpdatePin"), testUpdateKey)
	}
	if profileUpdatePinSet(nil) != nil {
		t.Fatal("no keys must produce no condition")
	}
	if profileUpdatePinSet([]string{"not-a-key"}) != nil {
		t.Fatal("a malformed key must not be put in force")
	}
}

// The key that verifies configuration or policy must never also authorise code.
func TestProfileUpdateKeyThatHoldsAnotherAuthorityIsNotAdopted(t *testing.T) {
	configKey := testUpdateKey
	if profileUpdatePinSet([]string{configKey}, configKey) != nil {
		t.Fatal("the configuration-verification key was adopted as an update key")
	}
	if !profileUpdateKeysConflict([]string{"aa", configKey}, "", configKey) {
		t.Fatal("conflict with the configuration key was not reported")
	}
	if profileUpdatePinSet([]string{testUpdateKey}, "0000000000000000000000000000000000000000000000000000000000000000") == nil {
		t.Fatal("an unrelated reserved key must not block a legitimate update key")
	}
}

// A reserved key hidden inside one comma-separated element must still be refused.
func TestReservedKeyInsideACommaSeparatedElementIsRefused(t *testing.T) {
	configKey := testUpdateKey
	other := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if !profileUpdateKeysConflict([]string{other + "," + configKey}, configKey) {
		t.Fatal("a reserved key inside \"B,A\" was not reported as a conflict")
	}
	if set := profileUpdatePinSet([]string{other + "," + configKey}, configKey); set != nil {
		t.Fatalf("a reserved key inside \"B,A\" was adopted: %v", set)
	}
	// Two legitimate keys in one element or in two are the same set.
	a := profileUpdatePinSet([]string{other + "," + testUpdateKey})
	b := profileUpdatePinSet([]string{other, testUpdateKey})
	if a == nil || b == nil || a.get("Updater_UpdatePin") != b.get("Updater_UpdatePin") {
		t.Fatalf("the same keys gave different conditions: %v / %v", a, b)
	}
	// A reserved key given as a comma-separated set is split too.
	if set := profileUpdatePinSet([]string{testUpdateKey}, other+","+configKey); set != nil {
		t.Fatal("a reserved key listed inside a reserved set was adopted")
	}
}
