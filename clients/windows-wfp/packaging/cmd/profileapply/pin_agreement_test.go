package main

import (
	"strings"
	"testing"
)

const keyA = "0ae740bd219e4bc112ac84f6153972406a5415999f1eec6e8fa9cacf1a518220"
const keyB = "f95090bb69020b27192a046e5c31918ac05c573f481c9c13c3c4a4c50cb9a0cf"

// ★★★ A STALE HUMAN-READABLE COPY IS WORSE THAN NONE. The device is fine either way — it verifies against its
// arguments and fails closed if it cannot. The person is not: they read the file, believe it, and reason from
// a value that is not in force.
func TestARecordedKeyThatIsNotInForceIsCalledOut(t *testing.T) {
	a := comparePins(keyA, []string{"--service-run", "--config-pin", keyB})
	if a.Agree {
		t.Fatal("two different keys were reported as agreeing")
	}
	for _, want := range []string{signingKeyFileName, "0ae740bd219e4bc1", "f95090bb69020b27", "an operator reads"} {
		if !strings.Contains(a.Note, want) {
			t.Fatalf("the note does not carry %q: %s", want, a.Note)
		}
	}
	// It must not pick a winner. Deciding which of two copies is right is how a discrepancy gets papered over.
	if !strings.Contains(a.Note, "not a thing this can decide") {
		t.Fatalf("the report proposed a resolution: %s", a.Note)
	}
}

// A file with no key in force describes an intention. The device verifies nothing, and the file makes that
// invisible.
func TestAFileWithNothingInForceSaysTheDeviceVerifiesNothing(t *testing.T) {
	a := comparePins(keyA, []string{"--service-run", "--config-store"})
	if a.Agree {
		t.Fatal("a recorded key with none in force was reported as agreement")
	}
	if !strings.Contains(a.Note, "NO key") || !strings.Contains(a.Note, "verifies nothing") {
		t.Fatalf("%s", a.Note)
	}
}

// In force but with no readable copy is not an error — it is the state a package built with a baked pin
// produces — but an operator has nowhere to look, and that is worth one sentence.
func TestAKeyInForceWithNoReadableCopyIsReportedAsUndiscoverable(t *testing.T) {
	a := comparePins("", []string{"--config-pin=" + keyA})
	if !a.Agree {
		t.Fatal("a device verifying correctly was reported as a disagreement")
	}
	if !strings.Contains(a.Note, "undiscoverable") {
		t.Fatalf("%s", a.Note)
	}
}

func TestNothingAnywhereSaysTheDeviceCannotVerifyAnything(t *testing.T) {
	a := comparePins("", nil)
	if a.Agree || !strings.Contains(a.Note, "fail-closed") {
		t.Fatalf("%+v", a)
	}
}

// Case and whitespace are not a disagreement: the same key written two ways is one key.
func TestTheSameKeyWrittenTwoWaysAgrees(t *testing.T) {
	a := comparePins("  "+strings.ToUpper(keyA)+"\n", []string{"--config-pin", keyA})
	if !a.Agree {
		t.Fatalf("case or whitespace was read as a different authority: %s", a.Note)
	}
}

// ★ THE LAST ONE WINS, because that is what the flag package does with a repeated flag. A report that named
// the first would describe a value the agent does not use — which is the whole failure this file exists for,
// reproduced inside the thing meant to catch it.
func TestARepeatedPinIsReportedAsTheOneThatWillBeUsed(t *testing.T) {
	a := comparePins(keyB, []string{"--config-pin", keyA, "--config-pin", keyB})
	if !a.Agree {
		t.Fatalf("the report named a pin the flag package would discard: %s", a.Note)
	}
	if got := pinFromArgs([]string{"--config-pin", keyA, "--config-pin=" + keyB}); got != keyB {
		t.Fatalf("pinFromArgs = %q, want the last one", got)
	}
}
