package agentupdate

import (
	"strings"
	"testing"
)

// ★★ THE PAIRING TWO ROUNDS RECORDED AS CLOSED (2026-08-13, thirty-first review #9). The rule — the key that
// authorises RUNNING CODE must not also authorise the rollout plan — lived in one lane of one platform: macOS
// applied it to keys ADOPTED from the trust bundle. --plan-pin skipped it, a config-supplied plan key was
// never compared against a flag-supplied update key, and Windows did not implement it at all.
//
// The plan carries the FREEZE. One key for both means the party a halt exists to stop is the party who signs
// the halt, so a compromised release key can publish a bad build and lift the stop that would have caught it.
func TestAKeyThatSignsReleasesCannotAlsoSignTheHalt(t *testing.T) {
	update := []string{"aa11", "bb22"}

	kept, refused := SeparatePlanKeys(update, []string{"bb22", "cc33"})
	if len(refused) != 1 || refused[0] != "bb22" {
		t.Fatalf("the shared key was not refused: kept=%v refused=%v", kept, refused)
	}
	if len(kept) != 1 || kept[0] != "cc33" {
		t.Fatalf("a plan key that is nobody's release key was dropped: %v", kept)
	}
}

// Hex keys differing only in case, or padded, are the SAME key — and a check an accident walks through is not
// a check. This is the shape the config parser already normalises, so the comparison has to match it.
func TestTheComparisonIsNotFooledByCaseOrSpaces(t *testing.T) {
	for _, plan := range []string{"BB22", "bb22 ", " Bb22"} {
		_, refused := SeparatePlanKeys([]string{"bb22"}, []string{plan})
		if len(refused) != 1 {
			t.Fatalf("%q was accepted as a different key from bb22", plan)
		}
	}
}

// ★ THE PLAN KEY IS DROPPED, NEVER THE UPDATE KEY. Refusing the update key would leave the device unable to
// update at all — the state this product spent weeks escaping — while dropping the plan key leaves it unable
// to VERIFY a plan, which LoadRollout already answers for.
func TestTheUpdateKeySurvivesTheCollision(t *testing.T) {
	update := []string{"aa11"}
	kept, refused := SeparatePlanKeys(update, []string{"aa11"})
	if len(kept) != 0 || len(refused) != 1 {
		t.Fatalf("kept=%v refused=%v", kept, refused)
	}
	// The caller's update set is untouched: this function returns plan keys and nothing else.
	if len(update) != 1 || update[0] != "aa11" {
		t.Fatalf("the update key set was modified: %v", update)
	}
}

// Nothing to compare must not be read as nothing wrong: an empty update set means the collision cannot occur,
// and every plan key is legitimately kept.
func TestWithNoUpdateKeysEveryPlanKeyIsKept(t *testing.T) {
	kept, refused := SeparatePlanKeys(nil, []string{"aa11", "bb22"})
	if len(kept) != 2 || len(refused) != 0 {
		t.Fatalf("kept=%v refused=%v", kept, refused)
	}
}

// The message an operator reads has to name the consequence, not just the fact — this is the one place a
// device silently loses its ability to verify a halt.
func TestTheRefusalIsReportableWithoutTheKeyItself(t *testing.T) {
	_, refused := SeparatePlanKeys([]string{"aa11"}, []string{"aa11"})
	if len(refused) != 1 {
		t.Fatal("nothing to report")
	}
	if strings.TrimSpace(refused[0]) == "" {
		t.Fatal("the refused key is empty, so a caller cannot say which one it was")
	}
}
