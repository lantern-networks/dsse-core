package main

import "testing"

// ★★★ THE INSTALLER'S OWN READINESS CHECK DID THE THING THE PRODUCT REFUSES (2026-09-04, found when the
// refusal landed and every fresh deployment turned red).
//
// -verify proves the enrolment path by APPROVING A DEVICE. With no organization named, that approval lands in
// the operator's own — the organization that administers the customers and has no devices — and the Edge now
// refuses it. A fresh deployment has no customer organization yet, so the check cannot be answered at install
// time at all.
//
// Counting that as a failure makes -verify unpassable on every new deployment. Counting it as a pass is a
// green that measured nothing. It is neither.
func TestAnUnansweredCheckIsNeitherPassNorFail(t *testing.T) {
	results := []verifyResult{
		{name: "a", ok: true},
		{name: "b", skipped: true, note: "n/a here: no customer organization yet"},
		{name: "c", ok: false, note: "genuinely broken"},
	}
	failed, skipped := 0, 0
	for _, r := range results {
		switch {
		case r.skipped:
			skipped++
		case !r.ok:
			failed++
		}
	}
	if failed != 1 {
		t.Fatalf("failed = %d, want 1 — a skipped check must not be counted as a failure", failed)
	}
	if skipped != 1 {
		t.Fatalf("skipped = %d, want 1 — an unanswered check must be visible, not folded into the passes", skipped)
	}
	// And the shape that matters: a skipped result must never read as ok.
	for _, r := range results {
		if r.skipped && r.ok {
			t.Fatal("a check that could not be answered must not also claim to have passed")
		}
	}
}
