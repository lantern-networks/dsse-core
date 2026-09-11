package main

import (
	"errors"
	"fmt"
	"testing"
)

// ★★★ THE OPERATOR HAD A FRESH TOKEN AND WAS TOLD IT WAS INVALID (2026-08-26, found by standing a fleet up
// from nothing three times; the third refused everything). An Edge holds no token store — it asks the control
// plane to verify and spend. Behind a front door, in the seconds after leadership moves, that ask reaches a
// node that refuses because it does not lead, and every enrolment was answered "invalid or missing
// eligibility token". The true reason was in a log nobody had a reason to open.
func TestAnAuthorityThatCouldNotBeAskedIsNotAVerdictOnTheToken(t *testing.T) {
	unreachable := []error{
		// The one that actually happened: an answer, from the wrong node.
		errors.New("enrolment token refused: this control plane does not hold leadership, and an " +
			"administrative change written here would be accepted and then discarded"),
		errors.New(`Post "https://dsse-control-plane:9443/admin/fleet/enrolment-token/verify": dial tcp: connection refused`),
		errors.New(`Post "https://cp:9443/…": dial tcp: lookup cp: no such host`),
		errors.New("context deadline exceeded"),
		fmt.Errorf("read: %w", errors.New("EOF")),
	}
	for _, err := range unreachable {
		if !enrolmentAuthorityWasUnreachable(err) {
			t.Fatalf("this is the authority being unreachable and was read as a bad token: %v", err)
		}
	}

	// ★ AND A REAL VERDICT STAYS A REAL VERDICT. Widening this until everything looks like a transport
	// problem would hide the refusals that matter — a spent token doing the rounds, a revoked one still in a
	// kitting image — behind "try again shortly".
	verdicts := []error{
		errors.New("token already spent"),
		errors.New("enrolment token has expired"),
		errors.New("token belongs to another organization"),
		errors.New("revoked"),
		nil,
	}
	for _, err := range verdicts {
		if enrolmentAuthorityWasUnreachable(err) {
			t.Fatalf("a judgement on the token was reported as an unreachable authority: %v", err)
		}
	}
}
