package main

import (
	"testing"
	"time"
)

// Renewal starts at two thirds of life, deliberately, so the remaining third is retry budget.
//
// This is the number that decides whether a broken renewal path is an ALERT or an OUTAGE. With a 60-day
// certificate, starting at day 40 leaves 20 days of failed attempts before anything stops working. Renewing at
// the last minute would delete that margin, and renewing too early would burn issuance for no benefit.
func TestRenewalStartsWithRetryBudgetLeft(t *testing.T) {
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(60 * 24 * time.Hour)

	cases := []struct {
		name string
		at   time.Time
		want bool
	}{
		{"fresh", notBefore, false},
		{"halfway", notBefore.Add(30 * 24 * time.Hour), false},
		{"just before two thirds", notBefore.Add(40*24*time.Hour - time.Minute), false},
		{"at two thirds", notBefore.Add(40 * 24 * time.Hour), true},
		{"day 50 — still 10 days of retries left", notBefore.Add(50 * 24 * time.Hour), true},
		{"expired", notAfter.Add(time.Hour), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := renewalDue(notBefore, notAfter, tc.at); got != tc.want {
				t.Fatalf("renewalDue at %s = %v, want %v", tc.at.Format(time.RFC3339), got, tc.want)
			}
		})
	}

	// The retry budget must be a real span, not a rounding artefact: from the moment renewal opens to expiry
	// there has to be enough room for many attempts.
	opens := notBefore.Add(notAfter.Sub(notBefore) * 2 / 3)
	if budget := notAfter.Sub(opens); budget < 15*24*time.Hour {
		t.Fatalf("retry budget is only %v for a 60-day cert — too little room for a broken renewal path to be "+
			"noticed and fixed before it becomes an outage", budget)
	}
}

// Degenerate inputs must not be reported as "renew now": a zero or inverted validity window means we do not
// know when the certificate expires, and treating unknown as due would drive a renewal storm.
func TestRenewalDueRejectsDegenerateWindows(t *testing.T) {
	now := time.Now()
	if renewalDue(time.Time{}, time.Time{}, now) {
		t.Fatal("a zero validity window must not be reported as due")
	}
	if renewalDue(now, now.Add(-time.Hour), now) {
		t.Fatal("an inverted window (notAfter before notBefore) must not be reported as due")
	}
	if renewalDue(now, now, now) {
		t.Fatal("a zero-length window must not be reported as due")
	}
}
