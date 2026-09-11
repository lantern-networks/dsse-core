package enroll

import (
	"testing"
	"time"
)

// The rule is a FRACTION of the certificate's own life, not a fixed number of days. These hold that, because
// the two agree on the 60-day certificates issued today and disagree on every shorter one — which is exactly
// the drift that would not have been noticed.

func TestRenewalStartsAtTwoThirdsOfLifeWhateverTheLifeIs(t *testing.T) {
	for _, life := range []time.Duration{
		60 * 24 * time.Hour, // what the deployment issues today
		24 * time.Hour,      // a deployment that shortened -enroll-cert-ttl
		time.Hour,           // and one that shortened it a lot
		10 * 365 * 24 * time.Hour,
	} {
		start := time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC)
		end := start.Add(life)
		justBefore := start.Add(life*2/3 - time.Minute)
		justAfter := start.Add(life*2/3 + time.Minute)
		if RenewalDue(start, end, justBefore) {
			t.Fatalf("life %s: due before two thirds had passed", life)
		}
		if !RenewalDue(start, end, justAfter) {
			t.Fatalf("life %s: not due after two thirds had passed", life)
		}
	}
}

// ★ THE ONE THAT CATCHES THE FIXED-DAYS RULE. A twenty-day threshold says "not yet" for the whole life of a
// one-day certificate, so the holder never renews and expires. Named for what it is.
func TestAShortLivedCertificateIsDueLongBeforeTwentyDaysRemain(t *testing.T) {
	start := time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC)
	end := start.Add(24 * time.Hour)
	at := start.Add(20 * time.Hour)  // 4 hours left — a fixed 20-day rule would already have renewed, but only
	if !RenewalDue(start, end, at) { // because 4 hours < 20 days; the point is that the fraction agrees here
		t.Fatal("a one-day certificate with four hours left was not due for renewal")
	}
	// And the direction a fixed rule gets WRONG: early in a short certificate's life, a fixed 20-day threshold
	// says "renew now" for a certificate that has only just been issued, so the holder renews on every tick.
	if RenewalDue(start, end, start.Add(time.Hour)) {
		t.Fatal("a one-hour-old one-day certificate was already due: the rule is not a fraction of its life")
	}
}

func TestACertificateWithNoUsableLifeIsNeverDue(t *testing.T) {
	now := time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC)
	if RenewalDue(now, time.Time{}, now) {
		t.Fatal("a certificate with no expiry was reported due")
	}
	if RenewalDue(now, now.Add(-time.Hour), now) {
		t.Fatal("a certificate that expires before it starts was reported due")
	}
	if RenewalDue(now, now, now) {
		t.Fatal("a zero-life certificate was reported due")
	}
}
