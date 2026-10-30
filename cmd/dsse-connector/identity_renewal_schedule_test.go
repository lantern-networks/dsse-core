package main

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/enroll"
)

func TestConnectorShortLivedIdentityGetsRenewalAttemptsBeforeExpiry(t *testing.T) {
	start := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	for _, life := range []time.Duration{time.Hour, 5 * time.Minute, 24 * time.Hour} {
		t.Run(life.String(), func(t *testing.T) {
			end := start.Add(life)
			next := connectorIdentityCheckInterval(start, end)
			if next <= 0 {
				t.Fatalf("invalid interval %s", next)
			}
			attempts := 0
			for now := start; now.Before(end); now = now.Add(next) {
				if enroll.RenewalDue(start, end, now) {
					attempts++
				}
			}
			if attempts < 3 {
				t.Fatalf("%s certificate gets only %d renewal attempts before expiry with interval %s", life, attempts, next)
			}
		})
	}
}

func TestConnectorRenewalScheduleRemainsBounded(t *testing.T) {
	start := time.Now()
	if got := connectorIdentityCheckInterval(start, start.Add(60*24*time.Hour)); got != 6*time.Hour {
		t.Fatalf("long-lived certificate changed established maximum interval: %s", got)
	}
	if got := connectorIdentityCheckInterval(start, start.Add(time.Second)); got != 15*time.Second {
		t.Fatalf("tiny certificate lifetime must not cause a busy request loop: %s", got)
	}
	if got := connectorIdentityCheckInterval(start, start); got <= 0 || got > 6*time.Hour {
		t.Fatalf("invalid certificate lifetime produced unbounded schedule: %s", got)
	}
}
