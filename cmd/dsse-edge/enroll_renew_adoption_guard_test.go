package main

import (
	"crypto/x509"
	"testing"
	"time"
)

func certIssuedAt(t time.Time) *x509.Certificate {
	return &x509.Certificate{NotBefore: t}
}

// The loop that ran on the reference Edge on 2026-08-02: the device asks every minute, always presenting the
// same old certificate, and the Edge signs a new one every time. After the first repeat the guard must start
// spacing the attempts out instead of minting on demand.
func TestRenewAdoptionGuardStopsTheEveryMinuteLoop(t *testing.T) {
	g := newRenewAdoptionGuard()
	old := certIssuedAt(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	now := time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)

	if v := g.Check("mac-dev-1", old, now); !v.Allow {
		t.Fatalf("first renewal must be allowed, got %+v", v)
	}
	g.Recorded("mac-dev-1", old, now)

	signed := 1
	for minute := 1; minute <= 60; minute++ {
		at := now.Add(time.Duration(minute) * time.Minute)
		if v := g.Check("mac-dev-1", old, at); v.Allow {
			signed++
			g.Recorded("mac-dev-1", old, at)
		}
	}
	// Unbounded was 61 certificates in the hour. With 30s/5m/15m/1h spacing it must be a handful.
	if signed > 6 {
		t.Fatalf("guard did not stop the loop: signed %d certificates in an hour", signed)
	}
	if signed < 2 {
		t.Fatalf("guard is too strict: a device must still be able to retry, signed %d", signed)
	}
}

// A device that DOES put the new certificate into service must be treated as converged: the next renewal,
// whenever it comes, starts from a clean slate rather than inheriting the backoff.
func TestRenewAdoptionGuardResetsOnceTheDeviceAdopts(t *testing.T) {
	g := newRenewAdoptionGuard()
	old := certIssuedAt(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	now := time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)

	g.Recorded("mac-dev-1", old, now)
	if v := g.Check("mac-dev-1", old, now.Add(time.Minute)); v.Allow {
		t.Fatalf("a repeat with the old certificate must be spaced out, got %+v", v)
	}
	// The device installs it and comes back presenting the renewed certificate.
	adopted := certIssuedAt(now)
	v := g.Check("mac-dev-1", adopted, now.Add(2*time.Minute))
	if !v.Allow || v.Unadopted != 0 {
		t.Fatalf("adoption must clear the history, got %+v", v)
	}
}

// Without a client certificate there is nothing to judge. The guard exists to stop a loop, never to invent a
// refusal that the endpoint did not previously have.
func TestRenewAdoptionGuardAllowsWhenAdoptionCannotBeJudged(t *testing.T) {
	g := newRenewAdoptionGuard()
	now := time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)
	g.Recorded("mac-dev-1", nil, now)
	if v := g.Check("mac-dev-1", nil, now.Add(time.Second)); v.Allow {
		t.Fatalf("a repeat is still spaced out, got %+v", v)
	}
	if v := g.Check("never-seen", nil, now); !v.Allow {
		t.Fatalf("an identity with no history must be allowed, got %+v", v)
	}
}

// The count an operator reads has to be the number of renewals that never took, not the number of requests.
func TestRenewAdoptionGuardCountsUnadoptedRenewals(t *testing.T) {
	g := newRenewAdoptionGuard()
	old := certIssuedAt(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	at := time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)

	for i := 0; i < 3; i++ {
		g.Recorded("mac-dev-1", old, at)
		at = at.Add(2 * time.Hour) // past any backoff, so each one is a real signature
	}
	v := g.Check("mac-dev-1", old, at)
	if !v.Allow {
		t.Fatalf("after the backoff has elapsed a retry is allowed, got %+v", v)
	}
	if v.Unadopted != 2 {
		t.Fatalf("unadopted count = %d, want 2 (three issuances, two of which replaced an unadopted one)", v.Unadopted)
	}
}
