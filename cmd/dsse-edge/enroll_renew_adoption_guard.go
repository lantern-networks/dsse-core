package main

import (
	"crypto/x509"
	"sync"
	"time"
)

// Renewal mints a real credential every time it is asked. On 2026-08-02 the reference Edge was minting one
// 1440h device certificate per minute for mac-dev-1, and had been for hours: the operator's "renew
// certificates issued before" cutoff made the device's certificate perpetually due for renewal, the device
// asked on every poll, the Edge signed, and the device could not put the result into service — so the next
// poll asked again. Nothing was wrong with any single request. The loop was invisible because a successful
// issuance is, correctly, logged as a success.
//
// The missing idea is CONVERGENCE: a renewal is supposed to end with the device presenting the new
// certificate. When a device asks again while still presenting the certificate the previous renewal was
// meant to replace, that previous renewal did not take, and signing another identical one will not help.
//
// This does NOT refuse renewal outright. A device can legitimately lose a freshly issued certificate once —
// a crash between "received" and "persisted" — and a hard refusal there would strand it with no way back.
// Instead the retries are spaced out and the situation is stated in the log, so an operator sees
// "issued but never adopted" instead of an endless column of successful issuances.
//
// Deliberately in memory, not in a file: this is a live convergence observation, not a ledger. Persistent
// state belongs in the control plane, and a restart re-learning it on the next poll costs one certificate.
type renewAdoptionGuard struct {
	mu      sync.Mutex
	byID    map[string]*renewAdoptionEntry
	backoff []time.Duration
}

type renewAdoptionEntry struct {
	// issuedAt is when this Edge last signed a renewal for the identity.
	issuedAt time.Time
	// unadopted counts consecutive renewals asked for while the OLD certificate was still presented.
	unadopted int
}

// renewAdoptionVerdict is what the endpoint needs to know, in words it can log and return.
type renewAdoptionVerdict struct {
	Allow bool
	// Unadopted is the number of consecutive renewals that were issued and never put into service.
	Unadopted int
	// RetryAfter is how long until the next attempt is allowed (only meaningful when !Allow).
	RetryAfter time.Duration
	// PreviousIssuedAt is when the renewal that was never adopted was signed.
	PreviousIssuedAt time.Time
}

func newRenewAdoptionGuard() *renewAdoptionGuard {
	return &renewAdoptionGuard{
		byID: map[string]*renewAdoptionEntry{},
		// The first step has to exceed the agent's poll interval or it spaces nothing: a device asking every
		// 60 seconds sailed straight through a 30-second step. Then it grows, so an endpoint that can NEVER
		// adopt costs one certificate an hour instead of sixty.
		backoff: []time.Duration{2 * time.Minute, 15 * time.Minute, time.Hour},
	}
}

// Check decides whether to sign, given the certificate the device is presenting RIGHT NOW on the (T)
// transport. presented may be nil (no client certificate available), in which case adoption cannot be
// judged and the request is allowed — this guard exists to stop a loop, never to invent a new refusal.
func (g *renewAdoptionGuard) Check(identity string, presented *x509.Certificate, now time.Time) renewAdoptionVerdict {
	if g == nil {
		return renewAdoptionVerdict{Allow: true}
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	entry := g.byID[identity]
	if entry == nil || entry.issuedAt.IsZero() {
		return renewAdoptionVerdict{Allow: true}
	}
	// Adoption test: is the device presenting something issued at or after our last renewal? A renewed
	// certificate is signed now, so its NotBefore is never earlier than the moment we signed it. Anything
	// older is the certificate the renewal was supposed to replace.
	if presented != nil && !presented.NotBefore.Before(entry.issuedAt.Add(-renewAdoptionClockSkew)) {
		// Adopted. Forget the history so a later, unrelated renewal starts clean.
		delete(g.byID, identity)
		return renewAdoptionVerdict{Allow: true}
	}
	// Not adopted. The spacing is that of the attempt ABOUT to be made, measured from the last signature —
	// computing it at signing time instead let the first repeat through unspaced, which for a device polling
	// once a minute meant the guard did nothing at all for the first minute of the loop.
	wait := g.wait(entry.unadopted + 1)
	if elapsed := now.Sub(entry.issuedAt); elapsed < wait {
		return renewAdoptionVerdict{
			Allow:            false,
			Unadopted:        entry.unadopted,
			RetryAfter:       (wait - elapsed).Round(time.Second),
			PreviousIssuedAt: entry.issuedAt,
		}
	}
	return renewAdoptionVerdict{
		Allow:            true,
		Unadopted:        entry.unadopted,
		PreviousIssuedAt: entry.issuedAt,
	}
}

// renewAdoptionClockSkew tolerates a signer whose NotBefore is backdated slightly against our clock.
const renewAdoptionClockSkew = 2 * time.Minute

// Recorded is called after a renewal is signed. presented is the certificate the device showed when it
// asked, which is what makes the NEXT call able to tell adoption from repetition. It returns the number of
// renewals that have now been issued without ever being put into service — the operator-facing count, taken
// AFTER this issuance, because a loop's second certificate reporting "0 unadopted" reads as healthy.
func (g *renewAdoptionGuard) Recorded(identity string, presented *x509.Certificate, now time.Time) int {
	if g == nil {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	entry := g.byID[identity]
	if entry == nil {
		entry = &renewAdoptionEntry{}
		g.byID[identity] = entry
	}
	if !entry.issuedAt.IsZero() && (presented == nil || presented.NotBefore.Before(entry.issuedAt.Add(-renewAdoptionClockSkew))) {
		// We signed before, and the device is still on the old certificate: the previous one never took.
		entry.unadopted++
	} else {
		entry.unadopted = 0
	}
	entry.issuedAt = now
	return entry.unadopted
}

func (g *renewAdoptionGuard) wait(unadopted int) time.Duration {
	if unadopted <= 0 {
		return 0
	}
	idx := unadopted - 1
	if idx >= len(g.backoff) {
		idx = len(g.backoff) - 1
	}
	return g.backoff[idx]
}
