package main

import (
	"errors"
	"testing"
	"time"
)

// ★★★ AN EDGE THAT HELD NOTHING WAITED AN HOUR, AND THAT IS THE HOUR A DEPLOYMENT IS SET UP IN (2026-08-28,
// measured while setting one up).
//
// The fetcher slept an HOUR when no material had a stated expiry, reasoning that a deployment issuing none
// need not be asked often. An Edge cannot tell "this deployment issues none" from "nobody has set an
// organization up YET" — and the second is the normal state of a deployment being installed, which is exactly
// when organizations are created.
//
// Walked: the Edge fetched at 00:56 and was handed nothing; the operator created an organization's device and
// interception authorities in the Console at 01:02; the Edge had already decided to look again at 01:56. The
// Console said the customer's own root was in force, the Edge went on signing under the shared one, and
// nothing anywhere said why.
//
// ★ THE CHEAP QUESTION IS WHAT MAKES ASKING OFTEN SAFE: known_generation is compared first and an unchanged
// answer mints nothing. There was never a cost to pay here.
func TestAnEdgeHoldingNoMaterialStillAsksOften(t *testing.T) {
	now := time.Now()
	empty := &tenantTransportMaterialFetcher{}
	for _, err := range []error{nil, errors.New("unavailable")} {
		if wait := empty.nextFetchWait(now, err); wait != 10*time.Second {
			t.Errorf("empty Edge retry = %s, want 10s (error %v)", wait, err)
		}
	}
	held := &tenantTransportMaterialFetcher{expiry: now.Add(12 * time.Hour)}
	if wait := held.nextFetchWait(now, nil); wait != time.Minute {
		t.Errorf("ordinary refresh = %s", wait)
	}
	if wait := held.nextFetchWait(now, errors.New("unavailable")); wait != 10*time.Second {
		t.Errorf("ordinary failure backoff = %s", wait)
	}
}
