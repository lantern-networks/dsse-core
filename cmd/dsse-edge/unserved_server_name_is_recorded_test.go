package main

import (
	"testing"
	"time"
)

// ★★★ THE EDGE KNEW AND SAID NOTHING (2026-08-20, reported from win-dev-1 after a 31-minute investigation on
// their side and a fingerprint comparison on this one).
//
// A device asked for the name it had been provisioned with, because its agent restored the ANNOUNCED name too
// late in start-up. The Edge answered with the deployment-wide certificate — which is what a server does with a
// name it does not recognise — and a device holding only its own organization's anchor refused it. The first
// casualty was that box's steering-posture fetch, so the boot ran with no control-plane posture at all.
//
// From this side the only trace was a SHA-256 in a refusal list. The Edge had the answer at the moment of the
// handshake.
//
// Rate limiting is part of the behaviour, not a detail: this is an unauthenticated path, and a line per
// handshake is a way to fill a disk.
func TestAnUnservedServerNameIsRecordedOncePerNamePerHour(t *testing.T) {
	restore := unservedServerNames.seen
	t.Cleanup(func() { unservedServerNames.seen = restore })
	unservedServerNames.seen = map[string]time.Time{}

	noteUnservedServerName("Stale.Provisioned.Name")
	if _, ok := unservedServerNames.seen["stale.provisioned.name"]; !ok {
		t.Fatal("a name this node does not serve was not recorded, so the next investigation starts from a " +
			"fingerprint again")
	}
	first := unservedServerNames.seen["stale.provisioned.name"]

	// The same name again inside the window must not re-stamp: one line per name per hour.
	noteUnservedServerName("stale.provisioned.name")
	if unservedServerNames.seen["stale.provisioned.name"] != first {
		t.Fatal("the same name inside the window was recorded twice — an unauthenticated path that logs per " +
			"handshake is a way to fill a disk")
	}

	// No name at all is the ordinary case (probes, deployments serving one certificate to everybody) and says
	// nothing happened.
	noteUnservedServerName("   ")
	if len(unservedServerNames.seen) != 1 {
		t.Fatalf("an empty server name was recorded as an event: %v", unservedServerNames.seen)
	}
}
