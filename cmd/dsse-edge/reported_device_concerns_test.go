package main

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/revocation"
)

// A reported observation must never become enforcement.
//
// The route this guards used to revoke fleet-wide on a node's say-so. A device one Edge decided had gone dark
// was denied everywhere, authored by nobody, and the entry outlived the code that wrote it by two weeks before
// anyone found it. Cutting a device off decides whether someone can work; an inference does not get to make
// that call.
func TestReportedConcernNeverRevokes(t *testing.T) {
	overlay := revocation.NewAdmissionRevocations()
	concerns := &reportedDeviceConcernList{byIdentity: map[string]reportedDeviceConcern{}}
	now := time.Now().UTC()

	concerns.record("mac-dev-1", "agent_dark", now)
	concerns.record("mac-dev-1", "agent_dark", now.Add(time.Minute))
	concerns.record("win-dev-1", "attestation_failed", now)

	if _, revoked := overlay.IsRevoked("mac-dev-1"); revoked {
		t.Fatalf("a reported concern revoked a device — reporting must never enforce")
	}
	if len(overlay.Snapshot()) != 0 {
		t.Fatalf("reporting wrote into the revocation overlay: %v", overlay.Snapshot())
	}

	got := concerns.snapshot()
	if len(got) != 2 {
		t.Fatalf("want 2 identities, got %d (%+v)", len(got), got)
	}
	for _, c := range got {
		if c.Enforced {
			t.Fatalf("%s reported as enforced; a report is never enforcement", c.Identity)
		}
	}
	// Repeats collapse onto the identity. A node that notices the same thing every poll would otherwise bury
	// every other device under one observation.
	for _, c := range got {
		if c.Identity == "mac-dev-1" && c.Reports != 2 {
			t.Fatalf("repeat reports should collapse with a count, got %d", c.Reports)
		}
	}

	// Dismissing is "seen", not "acted on" — it must leave enforcement exactly where it was.
	if !concerns.clear("mac-dev-1") {
		t.Fatalf("clear should report having found the entry")
	}
	if concerns.clear("mac-dev-1") {
		t.Fatalf("clearing twice should report nothing found")
	}
	if len(overlay.Snapshot()) != 0 {
		t.Fatalf("dismissing a report changed enforcement")
	}
}

// The explicit path still works, and is still the ONLY thing that revokes.
func TestOnlyAnExplicitBlockRevokes(t *testing.T) {
	overlay := revocation.NewAdmissionRevocations()
	overlay.Revoke("mac-dev-1", "admin_kill_switch")
	reason, revoked := overlay.IsRevoked("mac-dev-1")
	if !revoked || reason != "admin_kill_switch" {
		t.Fatalf("an explicit administrator block must revoke; got revoked=%v reason=%q", revoked, reason)
	}
	overlay.Restore("mac-dev-1")
	if _, still := overlay.IsRevoked("mac-dev-1"); still {
		t.Fatalf("an explicit restore must release the block")
	}
}
