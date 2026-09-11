package main

import (
	"sync/atomic"
	"testing"
)

// ★★★ A NEW DEVICE ASKED FOR NOBODY'S BUNDLE AND WAS GIVEN THE NODE'S (2026-08-29, measured on a Windows
// machine by the session that walked it).
//
// The first trust-bundle fetch passed currentAnnouncedServerName() — the name an ADOPTED bundle announced,
// which is empty on a device that has never adopted one. The Edge answers a nameless request with its own
// organization, as it must, so a brand-new device belonging to one organization adopted the DEPLOYMENT's
// interception root and logged "ADOPTED serial=3 anchors=1".
//
// The failure did not look like a failure. The device counted as provisioned, the ledger read green, and
// "each organization is inspected under its own authority" was false with nothing saying so. The name was in
// the signed install profile the whole time, and the agent prints it at start-up: one query parameter short.
func TestANewDeviceAsksForTheOrganizationItsProfileNames(t *testing.T) {
	// A device as it is on first boot: a profile that states its organization, nothing adopted yet.
	fresh := transportConfig{
		serverName:           "agents.osaka.example",
		configuredServerName: "c2neh.example",
		announcedServerName:  &atomic.Pointer[string]{},
	}
	if got := fresh.trustBundleServerName(); got != "c2neh.example" {
		t.Errorf("a device that has adopted nothing asks for %q — a nameless request is answered with the "+
			"NODE's organization, and what it adopts there is what it trusts afterwards", got)
	}
	// ★ AND NOT THE DEPLOYMENT HOST. Asking for that is the same as asking for nothing.
	if got := fresh.trustBundleServerName(); got == fresh.serverName {
		t.Errorf("it asked for the deployment host %q, which is how this defect happened", got)
	}

	// Once a bundle has been adopted, the announced name governs — that is how an organization is renamed
	// without reinstalling a fleet.
	adopted := transportConfig{
		serverName:           "agents.osaka.example",
		configuredServerName: "c2neh.example",
		announcedServerName:  &atomic.Pointer[string]{},
	}
	announced := "renamed.example"
	adopted.announcedServerName.Store(&announced)
	if got := adopted.trustBundleServerName(); got != "renamed.example" {
		t.Errorf("an adopted announcement no longer outranks the profile: %q", got)
	}

	// A deployment whose organizations have no name of their own asks for nothing, which is correct: it is
	// served the deployment's shared certificate and there is one organization to be.
	none := transportConfig{serverName: "agents.example", announcedServerName: &atomic.Pointer[string]{}}
	if got := none.trustBundleServerName(); got != "" {
		t.Errorf("a deployment with no per-organization name asked for %q", got)
	}
}
