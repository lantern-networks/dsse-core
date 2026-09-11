package main

import (
	"strings"
	"testing"
)

// ★★★ THE CONFIGURATION THIS PRODUCT PUBLISHES WAS ONE ITS OWN INSTALLER REFUSES — AGAIN (2026-08-27,
// measured by building the real signed, notarised .pkg and running its preinstall against a published
// configuration).
//
//	REFUSING TO INSTALL: the agent configuration names no update_publisher_team_id. Without it this Mac
//	installs whatever a signed manifest points at, as root, without checking who built it — and the Apple
//	Developer ID signature the packages already carry goes unused.
//
// This file already records the same shape for update_signing_keys, fixed on 2026-08-16: "the artifact the
// product publishes could not be used for an install at all: every attempt would stop at that refusal, and
// the reason would look like a broken installer rather than a configuration missing one key". The gate then
// grew a second requirement and the publisher was not told, so the fix held for one field and the next one
// reopened the hole.
//
// The two halves of this product are built and tested apart. What connects them is the FIELD LIST, so the
// list is asserted here rather than rediscovered on a Mac.
func TestThePublishedConfigurationCarriesWhatTheInstallerDemands(t *testing.T) {
	source := readSourceFile(t, "network_extension_snapshot_publisher.go")
	// Every field the macOS preinstall refuses without. Read off the shipping package's own gate.
	for _, field := range []struct{ key, costOfMissing string }{
		{"update_signing_keys", "the Mac installs a security agent it can never patch"},
		{"update_publisher_team_id", "the Mac installs whatever a signed manifest points at, as root, without checking who built it"},
		{"trusted_ca_bundle", "the Mac does not know which organization it belongs to, or what its traffic is re-signed by"},
		{"network_extension_transport", "the provider captures this Mac's traffic with no tunnel to carry it"},
	} {
		if !strings.Contains(source, `config["`+field.key+`"]`) {
			t.Errorf("the published configuration carries no %s, so the endpoint installer refuses every "+
				"install against this deployment — %s", field.key, field.costOfMissing)
		}
	}
}

// ★ AND THE DEPLOYMENT HAS TO BE ABLE TO SAY WHO ITS PUBLISHER IS. A field the publisher emits from a value
// nothing can set is the same hole one level down.
func TestTheDeploymentCanNameThePublisherItTrusts(t *testing.T) {
	// The flag lives beside the rest of the agent-update lane, not in main.go — the decomposition ratchet
	// freezes main.go's flag count, and these only mean anything together.
	source := readSourceFile(t, "steer_agent_update_routes.go") + readSourceFile(t, "main.go")
	if !strings.Contains(source, `"agent-update-publisher"`) {
		t.Error("no flag names the publisher whose packages this deployment's devices may install, so the " +
			"field above can only ever be emitted empty")
	}
	if !strings.Contains(source, "SetUpdatePublisher") {
		t.Error("the publisher identity is never handed to the snapshot publisher, so the flag would set a " +
			"value nothing reads — which is how this field came to be missing in the first place")
	}
}
