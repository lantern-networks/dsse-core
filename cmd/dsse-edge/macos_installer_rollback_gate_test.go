package main

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/clients/macos/updateplatform"
)

// The macOS package refuses to install an older build over a newer one, and must keep refusing — an
// unintended downgrade leaves a system extension whose version goes backwards. The single exception is a
// rollback the root updater authorised, and that authorisation is a FILE: one program writes it (Go), another
// reads it (a shell script inside the installer package), and nothing but this test holds the two together.
//
// The failure mode if they drift is total and quiet. The updater writes an authorisation the preinstall does
// not recognise, the guard refuses, and the rollback fails — during the incident that made someone reach for
// it, on a device that has been carrying a package for exactly this purpose all along. Nothing else in the
// build would notice: the package still builds, signs and notarizes.
func TestMacOSInstallerRollbackAuthorisationMatchesTheUpdater(t *testing.T) {
	data, err := os.ReadFile(packagingScript)
	if err != nil {
		t.Fatalf("read %s: %v", packagingScript, err)
	}
	src := string(data)

	// The path the updater writes, spelled out in the script.
	if want := updateplatform.IntentPath(); !strings.Contains(src, `INTENT="`+want+`"`) {
		t.Errorf("the preinstall does not read the authorisation from %q — the updater writes it there and the "+
			"guard would never find it", want)
	}
	// The schema marker, so an incompatible future shape cannot be read as a permissive one.
	if !strings.Contains(src, `"`+updateplatform.IntentSchema+`"`) {
		t.Errorf("the preinstall does not check for schema %q", updateplatform.IntentSchema)
	}

	// Every field the script extracts must be a field the updater actually writes. Read off the struct's JSON
	// tags rather than restated here — a test that repeats the names proves only that it agrees with itself.
	tags := map[string]bool{}
	rt := reflect.TypeOf(updateplatform.Intent{})
	for i := 0; i < rt.NumField(); i++ {
		name, _, _ := strings.Cut(rt.Field(i).Tag.Get("json"), ",")
		tags[name] = true
	}
	for _, field := range []string{"schema", "to_version", "expires_at_unix"} {
		if !tags[field] {
			t.Errorf("the preinstall extracts %q, which the Intent struct no longer writes", field)
		}
		if !strings.Contains(src, "plutil -extract "+field+" raw") {
			t.Errorf("the preinstall no longer reads %q out of the authorisation", field)
		}
	}

	// ★ The three properties that make this an override rather than a hole. Any one of them missing turns the
	// downgrade guard into a formality.
	for _, want := range []string{
		`[ "$owner" = "0" ]`,           // only root may author it
		`[ "$to" = "$AGENT_VERSION" ]`, // and it authorises THIS package, not any downgrade
		`rm -f "$INTENT"`,              // and it is consumed, so it cannot approve a second install
	} {
		if !strings.Contains(src, want) {
			t.Errorf("the rollback authorisation check no longer contains %q — without it, an authorisation left "+
				"on disk (or written by anyone) waves through any downgrade", want)
		}
	}

	// And the refusal itself must survive. The exception exists to make the guard usable, not to remove it.
	if !strings.Contains(src, "refusing to downgrade to $NEW_BUILD") {
		t.Error("the preinstall no longer refuses an UNauthorised downgrade — an accidental one is a system " +
			"extension whose version goes backwards")
	}
	// The version the authorisation is compared against has to be the one the app reports about itself
	// (CFBundleShortVersionString + CFBundleVersion), or the comparison is between two different vocabularies.
	if !strings.Contains(src, `s|__AGENT_VERSION__|${version}+${build}|g`) {
		t.Error("__AGENT_VERSION__ is no longer substituted as ${version}+${build}, which is what " +
			"DsseDeviceHeartbeat.agentVersion() reports and what the rollback store is keyed by")
	}
	if strings.Contains(src, "__AGENT_VERSION__") && !strings.Contains(src, `AGENT_VERSION="__AGENT_VERSION__"`) {
		t.Error("the preinstall no longer bakes in the version this package installs")
	}
}

// A stored package can only be rolled back TO if its own preinstall honours the authorisation — so the
// postinstall states that about the package it just stashed, beside the bytes. Without the marker the updater
// cannot tell, and the refusal arrives as an opaque installer failure during the incident.
func TestMacOSInstallerMarksStoredPackagesAsRollbackable(t *testing.T) {
	data, err := os.ReadFile(packagingScript)
	if err != nil {
		t.Fatalf("read %s: %v", packagingScript, err)
	}
	src := string(data)

	// The suffix the updater looks for, derived from the updater's own function rather than restated.
	suffix := strings.TrimPrefix(updateplatform.AcceptsIntentMarker("PKG"), "PKG")
	if !strings.Contains(src, `"$dst`+suffix+`"`) {
		t.Errorf("the postinstall does not write a %q marker beside the stashed package — every stored package "+
			"would look un-rollbackable to the updater", suffix)
	}
	// And it must state the schema the updater compares against, not merely exist.
	if !strings.Contains(src, `printf '%s\n' "`+updateplatform.IntentSchema+`" > "$dst`+suffix+`"`) {
		t.Errorf("the marker must contain %q: a marker nobody compares is a declared capability nobody checked",
			updateplatform.IntentSchema)
	}
}
