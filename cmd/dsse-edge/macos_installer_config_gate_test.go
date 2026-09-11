package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The macOS package refuses to install unless a usable agent configuration is ALREADY on the Mac
// (deploy/reference/build_macos_ne_pkg.sh, preinstall). That gate compares the config's schema_version against
// a string baked into the installer — and the config is written by the publisher in this package.
//
// Two strings, two files, one meaning. Drift them and the failure is total and silent until it reaches a
// customer: every install refuses a configuration that is perfectly correct, and the package still builds,
// signs and notarizes, because nothing in the build touches the publisher. Pin them together here, the same way
// TestMacOSPackagingContractMatchesSource pins the principal class and the config directory.
const packagingScript = "../../clients/macos-network-extension/packaging/build_macos_ne_pkg.sh"

func TestMacOSInstallerConfigSchemaMatchesPublisher(t *testing.T) {
	data, err := os.ReadFile(packagingScript)
	if err != nil {
		t.Fatalf("read %s: %v", packagingScript, err)
	}
	m := regexp.MustCompile(`config_schema="([^"]+)"`).FindSubmatch(data)
	if m == nil {
		t.Fatalf("%s: no config_schema= assignment — the installer's config gate moved or was renamed; "+
			"update this guard deliberately", packagingScript)
	}
	installer := string(m[1])

	// The value the control plane actually writes, read from the publisher itself rather than restated here —
	// a test that repeats the constant proves only that the test agrees with itself.
	published := (&localNetworkExtensionSnapshotPublisher{}).agentConfig("tenant_lab_001")["schema_version"]
	if installer != published {
		t.Errorf("the installer gate demands schema %q but the publisher writes %q — every install would refuse "+
			"a correct configuration, and the package would build and notarize cleanly anyway", installer, published)
	}
}

// The gate must actually be wired in. It is easy to leave a well-written check in the file and not reach it —
// the preinstall exits 0 on several earlier paths — so assert the refusals exist and are placed before the
// point of no return.
func TestMacOSInstallerRefusesWithoutConfiguration(t *testing.T) {
	data, err := os.ReadFile(packagingScript)
	if err != nil {
		t.Fatalf("read %s: %v", packagingScript, err)
	}
	src := string(data)

	for _, want := range []string{
		`[ -f "$CONFIG" ] || refuse`,                  // present at all
		`plutil -convert xml1 -o /dev/null "$CONFIG"`, // parses as JSON
		`[ -n "$(cfg edge_url)" ] || refuse`,          // has an edge to talk to
		// ★ The FULL key. An earlier version of the gate checked "transport.transport_tls_url", which does not
		// exist in a deployed configuration — the provider reads network_extension_transport. The short name
		// looked right in review and was simply absent on every real device.
		`[ -n "$(cfg network_extension_transport.transport_tls_url)" ]`,
		`read_keys update_signing_keys`, // and can ever be updated
		`[ "$owner" = "0" ]`,            // and only root can rewrite the keys that install software
	} {
		if !strings.Contains(src, want) {
			t.Errorf("the preinstall config gate no longer contains %q — the package would install an agent that "+
				"steers this Mac's traffic with nowhere to send it", want)
		}
	}

	// ★ plutil -lint on a JSON file rejects VALID json with the same message it gives for corrupt json, so it
	// cannot distinguish the two. It must never come back as the parse check.
	if regexp.MustCompile(`plutil -lint "?\$CONFIG`).MatchString(src) {
		t.Error(`the config gate uses "plutil -lint" on the agent config: that lints as a PROPERTY LIST and ` +
			`rejects valid JSON, so every install would refuse. Use "plutil -convert".`)
	}

	// ★ The update key and the plan key must be checked for being DIFFERENT keys. One key for both means the
	// party a freeze exists to stop is the party who signs the freeze — and unlike the other conditions this one
	// cannot be noticed by looking at a working device, because everything works right up until it matters.
	if !strings.Contains(src, `|| refuse \`) || !strings.Contains(src, "must not also sign the policy") {
		t.Error("the gate no longer refuses one key serving as both the update authority and the agent-policy key")
	}

	// The gate must precede the step that quits the running agent — after that, refusing has already disturbed
	// the machine it claims to have left untouched.
	gate := strings.Index(src, `[ -f "$CONFIG" ] || refuse`)
	quit := strings.Index(src, `osascript -e 'quit app`)
	if gate < 0 || quit < 0 || gate > quit {
		t.Errorf("the configuration gate must run BEFORE the agent is quit (gate at %d, quit at %d)", gate, quit)
	}
}

// ★ THE INSTALLER AND THE PUBLISHER MUST NAME THE SAME FIELDS (2026-08-16). The agent's trusted authorities
// are fixed at install, so the installer reads them out of the configuration — and it reads them by NAME.
// This file already records the same mistake twice: a gate written from what the code was imagined to emit
// ("transport.transport_tls_url", "schema_version") refused healthy machines, because the name it checked did
// not exist in a deployed configuration.
//
// So the names are pinned to the publisher that writes them rather than restated. A test that repeats the
// strings proves only that the test agrees with itself.
func TestInstallerReadsTheTrustedCABundleFieldsThePublisherWrites(t *testing.T) {
	data, err := os.ReadFile(packagingScript)
	if err != nil {
		t.Fatalf("read %s: %v", packagingScript, err)
	}
	script := string(data)

	publisher := &localNetworkExtensionSnapshotPublisher{}
	publisher.SetTrustedCABundleSource(func(tenantID string) map[string]any {
		return map[string]any{"tenant_id": tenantID, "interception_root_pem": "-----BEGIN CERTIFICATE-----"}
	})
	written, ok := publisher.agentConfig("tenant_lab_001")["trusted_ca_bundle"].(map[string]any)
	if !ok {
		t.Fatal("the publisher does not write trusted_ca_bundle at all — the installer would read a field nobody emits")
	}

	for field := range written {
		if field != "tenant_id" && field != "interception_root_pem" {
			continue
		}
		if !strings.Contains(script, "trusted_ca_bundle."+field) {
			t.Errorf("the publisher writes trusted_ca_bundle.%s and the installer never reads it", field)
		}
	}
	// And absence must NOT refuse: every configuration already on a Mac predates the field, so a hard
	// requirement today refuses every install on the fleet — the exact failure this file records twice.
	if strings.Contains(script, `[ -n "$bundle_root" ] || refuse`) {
		t.Error("the installer refuses a configuration with no trusted_ca_bundle; every Mac in the field has one of those")
	}
}

// ★★★ A FRESH ENROLMENT TOKEN MUST RE-DERIVE THE CONFIGURATION (2026-09-01, measured on a real Mac against a
// live deployment).
//
// The postinstall skips the derivation when the configuration on the machine was written from this profile by
// this build. The one-time enrolment token is neither: it is consumed on first use, so a device whose first
// enrolment did not complete needs a new one — and this package's own failure message tells the operator to
//
//	Place it and re-run the installer; nothing else is needed.
//
// The re-run found the same profile and the same build, skipped, and left the SPENT token in the
// configuration. Measured: the control plane answered "enrolment token has already been used" while the token
// just issued for that machine showed used_at=null. The instruction the operator was following could not work,
// and no amount of repeating it would have helped.
//
// So the marker must name the token as well. Read from the script, because that is where the skip lives.
func TestMacOSInstallerRederivesWhenTheEnrolmentTokenChanges(t *testing.T) {
	data, err := os.ReadFile(packagingScript)
	if err != nil {
		t.Fatalf("read %s: %v", packagingScript, err)
	}
	m := regexp.MustCompile(`want="\$\(dsse_profile_issued_at "\$profile"\)([^"]*)"`).FindSubmatch(data)
	if m == nil {
		t.Fatalf("%s: no want= assignment for the derivation marker — it moved or was renamed; update this "+
			"guard deliberately", packagingScript)
	}
	if rest := string(m[1]); !strings.Contains(rest, "token_digest") {
		t.Errorf("the derivation marker is profile+%q and does not name the enrolment token: a device whose "+
			"first enrolment failed can never enrol again, because re-running the installer with a fresh "+
			"token leaves the spent one in place", rest)
	}
	// ★ AND THE SECRET ITSELF IS NEVER THE MARKER. derived_by.txt is world-readable; a digest is the whole
	// point of writing one.
	if !regexp.MustCompile(`token_digest="\$\(/usr/bin/shasum[^)]*\)"`).Match(data) {
		t.Error("token_digest is not computed with shasum — the marker must carry a digest of the token, " +
			"never the token, because derived_by.txt is readable by anyone on the machine")
	}
}
