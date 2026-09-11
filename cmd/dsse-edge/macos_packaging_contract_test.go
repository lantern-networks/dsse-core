package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The macOS NE Info.plist principal class and the provider config directory are BUILD-TIME CONTRACTS between
// the (sanitized, Dsse*) Swift source and the packaging tooling that writes the deployed bundle. When the OSS
// sanitization renamed Dsse* -> Dsse*, the Swift source moved but the packaging generators did not — so
// a repackage produced an Info.plist whose principal class / config dir disagreed with the compiled binary.
// That shipped a real outage twice on 2026-06-22 (the OS logged "No such class" and the provider failed to
// find its agent_config; the tunnel went connecting->disconnected and the NE intercepted nothing).
//
// These guards pin the contract the same way TestNoStaleRenamedWireContractStrings pins the wire strings: the
// packaging generators' EXPECTED_* constants MUST equal the Swift source's required* constants. If either side
// drifts (e.g. a future rename touches only one), this fails in CI instead of at deploy time.
//
// NOTE: this is independent of the product bundle id (the product bundle id), which intentionally keeps
// the product codename until the company-setup re-signing. The principal class follows the *Swift module*
// (Dsse*); the config dir is the de-codenamed path (.../Dsse). Do not "fix" either back to Dsse*.

const (
	swiftProviderSource = "../../clients/macos-network-extension/Sources/DsseAppProxyProviderSkeleton/DsseAppProxyProvider.swift"
	// ★★★ THE THING THAT ACTUALLY BUILDS THE BUNDLE (2026-09-04). This used to read two Ruby generators in
	// prototype/scripts — which are stale-guarded and exit 2, predate the OSS extraction, and are OUTSIDE the
	// published tree, so in a clone of that tree this test failed on a file the reader was never given. The
	// bundle is assembled by the shell script beside the Swift package, and that is what has to agree with the
	// source: it writes the Info.plist whose NEProviderClasses value the OS instantiates.
	appBuilder = "../../clients/macos-network-extension/packaging/build_macos_ne_app.sh"
	pkgBuilder = "../../clients/macos-network-extension/packaging/build_macos_ne_pkg.sh"
)

func extractFirst(t *testing.T, path, pattern string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	re := regexp.MustCompile(pattern)
	m := re.FindSubmatch(data)
	if m == nil {
		t.Fatalf("%s: could not find a value matching %q — the contract source moved or was renamed; "+
			"update this guard deliberately", path, pattern)
	}
	return string(m[1])
}

// TestMacOSPackagingContractMatchesSource asserts the packaging generators emit the SAME principal class and
// agent-config dir the Swift provider actually uses. Any drift (the exact class of bug that took the NE down
// on 2026-06-22) fails here.
func TestMacOSPackagingContractMatchesSource(t *testing.T) {
	// Swift source of truth.
	srcClass := extractFirst(t, swiftProviderSource, `static let requiredPrincipalClass\s*=\s*"([^"]+)"`)
	srcConfigDir := extractFirst(t, swiftProviderSource, `static let productionAgentConfigDirectory\s*=\s*"([^"]+)"`)

	// Sanity: the source must already be on the sanitized Dsse names / de-codenamed path. If this trips, the
	// source itself regressed.
	if srcClass != "DsseAppProxyProviderSkeleton.DsseAppProxyProvider" {
		t.Errorf("Swift requiredPrincipalClass = %q, want the sanitized Dsse class", srcClass)
	}
	if srcConfigDir != "/Library/Application Support/Dsse" {
		t.Errorf("Swift productionAgentConfigDirectory = %q, want the de-codenamed /Library/Application Support/Dsse", srcConfigDir)
	}

	// The class the app builder writes into the extension's Info.plist, under the App Proxy extension point.
	builtClass := extractFirst(t, appBuilder,
		`com\.apple\.networkextension\.app-proxy</key><string>([^<]+)</string>`)
	if builtClass != srcClass {
		t.Errorf("%s writes NEProviderClasses = %q, but the Swift binary's class is %q — the built bundle would "+
			"carry an Info.plist the OS cannot instantiate (\"No such class\"). Align the builder to the source.",
			appBuilder, builtClass, srcClass)
	}

	// And the directory the package installs into has to be the one the provider reads, or a fresh install
	// puts configuration where nothing looks for it (startProxy lifecycle_failed=missing_agent_config_path).
	if !strings.Contains(readFileForTest(t, pkgBuilder), srcConfigDir) {
		t.Errorf("%s never names %q — the provider reads that directory, so the package has to install into it",
			pkgBuilder, srcConfigDir)
	}
}
