//go:build windows

package main

import "testing"

// TestMatchAppRuleDispatch covers the three exclusion-identifier forms with INJECTED signature results
// (the real Authenticode lookup is exercised live, not in unit tests). The point: publisher:/signed: rules
// reject a spoof (an unsigned binary placed under a path that merely CONTAINS the name), which the legacy
// substring rule accepts.
func TestMatchAppRuleDispatch(t *testing.T) {
	b := &appBypass{sigCache: map[string]sigResult{}}
	const spoof = `c:\users\x\appdata\local\automation\evil.exe` // unsigned, path contains "automation"
	const real = `c:\program files\anthropic\automation.exe`     // genuinely signed by Anthropic
	b.sigCache[spoof] = sigResult{valid: false, publisher: ""}
	b.sigCache[real] = sigResult{valid: true, publisher: "anthropic, pbc"}

	cases := []struct {
		name string
		rule string
		path string
		base string
		want bool
	}{
		{"legacy substring matches the spoof (the weakness)", "automation", spoof, "evil.exe", true},
		{"publisher rejects the unsigned spoof", "publisher:anthropic", spoof, "evil.exe", false},
		{"publisher accepts the genuine signed binary", "publisher:anthropic", real, "automation.exe", true},
		{"publisher rejects a wrong publisher", "publisher:microsoft", real, "automation.exe", false},
		{"signed accepts valid signature + exact basename", "signed:automation.exe", real, "automation.exe", true},
		{"signed rejects the unsigned spoof", "signed:automation.exe", spoof, "evil.exe", false},
		{"signed rejects exact-name-but-unsigned", "signed:evil.exe", spoof, "evil.exe", false},
		{"empty publisher target never matches", "publisher:", real, "automation.exe", false},
	}
	for _, c := range cases {
		if got := b.matchAppRule(c.rule, c.path, c.base); got != c.want {
			t.Errorf("%s: matchAppRule(%q,...) = %v, want %v", c.name, c.rule, got, c.want)
		}
	}
}

// TestMatchAppRuleStrongIdentity covers the AppID-parity forms: subject: (Subject O= exact, the Team-ID analog)
// and thumbprint: (leaf cert SHA-256 exact, the strongest pin). Both bind to the cryptographic signer identity,
// not a basename or path — so they reject a different-but-validly-signed binary that signed:/substring accept.
func TestMatchAppRuleStrongIdentity(t *testing.T) {
	b := &appBypass{sigCache: map[string]sigResult{}}
	const real = `c:\program files\anthropic\automation.exe`
	const impostor = `c:\program files\evilcorp\automation.exe` // also validly signed, but by someone else
	const unsigned = `c:\tmp\automation.exe`
	b.sigCache[real] = sigResult{valid: true, publisher: "anthropic, pbc", org: "anthropic, pbc", thumbprint: "aabbccdd"}
	b.sigCache[impostor] = sigResult{valid: true, publisher: "evil corp", org: "evil corp", thumbprint: "11223344"}
	b.sigCache[unsigned] = sigResult{valid: false}

	cases := []struct {
		name string
		rule string
		path string
		base string
		want bool
	}{
		{"subject matches the exact signer org", "subject:anthropic, pbc", real, "automation.exe", true},
		{"subject rejects a different signer (same basename, validly signed)", "subject:anthropic, pbc", impostor, "automation.exe", false},
		{"subject rejects unsigned", "subject:anthropic, pbc", unsigned, "automation.exe", false},
		{"subject is exact, not substring", "subject:anthropic", real, "automation.exe", false},
		{"thumbprint matches the exact leaf cert", "thumbprint:aabbccdd", real, "automation.exe", true},
		{"thumbprint tolerates colon-separated form", "thumbprint:aa:bb:cc:dd", real, "automation.exe", true},
		{"thumbprint rejects a different cert", "thumbprint:aabbccdd", impostor, "automation.exe", false},
		{"signed: would WRONGLY accept the impostor (why subject:/thumbprint: exist)", "signed:automation.exe", impostor, "automation.exe", true},
		{"empty subject never matches", "subject:", real, "automation.exe", false},
		{"empty thumbprint never matches", "thumbprint:", real, "automation.exe", false},
	}
	for _, c := range cases {
		if got := b.matchAppRule(c.rule, c.path, c.base); got != c.want {
			t.Errorf("%s: matchAppRule(%q,...) = %v, want %v", c.name, c.rule, got, c.want)
		}
	}
}

// TestIsSignatureRuleCoversStrongForms ensures subject:/thumbprint: are classed as signature rules (enforced in
// userspace; skipped — fail-closed/still-steered — by the kernel WFP backend until Phase 2).
func TestIsSignatureRuleCoversStrongForms(t *testing.T) {
	for _, r := range []string{"subject:anthropic, pbc", "thumbprint:aabb", "publisher:x", "signed:a.exe"} {
		if !isSignatureRule(r) {
			t.Errorf("isSignatureRule(%q) = false, want true", r)
		}
	}
	for _, r := range []string{"automation", "chrome.exe", ""} {
		if isSignatureRule(r) {
			t.Errorf("isSignatureRule(%q) = true, want false (legacy path substring)", r)
		}
	}
}
