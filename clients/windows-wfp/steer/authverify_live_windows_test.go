//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestImageSignatureLive exercises the REAL Authenticode path (WinVerifyTrust + signer extraction) against a
// known Microsoft-signed system binary and an unsigned file, then proves the spoof-resistance end to end:
// copying the MS-signed binary under a path containing "automation" defeats the legacy substring rule but NOT a
// publisher:/signed: rule (the copy keeps its true Microsoft signer + its real basename).
func TestImageSignatureLive(t *testing.T) {
	// node.exe is EMBEDDED Authenticode-signed (signer "OpenJS Foundation"). NOTE: Windows system binaries
	// like notepad.exe/cmd.exe are CATALOG-signed (.cat, not embedded); WinVerifyTrust on the file alone
	// reports them unsigned. Catalog-aware verification is a forward item — the steer-exclusion targets
	// (third-party apps: Automation, VPN clients, browsers) are embedded-signed, which this covers.
	signed := `C:\Program Files\nodejs\node.exe`
	if _, err := os.Stat(signed); err != nil {
		t.Skip("node.exe not present")
	}
	sig := imageSignature(signed)
	if !sig.valid {
		t.Fatalf("node.exe should be Authenticode-valid; got valid=false")
	}
	if !strings.Contains(strings.ToLower(sig.publisher), "openjs") {
		t.Fatalf("node.exe signer = %q, want contains 'OpenJS'", sig.publisher)
	}
	t.Logf("node.exe -> valid=%v publisher=%q org=%q thumbprint=%q", sig.valid, sig.publisher, sig.org, sig.thumbprint)

	// unsigned content -> not valid
	junk := filepath.Join(t.TempDir(), "junk.exe")
	if err := os.WriteFile(junk, []byte("not a real PE"), 0o644); err == nil {
		if imageSignature(junk).valid {
			t.Errorf("unsigned junk.exe should be invalid")
		}
	}

	// SPOOF: copy the signed binary under ...\automation\ (path contains the excluded substring). A byte copy
	// keeps the embedded signature, so the copy is still validly OpenJS-signed with basename node.exe.
	spoofDir := filepath.Join(t.TempDir(), "automation")
	if err := os.MkdirAll(spoofDir, 0o755); err != nil {
		t.Fatal(err)
	}
	spoof := filepath.Join(spoofDir, "node.exe")
	data, err := os.ReadFile(signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(spoof, data, 0o644); err != nil {
		t.Fatal(err)
	}
	b := &appBypass{sigCache: map[string]sigResult{}}
	lower := strings.ToLower(spoof)
	base := strings.ToLower(filepath.Base(spoof))

	checks := []struct {
		rule string
		want bool
		why  string
	}{
		{"automation", true, "legacy substring matches any path containing 'automation' (the spoof hole)"},
		{"publisher:anthropic", false, "an OpenJS-signed binary is not Anthropic-signed"},
		{"signed:automation.exe", false, "basename is node.exe, not automation.exe"},
		{"publisher:openjs", true, "the copy is still validly OpenJS-signed"},
		{"signed:node.exe", true, "validly signed AND basename matches"},
	}
	for _, c := range checks {
		if got := b.matchAppRule(c.rule, lower, base); got != c.want {
			t.Errorf("matchAppRule(%q) = %v, want %v (%s)", c.rule, got, c.want, c.why)
		}
	}
	t.Logf("spoof ...\\automation\\node.exe: legacy 'automation'=bypassed, publisher:anthropic=BLOCKED, signed:automation.exe=BLOCKED, publisher:openjs=bypassed")
}
