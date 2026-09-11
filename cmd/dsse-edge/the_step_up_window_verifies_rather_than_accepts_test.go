package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ★★★ THE macOS STEP-UP WINDOW SHIPPED A TLS BYPASS FOR TWO NAMED HOSTS (2026-09-03, found after the operator
// pointed out that out-of-band step-up exists on macOS too — I had said it did not).
//
//	private let labTrustedHosts: Set<String> = ["203.0.113.10", "kc.dsse.lab"]
//
// For those hosts the challenge handler returned .useCredential with whatever certificate was presented. It
// was written as "lab-only, tightly scoped" and compiled into the signed product; 203.0.113.10 is a private
// address common enough that somebody will eventually run something there, and a bypass keyed on a hostname
// trusts whoever answers to it.
func TestTheMacStepUpWindowDoesNotShipATrustBypass(t *testing.T) {
	errorLine := func(gone, line string) { t.Errorf("%s is back in code, not in the note: %s", gone, line) }
	path := filepath.Join("..", "..", "clients", "macos-network-extension", "Sources",
		"DsseAgentAppExecutable", "StepUpAuthWindow.swift")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Skip("the macOS window is not in this tree")
	}
	src := string(body)
	// The list itself and the addresses it held — in CODE. They are named in the note that records what was
	// removed, which is the point of the note: a check that forbade mentioning them would delete the record
	// of why this exists.
	for _, line := range strings.Split(src, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || t == "" {
			continue
		}
		for _, gone := range []string{"labTrustedHosts", "203.0.113.10", "kc.dsse.lab"} {
			if strings.Contains(t, gone) {
				errorLine(gone, t)
			}
		}
	}
	// It must EVALUATE, not accept: anchors set, anchors-only, and a real evaluation.
	for _, want := range []string{"SecTrustSetAnchorCertificates(", "SecTrustSetAnchorCertificatesOnly(",
		"SecTrustEvaluateWithError("} {
		if !strings.Contains(src, want) {
			t.Errorf("the window does not %s — it is accepting rather than verifying", want)
		}
	}
	if !strings.Contains(src, "cancelAuthenticationChallenge") {
		t.Error("a portal certificate that does not chain to the named authority is not refused")
	}
	// And the anchor comes from the profile, which is where the deployment names it.
	if !strings.Contains(src, `"step_up_portal_anchor_pem"`) {
		t.Error("the window does not read the authority the deployment names for its portal")
	}
}
