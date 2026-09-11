//go:build windows

package main

import (
	"strings"
	"testing"
)

func TestOSDescription(t *testing.T) {
	os := osDescription()
	if os == "" {
		t.Fatal("osDescription() empty; expected a Windows version string")
	}
	if !strings.HasPrefix(os, "Windows") {
		t.Fatalf("osDescription() = %q, expected to start with 'Windows'", os)
	}
	if strings.Contains(os, "\r") || strings.Contains(os, "\n") {
		t.Fatalf("osDescription() = %q must not contain CR/LF", os)
	}
	t.Logf("OS = %q", os)
}

func TestDiskEncryptionStatus(t *testing.T) {
	enc := diskEncryptionStatus()
	switch enc {
	case "on", "off", "":
		t.Logf("disk encryption (BitLocker) = %q", enc)
	default:
		t.Fatalf("diskEncryptionStatus() = %q, want on/off/empty", enc)
	}
}

func TestFirewallStatus(t *testing.T) {
	fw := firewallStatus()
	switch fw {
	case "on", "off", "":
		t.Logf("firewall = %q", fw)
	default:
		t.Fatalf("firewallStatus() = %q, want on/off/empty", fw)
	}
}

// The CONNECT header block must be well-formed: CRLF-terminated "Name: value" lines, no bare LF, and (when any
// posture is present) a source tag.
func TestDeviceConnectHeadersWellFormed(t *testing.T) {
	h := collectDeviceConnectHeaders()
	if h == "" {
		t.Skip("no device signals readable in this environment")
	}
	for _, line := range strings.Split(strings.TrimSuffix(h, "\r\n"), "\r\n") {
		if !strings.HasPrefix(line, "X-Dsse-") || !strings.Contains(line, ": ") {
			t.Fatalf("malformed header line %q in:\n%s", line, h)
		}
	}
	if !strings.HasSuffix(h, "\r\n") {
		t.Fatalf("header block must end with CRLF:\n%q", h)
	}
	if (strings.Contains(h, "X-Dsse-Posture-Encryption") || strings.Contains(h, "X-Dsse-Posture-Firewall")) &&
		!strings.Contains(h, "X-Dsse-Posture-Source: windows_collector") {
		t.Fatalf("posture present but source tag missing:\n%s", h)
	}
	t.Logf("headers:\n%s", h)
}
