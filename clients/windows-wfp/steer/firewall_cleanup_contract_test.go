package main

import (
	"strings"
	"testing"
)

func TestFirewallCleanupUsesExactOwnedSelectorAndReadback(t *testing.T) {
	for _, tc := range []struct{ property, value string }{
		{"DisplayName", "DSSE steer-all block QUIC (udp443)"},
		{"Group", "DSSE Server-Initiated"},
	} {
		script, err := firewallCleanupScript(tc.property, tc.value)
		if err != nil {
			t.Fatal(err)
		}
		selector := "$_ ." + tc.property
		selector = strings.ReplaceAll(selector, " ", "")
		if strings.Count(script, selector+" -ceq '") != 2 || strings.Count(script, "Get-NetFirewallRule -ErrorAction Stop") != 2 ||
			!strings.Contains(script, "Remove-NetFirewallRule -ErrorAction Stop") ||
			!strings.Contains(script, "$remaining.Count -ne 0") {
			t.Fatalf("cleanup must select only owned rules and verify absence after deletion: %s", script)
		}
		// Listing costs time per rule on the machine: the readback belongs to the
		// deletion branch, so an absent rule is listed once, not twice.
		branch := strings.Index(script, "if ($matching.Count -gt 0) {")
		if branch < 0 || strings.Index(script, "$remaining") < branch || !strings.Contains(script, "throw 'DSSE firewall cleanup could not verify absence' }\n}") {
			t.Fatalf("absence readback must run only after a deletion: %s", script)
		}
	}
	if _, err := firewallCleanupScript("Name; Remove-Item C:\\", "anything"); err == nil {
		t.Fatal("unexpected selector must be rejected")
	}
	if _, err := firewallCleanupScript("Group", ""); err == nil {
		t.Fatal("empty selector must be rejected")
	}
}

func TestFirewallCleanupCompletionRequiresOwnTerminalMarker(t *testing.T) {
	for _, output := range []string{"", "Remove-NetFirewallRule failed", "prefix" + firewallCleanupComplete, firewallCleanupComplete + "suffix"} {
		if firewallCleanupCompleted(output) {
			t.Fatalf("accepted incomplete cleanup output: %q", output)
		}
	}
	if !firewallCleanupCompleted("other output\r\n" + firewallCleanupComplete + "\r\n") {
		t.Fatal("verified cleanup marker rejected")
	}
}
