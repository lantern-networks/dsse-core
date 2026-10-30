package main

import (
	"fmt"
	"strings"
)

const firewallCleanupComplete = "DSSE-FIREWALL-CLEANUP-COMPLETE"

// Only the two fixed properties used by DSSE-owned rules are accepted. Listing
// all rules makes an absent rule a verified no-op without relying on localized
// netsh or PowerShell "not found" messages.
func firewallCleanupScript(property, value string) (string, error) {
	if property != "DisplayName" && property != "Group" {
		return "", fmt.Errorf("unsupported firewall rule selector")
	}
	if strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("empty firewall rule selector")
	}
	quoted := strings.ReplaceAll(value, "'", "''")
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$matching = @(Get-NetFirewallRule -ErrorAction Stop | Where-Object { $_.%s -ceq '%s' })
if ($matching.Count -gt 0) { $matching | Remove-NetFirewallRule -ErrorAction Stop }
$remaining = @(Get-NetFirewallRule -ErrorAction Stop | Where-Object { $_.%s -ceq '%s' })
if ($remaining.Count -ne 0) { throw 'DSSE firewall cleanup could not verify absence' }
Write-Output '%s'
`, property, quoted, property, quoted, firewallCleanupComplete), nil
}

func firewallCleanupCompleted(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == firewallCleanupComplete {
			return true
		}
	}
	return false
}
