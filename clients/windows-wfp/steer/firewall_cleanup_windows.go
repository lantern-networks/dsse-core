//go:build windows

package main

import (
	"fmt"
	"time"
)

// firewallCleanupTimeout only stops a hung PowerShell from holding recover or
// the MSI uninstall forever. It is not a performance budget: listing rules
// grows with every rule other software has added, and 15 s failed an uninstall
// on a PC with 974 rules (2026-10-29). Both DSSE rule cleanups share it.
const firewallCleanupTimeout = 2 * time.Minute

// removeOwnedFirewallRules reports success only after the exact rule selector
// is absent in an independent readback. A missing rule is an idempotent success;
// command start, timeout, deletion and readback failures are not.
func removeOwnedFirewallRules(property, value string) error {
	script, err := firewallCleanupScript(property, value)
	if err != nil {
		return err
	}
	cmd, err := hiddenPowerShell(script)
	if err != nil {
		return err
	}
	output, err := runBoundedOutput(cmd, firewallCleanupTimeout)
	if err != nil {
		return fmt.Errorf("firewall cleanup command: %w", err)
	}
	if !firewallCleanupCompleted(output) {
		return fmt.Errorf("firewall cleanup did not confirm rule absence")
	}
	return nil
}
