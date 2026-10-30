//go:build windows

package main

import (
	"fmt"
	"time"
)

// removeOwnedFirewallRules reports success only after the exact rule selector
// is absent in an independent readback. A missing rule is an idempotent success;
// command start, timeout, deletion and readback failures are not.
func removeOwnedFirewallRules(property, value string, timeout time.Duration) error {
	script, err := firewallCleanupScript(property, value)
	if err != nil {
		return err
	}
	cmd, err := hiddenPowerShell(script)
	if err != nil {
		return err
	}
	output, err := runBoundedOutput(cmd, timeout)
	if err != nil {
		return fmt.Errorf("firewall cleanup command: %w", err)
	}
	if !firewallCleanupCompleted(output) {
		return fmt.Errorf("firewall cleanup did not confirm rule absence")
	}
	return nil
}
