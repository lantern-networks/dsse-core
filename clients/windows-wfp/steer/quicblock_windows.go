//go:build windows

// quicblock_windows.go — optional QUIC (UDP:443) block for the steer-all default posture. The WFP callout
// steers TCP; a browser's HTTP/3 attempt over UDP:443 is not steered and stalls before the browser falls
// back to TCP (which IS intercepted) — measured ~28s -> ~16s page load when UDP:443 is blocked. Blocking
// QUIC forces the browser onto the intercepted TCP path immediately. There is no un-intercepted QUIC escape
// either way; this only removes the fallback stall. Implemented as a Windows Firewall rule (visible,
// reversible) rather than a kernel change.
package main

import (
	"fmt"
	"os/exec"
	"syscall"
	"time"

	"github.com/lantern-networks/dsse-core/clients/windows-wfp/winbin"
)

const quicBlockRuleName = "DSSE steer-all block QUIC (udp443)"

// From the system directory, never %PATH% — see package winbin. netsh here changes the machine's firewall from
// a process running as SYSTEM, which is the last place to accept whatever answers a search first.
func hiddenNetsh(args ...string) (*exec.Cmd, error) {
	netsh, err := winbin.System("netsh.exe")
	if err != nil {
		return nil, err
	}
	c := exec.Command(netsh, args...)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return c, nil
}

// addQUICBlock installs an outbound block for UDP:443 (idempotent — any stale rule is removed first).
func addQUICBlock() error {
	if err := removeQUICBlock(); err != nil {
		return fmt.Errorf("remove previous QUIC block before add: %w", err)
	}
	c, err := hiddenNetsh("advfirewall", "firewall", "add", "rule",
		"name="+quicBlockRuleName, "dir=out", "action=block", "protocol=UDP", "remoteport=443", "profile=any")
	if err != nil {
		return fmt.Errorf("add QUIC block rule: %w", err)
	}
	out, err := c.CombinedOutput()
	if err != nil {
		return fmt.Errorf("add QUIC block rule: %v: %s", err, out)
	}
	return nil
}

// removeQUICBlock confirms that the exact DSSE rule is absent. A rule that
// outlives the agent blocks native UDP:443, so callers must report failures.
func removeQUICBlock() error {
	return removeOwnedFirewallRules("DisplayName", quicBlockRuleName, 15*time.Second)
}
