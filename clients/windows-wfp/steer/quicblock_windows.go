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
	"os"
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
	removeQUICBlock()
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

// removeQUICBlock deletes the QUIC block rule (best-effort, on shutdown). NOTE: a force-kill skips this, so
// the rule persists — remove manually with `netsh advfirewall firewall delete rule name="<quicBlockRuleName>"`.
func removeQUICBlock() {
	c, err := hiddenNetsh("advfirewall", "firewall", "delete", "rule", "name="+quicBlockRuleName)
	if err != nil {
		// Said out loud rather than dropped: this runs on shutdown, and a rule that outlives the agent blocks
		// UDP:443 on a machine nobody is steering any more. The note names what to remove by hand, which the
		// comment above already documents.
		fmt.Fprintf(os.Stderr, "quic block: the rule could NOT be removed (%v) — UDP:443 stays blocked on this box "+
			"until `netsh advfirewall firewall delete rule name=%q` is run\n", err, quicBlockRuleName)
		return
	}
	// Bounded (review C-2): netsh must not be able to hang a session-0 recover custom action.
	runBounded(c, 15*time.Second)
}
