//go:build windows

// vm_egress_windows.go — enforcing the organization's decision about virtual machines on this device.
// See vm_egress.go for what was measured and why the default is to block.
package main

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// ★★★ THE ORDINARY FIREWALL CANNOT DO THIS, WHICH IS THE WHOLE POINT (2026-09-01).
//
// An outbound Windows Firewall rule — what quicblock_windows.go uses for UDP:443 — matches traffic from
// processes on THIS stack. A guest's traffic is not from a process here; it is why the connect-time classifier
// misses it, and it is why an outbound rule would miss it too. Reaching for the tool next door because it is
// the tool next door is how a block gets installed, reports success, and stops nothing.
//
// Windows has a separate control for exactly this surface: the Hyper-V firewall, which governs traffic of the
// virtual machines behind the virtual switch rather than of processes on the host. The box this was measured
// on already lists an interface named "vEthernet (WSL (Hyper-V firewall))", so the feature is present where
// the hole is.
//
// ★ AND THE VM CREATOR IS NAMED, NOT GUESSED. WSL's containers are one "VM creator" with a fixed id; Hyper-V's
// own guests are another. Blocking by creator reaches every distro, including one a standard user imports
// afterwards — which is the case that made this a hole rather than a configuration mistake. A rule bound to
// the distros that exist today would be stepped around by importing a new one, and that import needs no
// administrator.
// ★★★ THE CREATORS ARE ASKED FOR, NOT WRITTEN DOWN (2026-09-01). The first version of this file carried two
// GUIDs: WSL's, which is well known, and one for Hyper-V's own guests that I had written from memory. That is
// the defect this deployment has been naming all day — the near thing with a similar name — and here it would
// have been silent: a wrong creator id sets nothing, the cmdlet may still succeed, and the box goes on
// carrying guest traffic while the profile says it does not.
//
// So the box is asked which VM creators it has, and every one of them is set. That also covers the case that
// made this a hole: a standard user importing a new distro afterwards is a new CONTAINER under an existing
// creator, not a new creator, so it is already governed.
//
// A box that reports none is not silently compliant — see applyVMEgress.
func vmEgressCreators() ([]string, error) {
	list, err := hiddenPowerShell("(Get-NetFirewallHyperVVMCreator -ErrorAction Stop).VMCreatorId")
	if err != nil {
		return nil, err
	}
	out, err := runBoundedOutput(list, 20*time.Second)
	if err != nil {
		return nil, fmt.Errorf("this box could not be asked which virtual-machine creators it has: %w", err)
	}
	var creators []string
	for _, line := range strings.Split(out, "\n") {
		if id := strings.TrimSpace(line); id != "" {
			creators = append(creators, id)
		}
	}
	return creators, nil
}

func applyVMEgress(d vmEgressDecision) error {
	action := "Allow"
	if d.Block {
		action = "Block"
	}
	creators, err := vmEgressCreators()
	if err != nil {
		return fmt.Errorf("virtual-machine egress: %w", err)
	}
	if len(creators) == 0 {
		// ★ NOT SILENTLY COMPLIANT. No creators means either this box runs no virtual machines — fine — or
		// that this Windows has no Hyper-V firewall to govern the ones it does. The two are the same empty
		// answer here and must not read the same, so the caller says so and the fleet view carries it.
		return fmt.Errorf("virtual-machine egress could not be %s: this box reports no virtual-machine "+
			"creators, so either it runs none or this Windows offers no control over the ones it runs",
			strings.ToLower(action))
	}
	var failures []string
	for _, creator := range creators {
		set, perr := hiddenPowerShell(fmt.Sprintf(
			"Set-NetFirewallHyperVVMSetting -Name '%s' -DefaultOutboundAction %s -ErrorAction Stop", creator, action))
		if perr != nil {
			return fmt.Errorf("virtual-machine egress: %w", perr)
		}
		if out, cerr := set.CombinedOutput(); cerr != nil {
			// Not fatal on its own: a box with no Hyper-V firewall, or without that creator, answers here. It
			// is collected and reported, because "this creator could not be set" is exactly the state an
			// operator must not have to infer from a device that looks compliant.
			failures = append(failures, fmt.Sprintf("%s: %v: %s", creator, cerr, strings.TrimSpace(string(out))))
			continue
		}
		if err := confirmVMEgress(creator, action); err != nil {
			failures = append(failures, err.Error())
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("virtual-machine egress is NOT enforced as the profile says (%s): %s",
			strings.ToLower(action), strings.Join(failures, "; "))
	}
	return nil
}

// confirmVMEgress reads back what the box will actually do. The answer, not the exit code.
func confirmVMEgress(creator, want string) error {
	get, err := hiddenPowerShell(fmt.Sprintf(
		"(Get-NetFirewallHyperVVMSetting -Name '%s' -ErrorAction Stop).DefaultOutboundAction", creator))
	if err != nil {
		return fmt.Errorf("%s: %v", creator, err)
	}
	out, err := runBoundedOutput(get, 20*time.Second)
	if err != nil {
		return fmt.Errorf("%s: could not be read back: %v", creator, err)
	}
	got := strings.TrimSpace(out)
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("%s: the box says %q after being set to %q", creator, got, want)
	}
	return nil
}

// runBoundedOutput is runBounded's answering form: a session-0 service must not be hung by a cmdlet, and this
// one is asked a question whose ANSWER is the point.
func runBoundedOutput(c *exec.Cmd, d time.Duration) (string, error) {
	// ★★★ START ONCE. The first version called c.Start() and THEN c.Output() in the goroutine — and Output
	// starts the command itself, so on a real box every call returned "exec: already started" and NOTHING was
	// ever read. vmEgressCreators could not enumerate, so VM-egress was never applied: the box printed the
	// decision, could not carry it, and (correctly) shouted the fail-loud WARNING — measured on win-dev-1
	// 2026-09-01, the first time this ran as the service rather than in a unit test. The unit tests exercised
	// the decision logic, not this exec path; the standalone cmdlet measurement called the cmdlets directly,
	// not through here; only the agent, running, with a real creator to list, reached the double start.
	var buf bytes.Buffer
	c.Stdout = &buf
	if err := c.Start(); err != nil {
		return "", err
	}
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	select {
	case err := <-done:
		return buf.String(), err
	case <-time.After(d):
		_ = c.Process.Kill()
		<-done // reap the Wait goroutine so it cannot leak
		return "", fmt.Errorf("timed out after %s", d)
	}
}
