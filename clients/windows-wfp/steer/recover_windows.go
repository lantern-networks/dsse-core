//go:build windows

// recover_windows.go — `--mode recover`: a network "panic button". When the steer agent exits UNCLEANLY
// (force-kill, crash, or a WFP driver fault/BSOD), its deferred teardown never runs and the box is left in a
// state that LOOKS like a dead network — three independent mutations all have to be undone before traffic
// flows again:
//
//  1. DNS is pointed at the local loopback proxy (127.0.0.1:53 / [::1]:53) that is no longer listening, so
//     every name lookup fails. (dns_resolver_windows.go)
//  2. A Windows Firewall rule blocks outbound UDP:443, so even direct QUIC is dropped. (quicblock_windows.go)
//  3. The WFP driver's connect-redirect filters are still installed and steer every outbound TCP flow to the
//     dead local terminator, so even with DNS fixed, TCP connects hang/fail until the driver is unloaded.
//
// Discovering and reversing all three by hand is exactly why "network recovery took a long time". This mode
// does all of it idempotently in one elevated command:
//
//	dsse-steer.exe --mode recover            # full recovery (default)
//	dsse-steer.exe --mode recover --recover-keep-services   # restore network but leave the services installed/stopped
//
// It is safe to run anytime: every step is best-effort and a no-op when its mutation isn't present.
package main

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/lantern-networks/dsse-core/clients/windows-wfp/winbin"
)

// runBounded runs a prepared command with a hard timeout and kills it if it overruns (review C-2). recover's
// child processes (netsh, powershell) can hang on CLR/module init in a session-0 MSI custom-action context; a
// hung child would otherwise block the whole msiexec transaction indefinitely. Best-effort: errors/timeouts are
// swallowed (recover is idempotent and already best-effort per step).
func runBounded(c *exec.Cmd, d time.Duration) {
	if c == nil {
		return
	}
	if err := c.Start(); err != nil {
		return
	}
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	select {
	case <-done:
	case <-time.After(d):
		if c.Process != nil {
			_ = c.Process.Kill()
		}
		<-done // reap
	}
}

// stopServiceIfPresent stops a Windows service by name (best-effort, locale-independent). Returns true if the
// service existed and a stop was issued. Stopping a not-installed/already-stopped service is treated as success.
func stopServiceIfPresent(name string) (issued bool, err error) {
	// ★ sc.exe FROM THE SYSTEM DIRECTORY, and a resolution failure is an ERROR rather than "nothing to stop".
	// The old line resolved it through %PATH% and folded every query failure into `return false, nil` — so on a
	// box where the lookup failed (measured for msiexec on win-dev-1, 2026-08-11; see package winbin) this
	// reported a successful disarm without having asked anything. It is called before handing an endpoint to an
	// installer, and answering "steering is down" when nothing was stopped is the worst direction to be wrong in.
	sc, perr := winbin.System("sc.exe")
	if perr != nil {
		return false, perr
	}
	out, qerr := exec.Command(sc, "query", name).CombinedOutput()
	if strings.Contains(string(out), "1060") { // 1060 = service does not exist
		return false, nil
	}
	if qerr != nil && !strings.Contains(string(out), "RUNNING") && !strings.Contains(string(out), "STOPPED") &&
		!strings.Contains(string(out), "PENDING") {
		// A query that could not run, as opposed to one that ran and described a service. sc exits non-zero for
		// an absent service too, which the 1060 check above has already taken.
		return false, fmt.Errorf("sc query %s: %v: %s", name, qerr, strings.TrimSpace(string(out)))
	}
	if !strings.Contains(string(out), "RUNNING") && !strings.Contains(string(out), "PENDING") {
		return false, nil // installed but not running -> nothing to stop
	}
	c := exec.Command(sc, "stop", name)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	o, serr := c.CombinedOutput()
	if serr != nil {
		return true, fmt.Errorf("sc stop %s: %v: %s", name, serr, strings.TrimSpace(string(o)))
	}
	return true, nil
}

// runRecover restores the box to a clean network state after an unclean agent exit. keepServices=true skips
// stopping the SCM services (DsseSteer/DsseWfp) — used when the operator only wants the network back but intends
// to keep the agent installed (it will re-take-over on its next start). The default stops both so nothing
// immediately re-applies the mutations we just reversed.
func runRecover(keepServices bool) error {
	fmt.Println("recover: restoring the box to a clean network state (idempotent; run elevated)...")
	var problems []string

	// 1. Stop the agent + driver first so they can't re-apply the DNS/QUIC/redirect mutations after we undo
	//    them. The WFP driver unload is also what tears down the connect-redirect filters that point TCP at the
	//    dead local terminator — without this, outbound TCP stays broken even after DNS is fixed.
	if !keepServices {
		for _, svc := range []string{serviceName, "DsseWfp"} { // DsseSteer (agent) then DsseWfp (driver)
			issued, err := stopServiceIfPresent(svc)
			switch {
			case err != nil:
				problems = append(problems, fmt.Sprintf("stop %s: %v", svc, err))
			case issued:
				fmt.Printf("recover: stopped service %s\n", svc)
			default:
				fmt.Printf("recover: service %s not running (skip)\n", svc)
			}
		}
	} else {
		fmt.Println("recover: --recover-keep-services set; leaving DsseSteer/DsseWfp as-is")
	}

	// 1b. Clear the redirect policy EXPLICITLY, and verify it cleared.
	//
	// This was missing, and it mattered most in the mode that needs it most. With services stopped, the
	// driver unloads and takes its filters with it, so the redirect goes away as a side effect. With
	// --recover-keep-services the driver stays loaded — and nothing here cleared g_policyValid, so the box
	// went on refusing every connection while this function printed "WFP redirect mutations reversed. Network
	// should be back." In the MSI uninstall sequence a later action removes the driver, so the gap is
	// invisible there; as the standalone panic button after a crash, and as the deliberate pre-update disarm,
	// it is the whole job. A recovery path that reports success without doing the recovery is worse than one
	// that is absent, because it stops the search.
	//
	// Idempotent and correct in both modes: clearing a policy that is already gone is a no-op, and a driver
	// that is not loaded reports its absence rather than a false success.
	if v := removePolicyVerified(); !v.Verified {
		problems = append(problems, "wfp redirect: "+v.Reason)
	} else {
		fmt.Printf("recover: WFP redirect policy cleared and confirmed clear (%s)\n", v.State)
	}

	// 2. DNS: restore the captured servers from the persisted backup; if there is none, pull every resolver off
	//    the loopback back to automatic. Either way name resolution works again.
	if n, err := restoreResolverFromBackup(); err != nil {
		problems = append(problems, fmt.Sprintf("dns restore: %v", err))
	} else if n > 0 {
		fmt.Printf("recover: restored DNS servers on %d interface(s) from the persisted backup\n", n)
	} else {
		if err := resetAllResolvers(); err != nil {
			problems = append(problems, fmt.Sprintf("dns reset: %v", err))
		} else {
			fmt.Println("recover: no DNS backup found; reset any loopback-pinned resolver back to automatic + flushed cache")
		}
	}

	// 3. QUIC: drop the outbound UDP:443 firewall block (no-op if absent).
	removeQUICBlock()
	fmt.Println("recover: removed the QUIC (UDP:443) firewall block if present")

	// 3b. Server-initiated inbound: drop the DSSE Windows Firewall rule group left by a force-killed
	//     firewall-backend inbound agent (no-op if absent). inbound_netsh_windows.go
	removeDSSEFirewallRules()
	fmt.Printf("recover: removed the %q Windows Firewall rule group if present\n", "DSSE Server-Initiated")

	// 4. NCSI: restore the active connectivity test (undo NoActiveProbe=1) to its pre-steer value from the
	//    persisted snapshot, so the OS resumes its own connectivity assessment on the native network.
	restoreNCSIActiveProbe()
	fmt.Println("recover: restored the NCSI active connectivity test (NoActiveProbe) to its pre-steer value")

	if len(problems) > 0 {
		return fmt.Errorf("recover completed with %d problem(s): %s", len(problems), strings.Join(problems, "; "))
	}
	fmt.Println("recover: done — DNS, QUIC, and WFP redirect mutations reversed. Network should be back.")
	return nil
}
