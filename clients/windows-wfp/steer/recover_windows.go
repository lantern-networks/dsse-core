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
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// stopServiceIfPresent stops a Windows service and waits for an observed STOPPED state. A successful STOP
// request is not enough: the running agent can still republish DNS during its stop-pending cleanup.
func stopServiceIfPresent(name string) (issued bool, err error) {
	scm, err := mgr.Connect()
	if err != nil {
		return false, fmt.Errorf("connect to SCM: %w", err)
	}
	defer scm.Disconnect()
	service, err := scm.OpenService(name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("open service %s: %w", name, err)
	}
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		return false, fmt.Errorf("query service %s: %w", name, err)
	}
	if status.State == svc.Stopped {
		return false, nil
	}
	if status.State != svc.StopPending {
		if _, err := service.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
			return true, fmt.Errorf("stop service %s: %w", name, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := waitForServiceStopped(ctx, func() (uint32, error) {
		state, err := service.Query()
		return uint32(state.State), err
	}, uint32(svc.Stopped)); err != nil {
		return true, fmt.Errorf("confirm service %s stopped: %w", name, err)
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

	// Stop the agent first. Never unload the driver as an implicit way to
	// bypass an active captive deadline: explicit recovery and readback must
	// succeed while its admission filters are still present.
	if !keepServices {
		if _, err := stopServiceIfPresent(serviceName); err != nil {
			return fmt.Errorf("recover cannot safely restore DNS while %s may still run: %w", serviceName, err)
		}
	} else {
		fmt.Println("recover: --recover-keep-services set; service lifecycle belongs to the caller")
	}
	var unload func() error
	if !keepServices {
		unload = func() error {
			_, err := stopServiceIfPresent("DsseWfp")
			return err
		}
	}
	recovered, err := recoverBeforeDriverUnload(func() error {
		v := recoverWFPNetworkVerified()
		if !v.Verified {
			return fmt.Errorf("WFP recovery unverified: %s", v.Reason)
		}
		fmt.Printf("recover: WFP redirect and captive deadline confirmed clear (%s)\n", v.State)
		return nil
	}, unload)
	if err != nil {
		if !recovered {
			return err
		}
		// The guard is verified clear. A refused driver stop is still an error,
		// but must not leave the stopped agent's loopback DNS/firewall/NCSI state.
		problems = append(problems, err.Error())
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
	if err := removeQUICBlock(); err != nil {
		problems = append(problems, fmt.Sprintf("QUIC firewall cleanup: %v", err))
	} else {
		fmt.Println("recover: confirmed the QUIC (UDP:443) firewall block absent")
	}

	// 3b. Server-initiated inbound: drop the DSSE Windows Firewall rule group left by a force-killed
	//     firewall-backend inbound agent (no-op if absent). inbound_netsh_windows.go
	if err := removeDSSEFirewallRules(); err != nil {
		problems = append(problems, fmt.Sprintf("inbound firewall cleanup: %v", err))
	} else {
		fmt.Printf("recover: confirmed the %q Windows Firewall rule group absent\n", dsseFirewallGroup)
	}

	// 4. NCSI: restore the active connectivity test (undo NoActiveProbe=1) to its pre-steer value from the
	//    persisted snapshot, so the OS resumes its own connectivity assessment on the native network.
	if err := restoreNCSIActiveProbe(); err != nil {
		problems = append(problems, fmt.Sprintf("NCSI active probe restore: %v", err))
	} else {
		fmt.Println("recover: restored the NCSI active connectivity test (NoActiveProbe) to its pre-steer value")
	}

	if len(problems) > 0 {
		return fmt.Errorf("recover completed with %d problem(s): %s", len(problems), strings.Join(problems, "; "))
	}
	fmt.Println("recover: done — DNS, QUIC, and WFP redirect mutations reversed. Network should be back.")
	return nil
}
