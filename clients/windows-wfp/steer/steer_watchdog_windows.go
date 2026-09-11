//go:build windows

// steer_watchdog_windows.go — W-5 (defense-in-depth): a driver-recovery watchdog.  proved a non-admin
// cannot stop/unload the WFP driver (device ACL); this raises the bar against an ADMIN tamper by making a
// `sc stop`/unload LOUD and SELF-HEALING: the watchdog polls the driver service and, if it is not RUNNING,
// emits a tamper event and restarts it. It is not a final wall (an admin can also kill the watchdog and PPL/
// production signing are the real hardening, see handoff) -- it buys time and visibility, and pairs with W-3
// (the stop is reported as posture-unhealthy) and W-2 (full silence -> revoke).
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/clients/windows-wfp/winbin"
)

type watchdogConfig struct {
	service  string        // driver service name (e.g. DsseWfp)
	interval time.Duration // poll period
	timeout  time.Duration // 0 = run until interrupted
}

// serviceRunning reports whether the named service is in the RUNNING state (sc.exe state keywords are English
// regardless of UI locale).
//
// ★ IT RETURNS AN ERROR NOW, because the old signature could only say "not running" — and it said it for two
// completely different situations. sc.exe was resolved through %PATH% and its error was discarded, so a box
// where that lookup failed (measured on win-dev-1 for msiexec on 2026-08-11; see package winbin) would read an
// empty output, find no "RUNNING" in it, and conclude the driver had been stopped. The watchdog would then
// announce a tamper event and attempt a restart every interval, forever, on a machine where nothing was wrong
// and nothing it did could work. "I could not ask" and "the answer is no" must not share a return value.
func serviceRunning(name string) (bool, error) {
	sc, err := winbin.System("sc.exe")
	if err != nil {
		return false, err
	}
	out, err := exec.Command(sc, "query", name).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "RUNNING") && !strings.Contains(string(out), "STOPPED") {
		// A query that could not run at all. A query that RAN and reported a stopped or absent service exits
		// non-zero too, and that is an answer rather than a fault — hence the state check before the error.
		return false, fmt.Errorf("sc query %s: %v: %s", name, err, strings.TrimSpace(string(out)))
	}
	return strings.Contains(string(out), "RUNNING"), nil
}

// runWatchdog polls the driver service and restarts it if it stops, emitting a non-secret tamper event each
// time. Stopping THIS process stops the protection (which is why production wants it as a protected SYSTEM
// service + PPL; / W-5).
func runWatchdog(cfg watchdogConfig) error {
	if strings.TrimSpace(cfg.service) == "" {
		cfg.service = "DsseWfp"
	}
	if cfg.interval <= 0 {
		cfg.interval = 3 * time.Second
	}
	fmt.Printf("watchdog: guarding driver service %q every %s (restart-on-stop)\n", cfg.service, cfg.interval)

	ticker := time.NewTicker(cfg.interval)
	defer ticker.Stop()
	deadline := time.Time{}
	if cfg.timeout > 0 {
		deadline = time.Now().Add(cfg.timeout)
	}
	// Resolved ONCE, before the loop, and a failure ends the watchdog instead of running it blind: a guard that
	// cannot query or start the service it guards is not degraded, it is absent, and the operator has to be
	// told that rather than left with a process that looks like protection.
	sc, err := winbin.System("sc.exe")
	if err != nil {
		return fmt.Errorf("the watchdog cannot guard %s: %w", cfg.service, err)
	}

	for {
		<-ticker.C
		running, qerr := serviceRunning(cfg.service)
		if qerr != nil {
			// NOT treated as "stopped". The old code could not tell these apart and would announce a tamper event
			// every interval on a box where nothing had happened.
			fmt.Fprintf(os.Stderr, "watchdog: the state of %s could NOT be read (%v) — this is not a report that it "+
				"is stopped, and nothing was restarted\n", cfg.service, qerr)
			continue
		}
		if !running {
			// non-secret tamper event: which service, that it was found stopped, and the recovery attempt.
			fmt.Printf("wfp_driver_tamper_detected service=%s state=stopped action=restart\n", cfg.service)
			out, err := exec.Command(sc, "start", cfg.service).CombinedOutput()
			if err != nil && !strings.Contains(string(out), "RUNNING") {
				fmt.Fprintf(os.Stderr, "watchdog: restart failed: %v (admin/SYSTEM required)\n", err)
			} else {
				fmt.Printf("wfp_driver_recovered service=%s action=restart_issued\n", cfg.service)
			}
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			return nil
		}
	}
}
