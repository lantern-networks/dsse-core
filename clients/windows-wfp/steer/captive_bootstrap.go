package main

import "time"

// captive_bootstrap.go — platform-neutral captive-portal BOOTSTRAP controller. It drives the single posture
// transition that lets a fail-closed steer-all box escape a captive portal on a NEW network after a positive
// captive check. Native networking is unmediated while disarmed:
//
//	ARMED ──(netchange + Edge unreachable + captive POSITIVE)──▶ BOOTSTRAPPING (disarm to native)
//	                                                              │
//	          (Edge reachable via bg probe)  or  (before T_max) ─┴─▶ rearm attempt
//
// Before disarming, the driver must acknowledge an independent monotonic deadline.
// After that deadline its ALE gate refuses new direct flows even when this
// process is gone or local WFP/DNS/QUIC rearm fails. Ordinary SET/CLEAR and owner
// close preserve the gate. Only complete rearm or explicit recovery releases it.
// The driver must stay loaded; this does not promise persistence across unload/reboot.
// STEERING (Edge OK) and DARK (timed out, Edge still down) are reported only after complete rearm succeeds.
// All I/O is injected via captiveDeps so the logic is unit-tested on any OS; the Windows
// shell wires the real probeEdge / detect / disarm / rearm / NCSI toggle in main_windows.go.

// captiveDeps is the injected I/O the controller drives. Every field is required except logf.
type captiveDeps struct {
	// probeEdge reports whether the Edge is reachable for steering (the (T) mTLS dial+CONNECT of probeEdge).
	probeEdge func() bool
	// detectCaptive performs the out-of-band captive sweep (captive_detect.go / captive_windows.go).
	detectCaptive func() captiveVerdict
	// disarm tears steering down to the native network (reuses the fail-open onDisarm: WFP redirect off, DNS to
	// automatic, QUIC unblocked). rearm re-applies it. They are the same primitives the fail-open monitor uses.
	disarm func()
	// armDeadline must install/verify the independent driver gate BEFORE disarm.
	// Returns the remaining kernel window (adoption never extends it).
	// A missing/old/unreadable driver is an error, never permission to go native.
	armDeadline func(time.Duration) (time.Duration, error)
	// Release only after complete rearm, and never as part of service shutdown.
	// A failed acknowledgement retries FINISH, not the already-completed rearm.
	finishDeadline func() error
	// Reconcile an inherited guard after owner/process replacement by complete
	// local rearm. Called before network probes, which an expired gate blocks.
	recoverDeadline func() bool
	// A failed WFP/DNS/QUIC rearm is not an armed posture. The caller must
	// report success only after its complete local readback/rollback sequence.
	rearm func() bool
	// osCaptiveDetect toggles whether the OS runs its own captive detection. true (entering the window) RESTORES
	// the OS active probe so Windows shows the native "Sign in to network" flow; false (rearming steer-all)
	// re-suppresses it. Maps to restore/suppressNCSIActiveProbe.
	osCaptiveDetect func(on bool)
	// setActive (optional) flags whether the captive bootstrap window is currently open, so the status/tray
	// layer can distinguish CaptiveOnboarding from a plain fail-open Disarmed. nil = no-op.
	setActive func(active bool)
	// timeout is T_max, supplied to the independent gate before opening the window;
	// probeInterval is the background Edge re-probe and failed-rearm retry cadence.
	// Both are FUNCS so the live signed tuning policy (agenttuning, roadmap M5) can change them centrally without
	// a restart: openWindow snapshots timeout() once per window and reads probeInterval() each probe.
	timeout       func() time.Duration
	probeInterval func() time.Duration
	// now/newTimer are injectable clocks (real ones in production; fakes in tests). newTimer returns a channel
	// that fires after d and a stop func.
	now      func() time.Time
	newTimer func(d time.Duration) (<-chan time.Time, func())
	logf     func(format string, args ...any)
}

func (d captiveDeps) log(format string, args ...any) {
	if d.logf != nil {
		d.logf(format, args...)
	}
}

// shouldBootstrap encodes the trigger discipline: open the window ONLY when the
// Edge is unreachable AND a captive portal is positively detected. A reachable Edge stays STEERING; a mere Edge
// outage with no portal (negative/unknown) stays fail-closed (DARK) — it must NOT drop to the native network.
func shouldBootstrap(edgeReachable bool, v captiveVerdict) bool {
	if edgeReachable {
		return false
	}
	return v == captivePositive
}

// closeReason names why the bootstrap window ended (log + posture clarity).
type closeReason string

const (
	closeEdgeReached closeReason = "edge_reached" // Edge became reachable => STEERING
	closeTimeout     closeReason = "timeout"      // early rearm deadline; DARK only after complete rearm
	closeStopped     closeReason = "stopped"      // agent stopping
	closeArmFailed   closeReason = "deadline_arm_failed"
)

// runCaptiveController is the driver loop. It blocks on `trigger` (fired at startup and on every netchange), and
// for each trigger evaluates the posture and, if a captive portal is confirmed, starts a timed rearm attempt.
// It returns when `stop` is closed. Only one window is ever open at a time (evaluation is serial per trigger).
func runCaptiveController(stop <-chan struct{}, trigger <-chan struct{}, d captiveDeps) {
	for {
		select {
		case <-stop:
			return
		case <-trigger:
		}
		// Drain any coalesced burst of triggers so a roam that emits several events evaluates once.
		drain(trigger)

		if !d.reconcileDeadline(stop) {
			return
		}
		if d.probeEdge() {
			continue // Edge reachable => STEERING, nothing to do.
		}
		v := d.detectCaptive()
		if !shouldBootstrap(false, v) {
			// Edge down but no positive captive: stay fail-closed (DARK). Do NOT open the native network.
			d.log("steer_captive_skip reason=captive_%s (edge down, no portal — staying fail-closed)", v)
			continue
		}
		switch d.openWindow(stop) {
		case closeStopped:
			return
		case closeArmFailed:
			// ARM may have reached the driver even when its acknowledgement or
			// readback failed. Keep native networking closed, but reconcile now;
			// waiting for another netchange could strand an expired kernel gate.
			if !d.reconcileDeadline(stop) {
				return
			}
		}
	}
}

func (d captiveDeps) reconcileDeadline(stop <-chan struct{}) bool {
	for {
		select {
		case <-stop:
			return false
		default:
		}
		if d.recoverDeadline == nil || d.recoverDeadline() {
			return true
		}
		d.log("steer_captive_recovery_pending (existing driver gate retained)")
		retry, cancel := d.newTimer(d.probeInterval())
		select {
		case <-stop:
			cancel()
			return false
		case <-retry:
			cancel()
		}
	}
}

// openWindow runs one bootstrap window: disarm to the native network + let the OS detect the portal, then probe
// the Edge every probeInterval until it recovers or the early rearm timer fires. Failed rearm
// is retried while the independent driver deadline stays in force.
// Returns the closeReason. ARM supplies remaining kernel time; a late acknowledgement never renews it.
func (d captiveDeps) openWindow(stop <-chan struct{}) closeReason {
	timeout := d.timeout() // snapshot T_max for this window (live tuning applies to the NEXT window)
	if timeout <= 0 || d.armDeadline == nil || d.finishDeadline == nil {
		d.log("steer_captive_skip reason=invalid_or_missing_deadline_guard (staying fail-closed)")
		return closeArmFailed
	}
	select {
	case <-stop:
		return closeStopped
	default:
	}
	remaining, err := d.armDeadline(timeout)
	if err != nil {
		d.log("steer_captive_skip reason=deadline_arm_failed error=%v (staying fail-closed)", err)
		return closeArmFailed
	}
	// Leave one probe interval for local rearm, capped at half the actual
	// remaining window. This starts protection before T_max; it is not grace
	// beyond the kernel deadline. ARM/readback latency has already been removed.
	if remaining <= 0 || remaining > timeout {
		d.log("steer_captive_skip reason=deadline_already_elapsed (native network remains closed)")
		return closeArmFailed
	}
	lead := d.probeInterval()
	if lead <= 0 || lead > remaining/2 {
		lead = remaining / 2
	}
	rearmAfter := remaining - lead
	start := d.now()
	deadline, stopDeadline := d.newTimer(rearmAfter)
	defer stopDeadline()
	d.log("steer_captive_open reason=captive_positive (disarming to native network; rearm starts on Edge recovery or after %s, before kernel expiry; OS captive sign-in enabled)", rearmAfter)
	if d.setActive != nil {
		d.setActive(true) // window open — status shows CaptiveOnboarding (distinct from fail-open Disarmed)
	}
	d.disarm()
	d.osCaptiveDetect(true) // let Windows run its captive probe + show the native sign-in UI

	tick, stopTick := d.newTimer(d.probeInterval())
	// re-arm tick each fire (single-shot timer reused as a ticker so tests can drive it deterministically).
	// Wrap in a closure so the deferred stop targets the CURRENT tick timer, not the first one (stopTick is
	// reassigned each iteration).
	defer func() { stopTick() }()

	// A slow synchronous transport probe must not prevent timely rearm.
	// There is at most one outstanding probe; its buffered result can finish
	// after this window without holding the controller or spawning more work.
	// Production probeEdge bounds network waits separately: TCP dial (4s), TLS
	// handshake (4s), and CONNECT exchange (4s), closing the socket on return.
	// No second probe starts while that call remains outstanding.
	var probe <-chan bool
	reason := closeTimeout
loop:
	for {
		select {
		case <-stop:
			reason = closeStopped
			break loop
		case <-deadline:
			reason = closeTimeout
			break loop
		case <-tick:
			if d.now().Sub(start) >= rearmAfter {
				reason = closeTimeout
				break loop
			}
			if probe == nil {
				result := make(chan bool, 1)
				probe = result
				go func() { result <- d.probeEdge() }()
			}
			t2, s2 := d.newTimer(d.probeInterval())
			stopTick()
			tick, stopTick = t2, s2
		case reachable := <-probe:
			probe = nil
			if reachable {
				reason = closeEdgeReached
				break loop
			}

		}
	}

	d.osCaptiveDetect(false) // re-suppress the OS active probe under steer-all
	if d.setActive != nil {
		d.setActive(false) // the sign-in window ended; a failed rearm is an error, not onboarding
	}
	for !d.rearm() {
		d.log("steer_captive_rearm_failed reason=%s (steering state unverified; retry pending)", reason)
		retry, stopRetry := d.newTimer(d.probeInterval())
		select {
		case <-stop:
			stopRetry()
			return closeStopped
		case <-retry:
			stopRetry()
		}
	}
	for reason != closeStopped {
		select {
		case <-stop:
			reason = closeStopped // retain the guard across capture Close/CLEAR
			continue
		default:
		}
		if err := d.finishDeadline(); err == nil {
			break
		} else {
			d.log("steer_captive_finish_failed error=%v (complete steering retained; retry pending)", err)
		}
		retry, cancel := d.newTimer(d.probeInterval())
		select {
		case <-stop:
			cancel()
			reason = closeStopped
		case <-retry:
			cancel()
		}
	}
	switch reason {
	case closeEdgeReached:
		d.log("steer_captive_close reason=edge_reached (Edge reachable — steer-all re-armed, STEERING)")
	case closeTimeout:
		d.log("steer_captive_close reason=timeout (rearm scheduled before T_max %s, Edge still down — re-armed fail-closed, DARK)", timeout)
	case closeStopped:
		d.log("steer_captive_close reason=stopped (agent stopping)")
	}
	return reason
}

// drain empties any already-queued triggers without blocking.
func drain(ch <-chan struct{}) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

// realTimer is the production newTimer: a real time.Timer's channel + Stop.
func realTimer(d time.Duration) (<-chan time.Time, func()) {
	t := time.NewTimer(d)
	return t.C, func() { t.Stop() }
}
