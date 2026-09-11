package main

import "time"

// captive_bootstrap.go — platform-neutral captive-portal BOOTSTRAP controller. It drives the single posture
// transition that lets a fail-closed steer-all box escape a captive portal on a NEW network without weakening
// enforcement:
//
//	ARMED ──(netchange + Edge unreachable + captive POSITIVE)──▶ BOOTSTRAPPING (disarm to native, T_max window)
//	                                                              │
//	          (Edge reachable via bg probe)  or  (T_max elapsed) ─┴─▶ ARMED again
//
// Mechanically there are only two physical postures: ARMED (steer-all applied, fail-closed) and DISARMED (native
// network). The window is the ONLY time we go DISARMED, and it is bounded, captive-gated, and auto-closes on Edge
// reachability. STEERING (Edge OK) vs DARK (timed out, Edge still down) differ only in the close REASON we log —
// both re-apply steering. All I/O is injected via captiveDeps so the logic is unit-tested on any OS; the Windows
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
	rearm  func()
	// osCaptiveDetect toggles whether the OS runs its own captive detection. true (entering the window) RESTORES
	// the OS active probe so Windows shows the native "Sign in to network" flow; false (rearming steer-all)
	// re-suppresses it. Maps to restore/suppressNCSIActiveProbe.
	osCaptiveDetect func(on bool)
	// setActive (optional) flags whether the captive bootstrap window is currently open, so the status/tray
	// layer can distinguish CaptiveOnboarding from a plain fail-open Disarmed. nil = no-op.
	setActive func(active bool)
	// timeout is T_max (the window's absolute upper bound); probeInterval is the background Edge re-probe cadence.
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

// shouldBootstrap encodes the trigger discipline that makes always-on safe: open the window ONLY when the
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
	closeTimeout     closeReason = "timeout"      // T_max elapsed, Edge still down => DARK
	closeStopped     closeReason = "stopped"      // agent stopping
)

// runCaptiveController is the driver loop. It blocks on `trigger` (fired at startup and on every netchange), and
// for each trigger evaluates the posture and, if a captive portal is confirmed, opens a bounded escape window.
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

		if d.probeEdge() {
			continue // Edge reachable => STEERING, nothing to do.
		}
		v := d.detectCaptive()
		if !shouldBootstrap(false, v) {
			// Edge down but no positive captive: stay fail-closed (DARK). Do NOT open the native network.
			d.log("steer_captive_skip reason=captive_%s (edge down, no portal — staying fail-closed)", v)
			continue
		}
		if reason := d.openWindow(stop); reason != closeStopped {
			continue
		}
		return // stopped mid-window
	}
}

// openWindow runs one bootstrap window: disarm to the native network + let the OS detect the portal, then probe
// the Edge every probeInterval until it recovers or T_max elapses, then re-arm steering and restore OS suppression.
// Returns the closeReason. Reads the deadline from now()+timeout so an injected clock drives it in tests.
func (d captiveDeps) openWindow(stop <-chan struct{}) closeReason {
	timeout := d.timeout() // snapshot T_max for this window (live tuning applies to the NEXT window)
	d.log("steer_captive_open reason=captive_positive (disarming to native network for up to %s; OS captive sign-in enabled)", timeout)
	if d.setActive != nil {
		d.setActive(true) // window open — status shows CaptiveOnboarding (distinct from fail-open Disarmed)
	}
	d.disarm()
	d.osCaptiveDetect(true) // let Windows run its captive probe + show the native sign-in UI

	deadline, stopDeadline := d.newTimer(timeout)
	defer stopDeadline()
	tick, stopTick := d.newTimer(d.probeInterval())
	// re-arm tick each fire (single-shot timer reused as a ticker so tests can drive it deterministically).
	// Wrap in a closure so the deferred stop targets the CURRENT tick timer, not the first one (stopTick is
	// reassigned each iteration).
	defer func() { stopTick() }()

	reason := closeTimeout
	start := d.now()
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
			if d.probeEdge() {
				reason = closeEdgeReached
				break loop
			}
			// keep the window open; guard against a clock/deadline miss with an explicit elapsed check.
			if d.now().Sub(start) >= timeout {
				reason = closeTimeout
				break loop
			}
			t2, s2 := d.newTimer(d.probeInterval())
			stopTick()
			tick, stopTick = t2, s2
		}
	}

	d.osCaptiveDetect(false) // re-suppress the OS active probe under steer-all
	d.rearm()                // re-apply steering (fail-closed); STEERING if edge_reached, DARK if timeout
	if d.setActive != nil {
		d.setActive(false) // window closed — back to steering/dark
	}
	switch reason {
	case closeEdgeReached:
		d.log("steer_captive_close reason=edge_reached (Edge reachable — steer-all re-armed, STEERING)")
	case closeTimeout:
		d.log("steer_captive_close reason=timeout (T_max %s elapsed, Edge still down — re-armed fail-closed, DARK)", timeout)
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
