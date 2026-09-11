package main

import (
	"errors"
	"time"
)

// errCaptureVanished is the backend ending with no error and no stop request. Named rather than folded into a
// generic failure because an operator reading it needs to know the difference: nothing failed, the capture
// simply ceased to exist, and the agent kept steering by restarting it.
var errCaptureVanished = errors.New("the capture backend stopped on its own — no error was reported and no " +
	"shutdown was requested, so this endpoint would have silently stopped steering")

// supervise.go — durable, self-healing operation of the steering agent. The capture backend (WinDivert
// today, Wintun/WFP later) can stop for two reasons: a clean shutdown (Close/timeout) or a backend failure
// (the OS capture handle dies, the driver is reloaded, etc). For PERMANENT operation we must keep steering
// across the second case instead of exiting -- otherwise a single transient OS hiccup leaves the device
// un-steered (a ZTNA gap). superviseCapture turns the one-shot capture into a supervised loop that recreates
// the backend on failure with backoff. It is pure (no OS/WinDivert dependency) so it is unit-tested on any
// platform; the WinDivert backend is injected as a captureFactory.

// captureFactory creates a fresh SteeringCapture. The supervisor calls it to (re)create the backend.
type captureFactory func() (SteeringCapture, error)

// defaultSupervisorBackoff is a capped linear backoff between restart attempts: 500ms * attempt, capped at
// 5s. Fast enough to re-steer promptly after a transient failure, slow enough not to hot-loop on a
// persistently broken backend (e.g. the driver missing).
func defaultSupervisorBackoff(attempt int) time.Duration {
	const step = 500 * time.Millisecond
	const maxBackoff = 5 * time.Second
	d := time.Duration(attempt) * step
	if d > maxBackoff {
		return maxBackoff
	}
	return d
}

// superviseConfig tunes permanent-operation supervision.
type superviseConfig struct {
	// permanent: when false the supervisor runs the capture exactly once (the contained-burst behaviour) and
	// returns its outcome. When true it restarts the backend after a failure (clean stops still end it).
	permanent bool
	// maxRestarts caps the total number of restart attempts (a runaway backstop). 0 = unlimited.
	maxRestarts int
	// backoff returns the delay before restart attempt n (1-based). nil = no delay. Injected for tests.
	backoff func(attempt int) time.Duration
	// sleep performs the backoff wait. nil defaults to time.Sleep. Injected so tests don't actually wait.
	sleep func(time.Duration)
	// stop, when non-nil, ends supervision on close: the active capture is Closed (-> clean stop -> return
	// nil) and no restart is attempted. Used by the Windows service path for an SCM-driven clean shutdown.
	// nil (the default, e.g. foreground/one-shot) preserves the original behaviour.
	stop <-chan struct{}
}

// superviseCapture creates a capture, runs steer against it until the capture stops, then decides whether
// to restart. A clean stop (Err()==nil, i.e. Close/timeout) ends supervision and returns nil. A backend
// error restarts (permanent mode only) with backoff, bounded by maxRestarts; in non-permanent mode the
// error is returned immediately. Returns the terminal error (nil on clean stop, or the last error once
// restarts are exhausted). steer must block until the capture's Flows() channel closes.
func superviseCapture(newCapture captureFactory, steer func(SteeringCapture), cfg superviseConfig) error {
	sleep := cfg.sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	wait := func(attempt int) {
		if cfg.backoff == nil {
			return
		}
		if d := cfg.backoff(attempt); d > 0 {
			sleep(d)
		}
	}

	stopped := func() bool {
		if cfg.stop == nil {
			return false
		}
		select {
		case <-cfg.stop:
			return true
		default:
			return false
		}
	}

	attempt := 0
	for {
		if stopped() {
			return nil
		}
		capture, err := newCapture()
		if err != nil {
			if !cfg.permanent {
				return err
			}
			attempt++
			if cfg.maxRestarts > 0 && attempt > cfg.maxRestarts {
				return err
			}
			wait(attempt)
			continue
		}

		// Service stop: close the active capture so steer returns via a CLEAN stop (Err()==nil).
		var watchDone chan struct{}
		if cfg.stop != nil {
			watchDone = make(chan struct{})
			go func(c SteeringCapture) {
				select {
				case <-cfg.stop:
					_ = c.Close()
				case <-watchDone:
				}
			}(capture)
		}

		steer(capture) // blocks until capture.Flows() closes
		if watchDone != nil {
			close(watchDone)
		}
		stopErr := capture.Err()
		_ = capture.Close() // idempotent; ensures OS resources are released on every path

		if stopped() {
			return nil // intentional SCM-driven shutdown
		}
		if stopErr == nil && cfg.permanent && cfg.stop != nil {
			// ★ THE THIRD REASON A CAPTURE ENDS, AND IT COST THIS BOX A DAY (2026-08-14, win-dev-1). The file
			// header above says a capture stops "for two reasons": a clean shutdown, or a backend failure. There
			// is a third — the backend going away on its own, cleanly, with nobody asking and no error recorded —
			// and it was being read as the first.
			//
			// Measured: DsseSteer exited 2m13s, 2m20s and ~5m after successive starts, each time with
			// WIN32_EXIT_CODE 0 and not one line in its log, which simply stopped mid-sentence after a network
			// change. A clean exit code is also why the SCM never restarted it, so the box sat with its resolver
			// pointed at the loopback proxy of a process that no longer existed: total loss of connectivity,
			// recovered by hand with --mode recover.
			//
			// The ONLY evidence of intent in service mode is the stop channel. Its ABSENCE is not consent — the
			// same shape as the empty envelope taken for an unsigned plan and the empty terminal counter taken
			// for a delivered report. So this restarts, and it is loud about why: an endpoint that stops steering
			// without being told to is a ZTNA gap, which is exactly what the header says this loop exists to
			// prevent.
			//
			// Guarded on cfg.stop != nil so the contained-burst and foreground paths are untouched: they have no
			// stop channel and END on a clean Close/timeout, which is their contract rather than a defect.
			stopErr = errCaptureVanished
		}
		if stopErr == nil {
			return nil // clean stop (Close/timeout) -- intentional shutdown, done
		}
		if !cfg.permanent {
			return stopErr
		}
		attempt++
		if cfg.maxRestarts > 0 && attempt > cfg.maxRestarts {
			return stopErr
		}
		wait(attempt)
	}
}
