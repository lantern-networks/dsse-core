package main

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestShouldBootstrap(t *testing.T) {
	cases := []struct {
		edgeReachable bool
		v             captiveVerdict
		want          bool
	}{
		{true, captivePositive, false},  // Edge OK => stay STEERING even if a portal exists
		{true, captiveNegative, false},  // Edge OK => STEERING
		{false, captivePositive, true},  // Edge down + portal => open the window
		{false, captiveNegative, false}, // Edge down, no portal => stay fail-closed (DARK)
		{false, captiveUnknown, false},  // Edge down, indeterminate => stay fail-closed (DARK)
	}
	for _, c := range cases {
		if got := shouldBootstrap(c.edgeReachable, c.v); got != c.want {
			t.Fatalf("shouldBootstrap(%v,%v)=%v, want %v", c.edgeReachable, c.v, got, c.want)
		}
	}
}

// recorder captures the ordered side-effects the controller drives.
type recorder struct {
	mu     sync.Mutex
	events []string
}

func (r *recorder) add(s string) {
	r.mu.Lock()
	r.events = append(r.events, s)
	r.mu.Unlock()
}

func (r *recorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.events))
	copy(out, r.events)
	return out
}

func (r *recorder) count(s string) int {
	n := 0
	for _, e := range r.snapshot() {
		if e == s {
			n++
		}
	}
	return n
}

func baseDeps(rec *recorder) captiveDeps {
	return captiveDeps{
		finishDeadline:  func() error { rec.add("finish"); return nil },
		armDeadline:     func(d time.Duration) (time.Duration, error) { rec.add("arm"); return d, nil },
		disarm:          func() { rec.add("disarm") },
		rearm:           func() bool { rec.add("rearm"); return true },
		osCaptiveDetect: func(on bool) { rec.add(map[bool]string{true: "os:on", false: "os:off"}[on]) },
		timeout:         func() time.Duration { return 5 * time.Second },
		probeInterval:   func() time.Duration { return 2 * time.Millisecond },
		now:             time.Now,
		newTimer:        realTimer,
		logf:            func(string, ...any) {},
	}
}

func TestOpenWindow_EdgeReached(t *testing.T) {
	rec := &recorder{}
	d := baseDeps(rec)
	var probes int
	var mu sync.Mutex
	d.probeEdge = func() bool {
		mu.Lock()
		defer mu.Unlock()
		probes++
		return probes >= 2 // unreachable on the first tick, reachable on the second
	}

	stop := make(chan struct{})
	reason := d.openWindow(stop)

	if reason != closeEdgeReached {
		t.Fatalf("reason=%v, want edge_reached", reason)
	}
	ev := rec.snapshot()
	// Expected order: disarm, os:on, (probes...), os:off, rearm.
	if len(ev) < 5 || ev[0] != "arm" || ev[1] != "disarm" || ev[2] != "os:on" {
		t.Fatalf("bad opening order: %v", ev)
	}
	if ev[len(ev)-3] != "os:off" || ev[len(ev)-2] != "rearm" || ev[len(ev)-1] != "finish" {
		t.Fatalf("bad closing order: %v", ev)
	}
	if rec.count("disarm") != 1 || rec.count("rearm") != 1 {
		t.Fatalf("disarm/rearm not balanced: %v", ev)
	}
}

func TestOpenWindow_Timeout(t *testing.T) {
	rec := &recorder{}
	d := baseDeps(rec)
	const tmax = 20 * time.Millisecond
	d.timeout = func() time.Duration { return tmax }
	d.probeInterval = func() time.Duration { return 2 * time.Millisecond }
	d.probeEdge = func() bool { return false } // Edge never recovers

	start := time.Now()
	reason := d.openWindow(make(chan struct{}))
	elapsed := time.Since(start)

	if reason != closeTimeout {
		t.Fatalf("reason=%v, want timeout", reason)
	}
	if elapsed < tmax-2*time.Millisecond {
		t.Fatalf("closed before timeout: %v < %v", elapsed, tmax)
	}
	// Even on timeout the box must be re-armed fail-closed (never left disarmed).
	if rec.count("rearm") != 1 || rec.count("os:off") != 1 {
		t.Fatalf("must re-arm on timeout: %v", rec.snapshot())
	}
}

func TestOpenWindowFailedRearmIsRetriedAndNotLoggedAsSteering(t *testing.T) {
	rec := &recorder{}
	d := baseDeps(rec)
	d.timeout = func() time.Duration { return time.Millisecond }
	d.probeInterval = func() time.Duration { return time.Millisecond }
	d.probeEdge = func() bool { return false }
	d.setActive = func(active bool) {
		if active {
			rec.add("active")
		} else {
			rec.add("inactive")
		}
	}
	d.logf = func(format string, _ ...any) { rec.add(format) }
	attempts := 0
	d.rearm = func() bool {
		attempts++
		rec.add("rearm")
		return attempts == 2
	}
	if got := d.openWindow(make(chan struct{})); got != closeTimeout {
		t.Fatalf("reason=%s", got)
	}
	if attempts != 2 || rec.count("steer_captive_rearm_failed reason=%s (steering state unverified; retry pending)") != 1 {
		t.Fatalf("failed rearm was treated as successful: %v", rec.snapshot())
	}
}

func TestOpenWindow_Stopped(t *testing.T) {
	rec := &recorder{}
	d := baseDeps(rec)
	d.timeout = func() time.Duration { return 10 * time.Second }
	d.probeEdge = func() bool { return false }

	stop := make(chan struct{})
	go func() {
		time.Sleep(10 * time.Millisecond)
		close(stop)
	}()
	reason := d.openWindow(stop)

	if reason != closeStopped {
		t.Fatalf("reason=%v, want stopped", reason)
	}
	// Stopping still restores posture (re-arm + OS suppression) so we never exit disarmed.
	if rec.count("rearm") != 1 {
		t.Fatalf("must re-arm on stop: %v", rec.snapshot())
	}
}

func TestController_Gating(t *testing.T) {
	// Edge reachable => STEERING, never disarm.
	t.Run("edge_reachable", func(t *testing.T) {
		rec := &recorder{}
		d := baseDeps(rec)
		d.probeEdge = func() bool { return true }
		d.detectCaptive = func() captiveVerdict { t.Fatal("must not probe captive when Edge reachable"); return captiveUnknown }
		runOneTrigger(d)
		if rec.count("disarm") != 0 {
			t.Fatalf("disarmed with Edge reachable: %v", rec.snapshot())
		}
	})

	// Edge down but captive NEGATIVE => stay fail-closed, never disarm.
	t.Run("edge_down_no_portal", func(t *testing.T) {
		rec := &recorder{}
		d := baseDeps(rec)
		d.probeEdge = func() bool { return false }
		d.detectCaptive = func() captiveVerdict { return captiveNegative }
		runOneTrigger(d)
		if rec.count("disarm") != 0 {
			t.Fatalf("disarmed on a plain Edge outage (no portal): %v", rec.snapshot())
		}
	})
}

// runOneTrigger runs the controller with a single pre-queued trigger and stops it, so a gating decision
// (no window opened) is observed without a real netchange.
func runOneTrigger(d captiveDeps) {
	stop := make(chan struct{})
	trigger := make(chan struct{}, 1)
	trigger <- struct{}{}
	done := make(chan struct{})
	go func() {
		runCaptiveController(stop, trigger, d)
		close(done)
	}()
	// The single trigger is consumed and (Edge reachable / no portal) returns to the select; give it a beat,
	// then stop.
	time.Sleep(20 * time.Millisecond)
	close(stop)
	<-done
}

func TestOpenWindowInvalidDurationCannotDisarm(t *testing.T) {
	for _, timeout := range []time.Duration{0, -time.Second} {
		t.Run(timeout.String(), func(t *testing.T) {
			rec := &recorder{}
			d := baseDeps(rec)
			d.timeout = func() time.Duration { return timeout }
			d.probeEdge = func() bool { return false }
			d.openWindow(make(chan struct{}))
			if rec.count("disarm") != 0 || rec.count("os:on") != 0 {
				t.Fatalf("invalid deadline opened native networking: %v", rec.snapshot())
			}
		})
	}
}

func TestOpenWindowDeadlineArmFailureNeverDisarms(t *testing.T) {
	for _, kind := range []string{"old driver", "readback failure", "stale owner", "missing guard"} {
		t.Run(kind, func(t *testing.T) {
			rec := &recorder{}
			d := baseDeps(rec)
			d.armDeadline = func(time.Duration) (time.Duration, error) { rec.add("arm-failed"); return 0, errors.New(kind) }
			if kind == "missing guard" {
				d.armDeadline = nil
			}
			if got := d.openWindow(make(chan struct{})); got != closeArmFailed {
				t.Fatal(got)
			}
			if rec.count("disarm") != 0 || rec.count("os:on") != 0 || rec.count("rearm") != 0 {
				t.Fatal(rec.snapshot())
			}
		})
	}
}

func TestOpenWindowFailedRearmThenProcessStopRetainsDeadline(t *testing.T) {
	rec := &recorder{}
	d := baseDeps(rec)
	stop := make(chan struct{})
	active := false
	d.armDeadline = func(d time.Duration) (time.Duration, error) { active = true; rec.add("arm"); return d, nil }
	d.timeout = func() time.Duration { return time.Millisecond }
	d.probeEdge = func() bool { return false }
	d.rearm = func() bool { close(stop); return false }
	if got := d.openWindow(stop); got != closeStopped {
		t.Fatal(got)
	}
	if !active {
		t.Fatal("failed rearm released independent guard")
	}
	if rec.count("arm") != 1 || rec.count("disarm") != 1 {
		t.Fatal(rec.snapshot())
	}
}

func TestControllerRecoversInheritedDeadlineBeforeNetworkProbe(t *testing.T) {
	rec := &recorder{}
	d := baseDeps(rec)
	attempts := 0
	d.recoverDeadline = func() bool { attempts++; rec.add("recover"); return attempts >= 2 }
	d.probeEdge = func() bool {
		if attempts < 2 {
			t.Error("probed before inherited gate reconciled")
		}
		rec.add("probe")
		return true
	}
	runOneTrigger(d)
	ev := rec.snapshot()
	if len(ev) < 3 || ev[0] != "recover" || ev[1] != "recover" || ev[2] != "probe" {
		t.Fatal(ev)
	}
}

func TestOpenWindowStopNeverReleasesIndependentGuard(t *testing.T) {
	rec := &recorder{}
	d := baseDeps(rec)
	stop := make(chan struct{})
	d.disarm = func() { rec.add("disarm"); close(stop) }
	d.probeEdge = func() bool { return false }
	if got := d.openWindow(stop); got != closeStopped {
		t.Fatal(got)
	}
	if rec.count("finish") != 0 || rec.count("rearm") != 1 {
		t.Fatal(rec.snapshot())
	}
}

func TestOpenWindowFinishRetryDoesNotRepeatCompleteRearm(t *testing.T) {
	rec := &recorder{}
	d := baseDeps(rec)
	d.timeout = func() time.Duration { return time.Millisecond }
	d.probeEdge = func() bool { return false }
	attempts := 0
	d.finishDeadline = func() error {
		attempts++
		if attempts == 1 {
			return errors.New("ack lost after completed FINISH")
		}
		return nil
	}
	if got := d.openWindow(make(chan struct{})); got != closeTimeout {
		t.Fatal(got)
	}
	if attempts != 2 || rec.count("rearm") != 1 {
		t.Fatalf("attempts=%d events=%v", attempts, rec.snapshot())
	}
}

func TestControllerAmbiguousArmRetriesLocalRecoveryWithoutNewTrigger(t *testing.T) {
	rec := &recorder{}
	d := baseDeps(rec)
	stop, done, recovered := make(chan struct{}), make(chan struct{}), make(chan struct{})
	trigger := make(chan struct{}, 1)
	active := false
	recoveries := 0
	d.probeEdge = func() bool { return false }
	d.detectCaptive = func() captiveVerdict { return captivePositive }
	d.armDeadline = func(duration time.Duration) (time.Duration, error) {
		active = true
		rec.add("arm-ack-lost")
		return 0, errors.New("ARM reached driver but acknowledgement/readback failed")
	}
	d.recoverDeadline = func() bool {
		if !active {
			return true
		}
		recoveries++
		rec.add("local-recovery")
		if recoveries < 3 {
			return false
		}
		active = false
		close(recovered)
		return true
	}
	go func() { runCaptiveController(stop, trigger, d); close(done) }()
	trigger <- struct{}{} // no further network-change trigger is sent
	select {
	case <-recovered:
	case <-time.After(time.Second):
		close(stop)
		<-done
		t.Fatal("ambiguous ARM waited for another network change instead of local recovery")
	}
	close(stop)
	<-done
	if active || recoveries != 3 || rec.count("disarm") != 0 || rec.count("os:on") != 0 || rec.count("arm-ack-lost") != 1 {
		t.Fatalf("active=%t recoveries=%d events=%v", active, recoveries, rec.snapshot())
	}
}

func TestControllerAmbiguousArmRecoveryStopsWithoutReleasingGuard(t *testing.T) {
	rec := &recorder{}
	d := baseDeps(rec)
	stop := make(chan struct{})
	trigger := make(chan struct{}, 1)
	trigger <- struct{}{}
	active := false
	d.probeEdge = func() bool { return false }
	d.detectCaptive = func() captiveVerdict { return captivePositive }
	d.armDeadline = func(time.Duration) (time.Duration, error) {
		active = true
		return 0, errors.New("readback unavailable")
	}
	d.recoverDeadline = func() bool {
		if !active {
			return true
		}
		close(stop)
		return false
	}
	runCaptiveController(stop, trigger, d)
	if !active || rec.count("disarm") != 0 || rec.count("finish") != 0 {
		t.Fatal(rec.snapshot())
	}
}

func TestOpenWindowSchedulesBeforeActualRemainingKernelDeadline(t *testing.T) {
	rec := &recorder{}
	d := baseDeps(rec)
	d.timeout = func() time.Duration { return 3 * time.Minute }
	d.probeInterval = func() time.Duration { return 3 * time.Second }
	// Adoption/slow ARM has only ten seconds left. Never create a fresh 180s timer.
	d.armDeadline = func(time.Duration) (time.Duration, error) { return 10 * time.Second, nil }
	var durations []time.Duration
	d.newTimer = func(delay time.Duration) (<-chan time.Time, func()) {
		durations = append(durations, delay)
		ch := make(chan time.Time, 1)
		if len(durations) == 1 {
			ch <- time.Now().Add(delay)
		}
		return ch, func() {}
	}
	d.probeEdge = func() bool { return false }
	if got := d.openWindow(make(chan struct{})); got != closeTimeout {
		t.Fatal(got)
	}
	if len(durations) < 1 || durations[0] != 7*time.Second {
		t.Fatalf("rearm timers=%v", durations)
	}
	if rec.count("rearm") != 1 || rec.count("finish") != 1 {
		t.Fatal(rec.snapshot())
	}
}

func TestOpenWindowExpiredAcknowledgementNeverDisarms(t *testing.T) {
	rec := &recorder{}
	d := baseDeps(rec)
	d.armDeadline = func(time.Duration) (time.Duration, error) { return 0, nil }
	d.probeEdge = func() bool { return false }
	if got := d.openWindow(make(chan struct{})); got != closeArmFailed {
		t.Fatal(got)
	}
	if rec.count("disarm") != 0 || rec.count("os:on") != 0 {
		t.Fatal(rec.snapshot())
	}
}

func TestOpenWindowBlockedProbeCannotDelayRearm(t *testing.T) {
	rec := &recorder{}
	d := baseDeps(rec)
	d.timeout = func() time.Duration { return time.Second }
	d.probeInterval = func() time.Duration { return 100 * time.Millisecond }
	started, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	d.probeEdge = func() bool { close(started); <-release; return false }
	deadline, tick := make(chan time.Time, 1), make(chan time.Time, 1)
	timers := 0
	d.newTimer = func(time.Duration) (<-chan time.Time, func()) {
		timers++
		switch timers {
		case 1:
			return deadline, func() {}
		case 2:
			return tick, func() {}
		default:
			return make(chan time.Time), func() {}
		}
	}
	done := make(chan closeReason, 1)
	go func() { done <- d.openWindow(make(chan struct{})) }()
	tick <- time.Now()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("probe not started")
	}
	deadline <- time.Now()
	select {
	case got := <-done:
		if got != closeTimeout {
			t.Fatal(got)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked probe delayed rearm")
	}
	if rec.count("rearm") != 1 {
		t.Fatal(rec.snapshot())
	}
}
