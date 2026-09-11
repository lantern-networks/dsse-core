package main

import (
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
		disarm:          func() { rec.add("disarm") },
		rearm:           func() { rec.add("rearm") },
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
	if len(ev) < 4 || ev[0] != "disarm" || ev[1] != "os:on" {
		t.Fatalf("bad opening order: %v", ev)
	}
	if ev[len(ev)-2] != "os:off" || ev[len(ev)-1] != "rearm" {
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
	if elapsed < tmax {
		t.Fatalf("closed before timeout: %v < %v", elapsed, tmax)
	}
	// Even on timeout the box must be re-armed fail-closed (never left disarmed).
	if rec.count("rearm") != 1 || rec.count("os:off") != 1 {
		t.Fatalf("must re-arm on timeout: %v", rec.snapshot())
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
