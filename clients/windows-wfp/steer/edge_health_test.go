//go:build windows

package main

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestEdgeHealthNilSafe(t *testing.T) {
	var h *edgeHealth // fail-closed mode passes nil
	if !h.shouldTryEdge() {
		t.Fatal("nil health should always allow the edge")
	}
	h.recordSuccess() // must not panic
	if opened := h.recordFailure(); opened {
		t.Fatal("nil health should never open")
	}
}

func TestEdgeHealthOpensAfterThreshold(t *testing.T) {
	h := newEdgeHealth(3, 50*time.Millisecond)
	// First two failures keep the circuit closed.
	if h.recordFailure() || h.recordFailure() {
		t.Fatal("circuit opened before threshold")
	}
	if !h.shouldTryEdge() {
		t.Fatal("circuit should still be closed below threshold")
	}
	// Third failure opens it.
	if !h.recordFailure() {
		t.Fatal("third failure should open the circuit")
	}
	if h.shouldTryEdge() {
		t.Fatal("circuit should be open immediately after tripping")
	}
	// After the cooldown it half-opens (allows a probe).
	time.Sleep(70 * time.Millisecond)
	if !h.shouldTryEdge() {
		t.Fatal("circuit should allow a probe after the cooldown")
	}
}

func TestEdgeHealthSuccessResets(t *testing.T) {
	h := newEdgeHealth(2, time.Minute)
	h.recordFailure() // 1/2
	h.recordSuccess() // reset
	if h.recordFailure() {
		t.Fatal("a success should have reset the consecutive-failure count, so one more failure must NOT open")
	}
}

func TestEdgeHealthMonitorReArmsOnRecovery(t *testing.T) {
	h := newEdgeHealth(1, time.Hour) // long cooldown so only the monitor can close it
	if !h.recordFailure() {          // threshold 1 -> opens immediately
		t.Fatal("expected circuit to open")
	}
	if !h.isOpen() {
		t.Fatal("circuit should be open")
	}

	// Probe returns down for the first 2 calls, then up — the monitor must close the circuit on the up probe.
	var calls int
	probe := func() bool {
		calls++
		return calls >= 3
	}
	stop := make(chan struct{})
	go runEdgeHealthMonitor(stop, h, probe, 10*time.Millisecond, 0, nil, nil, nil)
	defer close(stop)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !h.isOpen() {
			return // recovered — steer-all re-armed
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("monitor did not re-arm steer-all after the Edge probe recovered")
}

func TestEdgeHealthMonitorDisarmsThenReArms(t *testing.T) {
	h := newEdgeHealth(1, time.Hour)
	h.recordFailure() // open the circuit (fail-open engaged)

	var disarmed atomic.Bool
	var disarmCalls, rearmCalls int32
	onDisarm := func() { atomic.AddInt32(&disarmCalls, 1); disarmed.Store(true) }
	onRearm := func() { atomic.AddInt32(&rearmCalls, 1); disarmed.Store(false) }

	// Edge down until we flip it up. disarmAfter is tiny so the monitor escalates quickly.
	var up atomic.Bool
	probe := func() bool { return up.Load() }

	stop := make(chan struct{})
	defer close(stop)
	go runEdgeHealthMonitor(stop, h, probe, 10*time.Millisecond, 40*time.Millisecond, &disarmed, onDisarm, onRearm)

	// Should disarm after the sustained-outage window.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && atomic.LoadInt32(&disarmCalls) == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if atomic.LoadInt32(&disarmCalls) == 0 {
		t.Fatal("monitor did not self-disarm after the sustained outage")
	}
	if !disarmed.Load() {
		t.Fatal("disarmed flag should be set")
	}
	// Now the Edge comes back — the monitor (still probing while disarmed) must re-arm.
	up.Store(true)
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && atomic.LoadInt32(&rearmCalls) == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if atomic.LoadInt32(&rearmCalls) == 0 {
		t.Fatal("monitor did not re-arm after the Edge recovered from a disarmed state")
	}
	if disarmed.Load() {
		t.Fatal("disarmed flag should be cleared after re-arm")
	}
}

func TestEdgeHealthMonitorIgnoresClosedCircuit(t *testing.T) {
	h := newEdgeHealth(3, time.Second) // closed (no failures)
	probed := make(chan struct{}, 1)
	probe := func() bool {
		select {
		case probed <- struct{}{}:
		default:
		}
		return true
	}
	stop := make(chan struct{})
	go runEdgeHealthMonitor(stop, h, probe, 10*time.Millisecond, 0, nil, nil, nil)
	defer close(stop)
	time.Sleep(80 * time.Millisecond)
	select {
	case <-probed:
		t.Fatal("monitor probed the Edge while the circuit was closed (should be a no-op when healthy)")
	default:
	}
}

func TestUpstreamServersDedupesAndSkipsLoopback(t *testing.T) {
	entries := []resolverEntry{
		{Servers: "192.0.2.1,8.8.8.8"},
		{Servers: "192.0.2.1"}, // dup
		{Servers: "127.0.0.1"}, // loopback, skipped
		{Servers: "::1"},       // loopback, skipped
		{Servers: "240d:1a::1"},
	}
	got := upstreamServers(entries)
	want := []string{"192.0.2.1", "8.8.8.8", "240d:1a::1"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}
