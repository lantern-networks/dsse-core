package main

import (
	"testing"
	"time"
)

// ★★ A DEVICE THAT KEEPS STEERING HAS TO KEEP SAYING SO (2026-08-14, measured on the lab). The fleet-wide view
// merges device_state CHANGE events from every Edge and applies steerActiveWindow to the last_steered it was
// told. `steering` was a bare boolean in the change signature, so a device that never stopped never differed
// from itself: it shipped one event at its first flow and nothing after. last_steered froze there, and about
// two minutes later the control plane declared the whole fleet idle while the Edges were carrying its traffic.
//
// A view whose inputs cannot express the present tense will always describe the past and look like the present.
// The signature now carries a coarse clock, so continued steering re-ships at a bounded rate.
//
// The cost is stated rather than discovered: one event per steerRefreshInterval per ACTIVELY STEERING device —
// not per flow. If that is too much at fleet scale the answer is to derive steering from the access-log stream
// those flows already produce, not to widen the interval until the screen is wrong again.
func TestContinuedSteeringRefreshesAtMostOncePerInterval(t *testing.T) {
	store := newEndpointRuntimeStore()
	start := time.Date(2026, 8, 14, 6, 0, 0, 0, time.UTC)

	var emitted []map[string]any
	prev := deviceStateChangeEmit
	deviceStateChangeEmit = func(e map[string]any) { emitted = append(emitted, e) }
	defer func() { deviceStateChangeEmit = prev }()

	store.recordSteeredFlow("mac-dev-1", "acme", "a.tanaka", start)
	if len(emitted) != 1 {
		t.Fatalf("the first flow emitted %d events, want 1", len(emitted))
	}

	// A burst of flows inside one interval is one device steering, not news. This is the flood the bare boolean
	// was protecting against, and it stays protected.
	for i := 1; i <= 20; i++ {
		store.recordSteeredFlow("mac-dev-1", "acme", "a.tanaka", start.Add(time.Duration(i)*time.Second))
	}
	if len(emitted) != 1 {
		t.Fatalf("20 flows within one interval emitted %d events, want 1 — this is per-flow spam", len(emitted))
	}

	// Crossing into the next bucket is worth exactly one: it is how a remote reader learns the device is STILL on.
	store.recordSteeredFlow("mac-dev-1", "acme", "a.tanaka", start.Add(steerRefreshInterval+time.Second))
	if len(emitted) != 2 {
		t.Fatalf("a device still steering %s later emitted %d events, want 2 — without the refresh every other "+
			"node's last_steered stays frozen at the first flow and the fleet reads as idle",
			steerRefreshInterval, len(emitted))
	}
	if emitted[1]["last_steered"] == emitted[0]["last_steered"] {
		t.Fatal("the refresh carries the same last_steered as the first flow, so it tells a reader nothing")
	}

	// And the refresh must be well inside the window it feeds, or a reader lapses the device between beats.
	if steerRefreshInterval >= steerActiveWindow {
		t.Fatalf("steerRefreshInterval (%s) is not shorter than steerActiveWindow (%s): a device would age out "+
			"between heartbeats and flicker", steerRefreshInterval, steerActiveWindow)
	}
}
