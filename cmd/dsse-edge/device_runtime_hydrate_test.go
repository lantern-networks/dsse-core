package main

import (
	"testing"
	"time"
)

// Hydration exists so a restart does not empty the fleet view. Three properties decide whether it helps or
// quietly makes things worse, and each has a way of being got wrong that no casual test would notice.
func TestSeedFromHistoryRestoresTheNewestStatePerDevice(t *testing.T) {
	store := newEndpointRuntimeStore()
	// Newest-first, as the log query returns them. The OLDER row for mac-dev-1 must not win.
	restored := store.seedFromHistory([]map[string]any{
		{
			"tenant_id": "acme", "device_id": "mac-dev-1", "timestamp": "2026-08-08T01:54:22Z",
			"os": "macOS 26.5.2", "logged_in_users": []any{"a.tanaka"},
			"disk_encryption_enabled": true, "firewall_enabled": true,
		},
		{
			"tenant_id": "acme", "device_id": "mac-dev-1", "timestamp": "2026-08-01T00:00:00Z",
			"os": "macOS 14.0", "logged_in_users": []any{"someone-else"},
			"disk_encryption_enabled": false, "firewall_enabled": false,
		},
		{
			"tenant_id": "acme", "device_id": "win-dev-1", "timestamp": "2026-08-08T01:47:01Z",
			"os": "Windows 11 25H2", "logged_in_users": []any{`WIN-DEV-01\jdoe`},
			"disk_encryption_enabled": true, "firewall_enabled": true,
		},
	})
	if restored != 2 {
		t.Fatalf("restored %d devices, want 2", restored)
	}
	snap := store.snapshot(time.Date(2026, 8, 8, 2, 0, 0, 0, time.UTC))
	mac, ok := snap["mac-dev-1"]
	if !ok {
		t.Fatalf("mac-dev-1 missing from the snapshot: %v", snap)
	}
	if mac.OS != "macOS 26.5.2" {
		t.Fatalf("os = %q, want the NEWEST row's value — history arrives newest-first and older rows must not overwrite", mac.OS)
	}
	if len(mac.LoggedInUsers) != 1 || mac.LoggedInUsers[0] != "a.tanaka" {
		t.Fatalf("logged-in users = %v, want the newest row's", mac.LoggedInUsers)
	}
}

// A device the live transport already reported is current; history is not. Overwriting it with an older row
// would take a fleet view that was right and make it stale — the opposite of the point.
func TestSeedFromHistoryNeverOverwritesLiveState(t *testing.T) {
	store := newEndpointRuntimeStore()
	now := time.Date(2026, 8, 8, 2, 0, 0, 0, time.UTC)
	store.ingestFromConnect("mac-dev-1", "acme", map[string][]string{
		"X-Dsse-Device-Os": {"macOS 26.5.2 (live)"},
	}, "203.0.113.7", now)

	restored := store.seedFromHistory([]map[string]any{{
		"tenant_id": "acme", "device_id": "mac-dev-1", "timestamp": "2026-08-01T00:00:00Z",
		"os": "macOS 14.0 (stale history)",
	}})
	if restored != 0 {
		t.Fatalf("restored %d, want 0 — a device already reported live must not be seeded from history", restored)
	}
	if got := store.snapshot(now)["mac-dev-1"].OS; got != "macOS 26.5.2 (live)" {
		t.Fatalf("live state was overwritten by history: %q", got)
	}
}

// A restored device that then reports the SAME state is not a transition. Without seeding the signature, every
// restart would emit a change event per device — turning a durability fix into a source of false history.
func TestSeedFromHistorySeedsTheChangeSignature(t *testing.T) {
	store := newEndpointRuntimeStore()
	store.seedFromHistory([]map[string]any{{
		"tenant_id": "acme", "device_id": "mac-dev-1", "timestamp": "2026-08-08T01:54:22Z",
		"os": "macOS 26.5.2", "logged_in_users": []any{"a.tanaka"},
		"disk_encryption_enabled": true, "firewall_enabled": true,
		// ★ INCLUDING THAT IT WAS STEERING (2026-08-14). Without this the restored state is INCOMPLETE, and the
		// first CONNECT afterwards is a genuine transition — the device started steering as far as this node
		// knows — so the event it emits is not false history, it is the fixture's omission. A restore has to
		// carry every field the signature reads or "same state" is not the same state.
		// ★ AND WHERE IT REACHED US FROM (2026-08-24). Same rule, one field later: the address is part of the
		// state — a device that moves network is the same device somewhere else — so a restore that omits it
		// makes the first live report look like a change.
		"last_steered": "2026-08-08T01:54:22Z", "edge": "region-a", "source_ip": "203.0.113.7",
	}})

	var emitted []map[string]any
	prev := deviceStateChangeEmit
	deviceStateChangeEmit = func(e map[string]any) { emitted = append(emitted, e) }
	defer func() { deviceStateChangeEmit = prev }()

	// WITHIN the same refresh bucket as the restored last_steered (2026-08-14): re-reporting identical state is
	// not news. Crossing a bucket IS — that is the heartbeat a remote reader needs to see the present tense —
	// and TestContinuedSteeringRefreshesAtMostOncePerInterval covers that side.
	now := time.Date(2026, 8, 8, 1, 54, 40, 0, time.UTC)
	store.ingestFromConnect("mac-dev-1", "acme", map[string][]string{
		"X-Dsse-Device-Os":          {"macOS 26.5.2"},
		"X-Dsse-Posture-Encryption": {"on"},
		"X-Dsse-Posture-Firewall":   {"on"},
	}, "203.0.113.7", now)
	store.recordSteeredFlow("mac-dev-1", "acme", "a.tanaka", now)

	for _, e := range emitted {
		t.Fatalf("re-reporting restored state emitted a change event, which is false history: %v", e)
	}
}

// ★★ AND A DEVICE THAT BEGINS STEERING DOES EMIT (2026-08-14). This is the event a fleet-wide view is built
// on: it is how the control plane learns a device has failed over to another Edge. A restore that reported no
// steering, followed by traffic, is a real transition — the opposite case from the test above, and both have to
// hold or the fleet view is either blind or noisy.
func TestBeginningToSteerIsAChangeWorthShipping(t *testing.T) {
	store := newEndpointRuntimeStore()
	store.seedFromHistory([]map[string]any{{
		"tenant_id": "acme", "device_id": "mac-dev-1", "timestamp": "2026-08-08T01:54:22Z",
		"os": "macOS 26.5.2", "logged_in_users": []any{"a.tanaka"},
		"disk_encryption_enabled": true, "firewall_enabled": true,
	}})

	var emitted []map[string]any
	prev := deviceStateChangeEmit
	deviceStateChangeEmit = func(e map[string]any) { emitted = append(emitted, e) }
	defer func() { deviceStateChangeEmit = prev }()

	store.recordSteeredFlow("mac-dev-1", "acme", "a.tanaka", time.Date(2026, 8, 8, 2, 0, 0, 0, time.UTC))
	if len(emitted) != 1 {
		t.Fatalf("a device that started steering emitted %d events; the fleet view learns about a failover from "+
			"exactly this one", len(emitted))
	}
	if emitted[0]["last_steered"] == "" {
		t.Fatal("the event does not say when it steered, so a reader cannot tell current from historical")
	}
}

// A row with no usable timestamp cannot claim to be the latest state of anything.
func TestSeedFromHistorySkipsUndatedAndUnidentifiedRows(t *testing.T) {
	store := newEndpointRuntimeStore()
	restored := store.seedFromHistory([]map[string]any{
		{"tenant_id": "acme", "device_id": "no-time", "os": "macOS"},
		{"tenant_id": "acme", "timestamp": "2026-08-08T01:54:22Z", "os": "macOS"},
	})
	if restored != 0 {
		t.Fatalf("restored %d, want 0 — an undated or unidentified row is not a state", restored)
	}
}

// ★★ "STEERING" MUST MEAN TRAFFIC, NOT CONTACT (2026-08-13, from the lab: the Devices page reported a Mac as
// actively steering whose only conversation with the Edge in twenty-five minutes was the update courier asking
// which version to run). steer_active was derived from lastSeen, and lastSeen is stamped by ANY contact — so a
// device that steered nothing at all read as protected.
func TestSteeringIsClaimedOnlyFromEvidenceOfSteering(t *testing.T) {
	store := newEndpointRuntimeStore()
	now := time.Now().UTC()

	// Contact that is NOT steering: the update courier fetching a manifest stamps presence only.
	store.mu.Lock()
	e := store.entry("mac-dev-1")
	e.lastSeen = now
	store.mu.Unlock()

	view := store.snapshot(now)["mac-dev-1"]
	if view.SteerActive {
		t.Fatal("a device that only asked us a question is reported as actively steering — the screen says " +
			"protected and the evidence says it fetched a manifest")
	}
	if view.LastSteered != "" {
		t.Fatalf("last_steered = %q for a device that has never steered", view.LastSteered)
	}

	// A flow OPEN is traffic being carried.
	store.recordSteeredFlow("mac-dev-1", "t1", "a.tanaka", now)
	view = store.snapshot(now)["mac-dev-1"]
	if !view.SteerActive {
		t.Fatal("a device that just steered a flow is not reported as steering")
	}
	if view.LastSteered == "" {
		t.Fatal("last_steered is empty after a flow")
	}

	// And it lapses on its own, so a device that stops steering stops claiming to.
	later := now.Add(steerActiveWindow + time.Minute)
	if store.snapshot(later)["mac-dev-1"].SteerActive {
		t.Fatal("the claim outlived the evidence")
	}
}

// ★★ A FLOW WITH NO USERNAME IS STILL A FLOW (2026-08-14). The mux handler called this only
// `if osUser != ""` — reasonable-looking under the function's old name, recordFlowUser — and since this is the
// only place a device is credited with carrying traffic, a flow whose optional metadata section is absent left
// the device recorded as never having steered. The `u=` extension is optional by design and an older agent
// omits it entirely, so this is a live path, not a hypothetical one.
func TestAFlowWithNoUsernameStillCountsAsSteering(t *testing.T) {
	store := newEndpointRuntimeStore()
	now := time.Date(2026, 8, 14, 5, 0, 0, 0, time.UTC)

	store.recordSteeredFlow("mac-dev-1", "acme", "", now)

	view := store.snapshot(now)["mac-dev-1"]
	if !view.SteerActive {
		t.Fatal("a device that carried a flow is reported as not steering because the flow carried no username")
	}
	if view.LastSteered == "" {
		t.Fatal("last_steered is empty after a flow that had no username")
	}
	if len(view.LoggedInUsers) != 0 {
		t.Fatalf("users = %v, want none — an absent username must not become a user", view.LoggedInUsers)
	}
}
