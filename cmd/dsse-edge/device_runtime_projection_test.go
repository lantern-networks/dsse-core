package main

import (
	"testing"
	"time"
)

func row(device, ts, edge, lastSteered string, users ...string) map[string]any {
	u := make([]any, 0, len(users))
	for _, s := range users {
		u = append(u, s)
	}
	return map[string]any{
		"tenant_id": "acme", "device_id": device, "timestamp": ts,
		"os": "macOS 26.5.2", "edge": edge, "last_steered": lastSteered, "logged_in_users": u,
	}
}

// ★★ THE PROJECTION IS BOUNDED BY THE FLEET, NOT BY HOW MUCH IT STEERS (2026-08-14). This is the whole reason
// it exists. The fleet view used to replay 48 hours of shipped rows per Console load, which was affordable
// while a steadily-steering device emitted one event ever. It re-ships once a minute now — 1440 rows a day —
// and that query was measured at 10.7 seconds.
func TestTheProjectionHoldsOneEntryPerDeviceHoweverOftenItReports(t *testing.T) {
	p := newFleetDeviceProjection()
	base := time.Date(2026, 8, 14, 6, 0, 0, 0, time.UTC)
	for i := 0; i < 1440; i++ { // a day of minute-by-minute refreshes
		ts := base.Add(time.Duration(i) * time.Minute).Format(time.RFC3339)
		p.Fold(row("mac-dev-1", ts, "region-b/local-edge-001", ts, "a.tanaka"))
	}
	records, _ := p.Devices("acme")
	if len(records) != 1 {
		t.Fatalf("1440 refreshes produced %d entries, want 1 — the projection has to be bounded by devices or "+
			"it is just the log with extra steps", len(records))
	}
	want := base.Add(1439 * time.Minute).Format(time.RFC3339)
	if records[0].Timestamp != want {
		t.Fatalf("kept %s, want the newest (%s)", records[0].Timestamp, want)
	}
}

// ★★ NEWEST BY THE ROW'S OWN CLOCK, NOT BY ARRIVAL (2026-08-14). The shipper RETAINS and REPLAYS on failure:
// region-b delivered 176 records in one burst that afternoon, oldest first, after the rows that had overtaken
// it. An arrival-ordered fold would have described every device by whichever row happened to land last.
func TestAReplayedBacklogDoesNotOverwriteNewerState(t *testing.T) {
	p := newFleetDeviceProjection()
	p.Fold(row("mac-dev-1", "2026-08-14T06:30:00Z", "region-b/local-edge-001", "2026-08-14T06:30:00Z", "a.tanaka"))
	// The backlog lands afterwards, carrying older state.
	p.Fold(row("mac-dev-1", "2026-08-14T05:00:00Z", "region-a/local-edge-001", "2026-08-14T05:00:00Z"))

	records, _ := p.Devices("acme")
	if len(records) != 1 || records[0].Timestamp != "2026-08-14T06:30:00Z" {
		t.Fatalf("a replayed backlog overwrote newer state: %+v", records)
	}
	if records[0].Edge != "region-b/local-edge-001" {
		t.Fatalf("edge went backwards to %q", records[0].Edge)
	}
}

// ★ "NOT SEEDED YET" AND "THIS FLEET HAS ONE NODE" ARE THE SAME EMPTY MAP (2026-08-14). They must not render
// the same: the first must answer fleet_wide=false, or a Console page shows one node's devices as the fleet
// during the window right after a restart — which is exactly when a device looks missing.
func TestAnUnseededProjectionDoesNotClaimToCoverTheFleet(t *testing.T) {
	p := newFleetDeviceProjection()
	local := map[string]deviceRuntimeView{"win-dev-1": {OS: "Windows 11 25H2"}}

	_, seeded := mergeFleetDeviceRuntimeFromProjection(local, p, "acme", time.Now())
	if seeded {
		t.Fatal("an empty, never-seeded projection reported that this answer covers the fleet")
	}

	p.Seed(nil) // read the history, found nothing — a real answer about a one-node fleet
	if _, seeded = mergeFleetDeviceRuntimeFromProjection(local, p, "acme", time.Now()); !seeded {
		t.Fatal("after seeding, an empty fleet still reports as unseeded — a restart would never look covered")
	}
}

// The local live view wins where they overlap, and a device only the projection knows is marked with the Edge
// carrying it — the two properties the merge existed for before this rewrite.
func TestLiveBeatsProjectionAndTheOtherEdgeIsNamed(t *testing.T) {
	now := time.Date(2026, 8, 14, 7, 0, 0, 0, time.UTC)
	p := newFleetDeviceProjection()
	p.Seed([]map[string]any{
		// Stale record for a device that is live HERE.
		row("win-dev-1", "2026-08-14T05:00:00Z", "region-a/local-edge-001", "2026-08-14T05:00:00Z"),
		// A device this node has never seen, steering elsewhere a moment ago.
		row("mac-dev-1", "2026-08-14T06:59:30Z", "region-b/local-edge-001", "2026-08-14T06:59:30Z", "a.tanaka"),
	})
	local := map[string]deviceRuntimeView{"win-dev-1": {OS: "Windows 11 25H2", SteerActive: true}}

	merged, seeded := mergeFleetDeviceRuntimeFromProjection(local, p, "acme", now)
	if !seeded {
		t.Fatal("seeded projection reported unseeded")
	}
	if !merged["win-dev-1"].SteerActive {
		t.Fatal("a stale shipped record overwrote the live view of a device steering through THIS node")
	}
	mac := merged["mac-dev-1"]
	if mac.Edge != "region-b/local-edge-001" {
		t.Fatalf("edge = %q — an operator asking why a device is missing needs to be told where it went", mac.Edge)
	}
	if !mac.SteerActive {
		t.Fatal("a device that steered 30s ago through another Edge is reported as not steering")
	}
	// And the claim lapses on its own, because the record is a moment and the question is about now.
	later := now.Add(steerActiveWindow + time.Minute)
	if m, _ := mergeFleetDeviceRuntimeFromProjection(nil, p, "acme", later); m["mac-dev-1"].SteerActive {
		t.Fatal("the claim outlived the evidence")
	}
}

// ★★ POSTURE TRAVELS, OR THE FLEET VIEW CANNOT BE ASKED ABOUT IT (2026-08-14, from the operator: "posture is no
// longer visible in the device list"). Posture is ingested by the EDGE a device reports to; the control plane
// has none of its own. When the Console began reading the fleet-wide answer first, the posture column went
// structurally empty — not stale, not unknown, ABSENT — while the Edge one desk away still held it.
//
// A projection that carries part of a record decides, silently, which questions the view can answer.
func TestPostureSurvivesTheProjection(t *testing.T) {
	p := newFleetDeviceProjection()
	r := row("mac-dev-1", "2026-08-14T09:00:00Z", "region-b/local-edge-001", "2026-08-14T09:00:00Z", "a.tanaka")
	r["disk_encryption_enabled"] = true
	r["firewall_enabled"] = false
	r["posture_collected_at"] = "2026-08-14T08:59:00Z"
	r["posture_source"] = "macos_collector"
	p.Seed([]map[string]any{r})

	merged, _ := mergeFleetDeviceRuntimeFromProjection(nil, p, "acme", time.Date(2026, 8, 14, 9, 0, 30, 0, time.UTC))
	got := merged["mac-dev-1"].Posture
	if got.DiskEncryptionEnabled == nil || !*got.DiskEncryptionEnabled {
		t.Fatalf("disk encryption did not survive the projection: %+v", got)
	}
	if got.FirewallEnabled == nil || *got.FirewallEnabled {
		t.Fatalf("a reported FALSE became %v — 'not enabled' and 'not reported' are different answers",
			got.FirewallEnabled)
	}
	if got.CollectedAt != "2026-08-14T08:59:00Z" {
		t.Fatalf("collected_at = %q — without it a reader cannot tell a posture answer from a posture memory",
			got.CollectedAt)
	}
	if got.Source != "macos_collector" {
		t.Fatalf("source = %q", got.Source)
	}
}

// A signal the device never reported stays ABSENT rather than becoming false — the tri-state is the point.
func TestAnUnreportedSignalIsNotFalse(t *testing.T) {
	p := newFleetDeviceProjection()
	p.Seed([]map[string]any{row("mac-dev-1", "2026-08-14T09:00:00Z", "region-a", "2026-08-14T09:00:00Z")})
	got := mustMerged(t, p)["mac-dev-1"].Posture
	if got.DiskEncryptionEnabled != nil {
		t.Fatalf("an unreported signal became %v — that is an answer this device never gave",
			*got.DiskEncryptionEnabled)
	}
}

func mustMerged(t *testing.T, p *fleetDeviceProjection) map[string]deviceRuntimeView {
	t.Helper()
	m, _ := mergeFleetDeviceRuntimeFromProjection(nil, p, "acme", time.Date(2026, 8, 14, 9, 0, 30, 0, time.UTC))
	return m
}
