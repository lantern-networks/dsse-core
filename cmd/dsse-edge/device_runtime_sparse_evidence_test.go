package main

import (
	"encoding/json"
	"testing"
	"time"
)

func captureRuntimeEvents(t *testing.T) *[]map[string]any {
	t.Helper()
	var events []map[string]any
	previous := deviceStateChangeEmit
	deviceStateChangeEmit = func(event map[string]any) {
		// Match the JSON shipment boundary, including tri-state pointers and users.
		body, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(body, &decoded); err != nil {
			t.Fatal(err)
		}
		events = append(events, decoded)
	}
	t.Cleanup(func() { deviceStateChangeEmit = previous })
	return &events
}

func TestRuntimeCaseAliasesAndHeartbeatKeepOriginalMetadata(t *testing.T) {
	events := captureRuntimeEvents(t)
	s := newEndpointRuntimeStore()
	now := time.Date(2026, 10, 26, 11, 0, 0, 0, time.UTC)
	yes, no := true, false
	s.ingestFromReport(" Mac-One ", "tenant", "macOS", &yes, &no, "collector", "192.0.2.1", now)
	s.recordSteeredFlow("Mac-One", "tenant", "user", now)
	s.ingestAgentVersion("mac-one", "tenant", "0.4.0+one", now.Add(time.Minute))
	local := s.snapshot(now.Add(time.Minute))
	if len(local) != 1 || local["mac-one"].OS != "macOS" {
		t.Fatalf("case aliases split the live identity: %+v", local)
	}
	p := newFleetDeviceProjection()
	for _, event := range *events {
		p.Fold(event)
	}
	records, _ := p.Devices("tenant")
	if len(records) != 1 || records[0].DeviceID != "mac-one" {
		t.Fatalf("case aliases split the fleet identity: %+v", records)
	}
	view := runtimeViewFromRecord(records[0], now.Add(time.Minute))
	if view.OS != "macOS" || len(view.LoggedInUsers) != 1 || !view.SteerActive ||
		view.Posture.FirewallEnabled == nil || *view.Posture.FirewallEnabled ||
		view.Posture.CollectedAt != now.Format(time.RFC3339) {
		t.Fatalf("version heartbeat erased/refreshed runtime evidence: %+v", view)
	}
	if runtimeViewFromRecord(records[0], now.Add(steerActiveWindow+time.Second)).SteerActive {
		t.Fatal("heartbeat extended the steering evidence lifetime")
	}
}

func TestSparseOtherEdgeCannotEraseOrRefreshRuntimeEvidence(t *testing.T) {
	events := captureRuntimeEvents(t)
	a, b := newEndpointRuntimeStore(), newEndpointRuntimeStore()
	now := time.Date(2026, 10, 26, 11, 0, 0, 0, time.UTC)
	yes := true
	a.ingestFromReport("Mac-One", "tenant", "macOS", &yes, &yes, "collector", "192.0.2.1", now)
	a.recordSteeredFlow("Mac-One", "tenant", "user", now)
	b.ingestAgentVersion("mac-one", "tenant", "0.4.0", now.Add(time.Minute))
	b.recordSteeredFlow("MAC-ONE", "tenant", "", now.Add(70*time.Second))
	p := newFleetDeviceProjection()
	// Delivery can be reversed: a newer heartbeat is not a newer OS observation.
	for i := len(*events) - 1; i >= 0; i-- {
		p.Fold((*events)[i])
	}
	view, _ := mergeFleetDeviceRuntimeFromProjection(b.snapshot(now.Add(71*time.Second)), p, "tenant", now.Add(71*time.Second))
	got := view["mac-one"]
	if got.OS != "macOS" || len(got.LoggedInUsers) != 1 || got.Posture.DiskEncryptionEnabled == nil ||
		got.Posture.CollectedAt != now.Format(time.RFC3339) || !got.SteerActive {
		t.Fatalf("sparse local/fleet evidence hid the actual report: %+v", got)
	}
	if other, _ := mergeFleetDeviceRuntimeFromProjection(nil, p, "other-tenant", now); len(other) != 0 {
		t.Fatal("runtime merge crossed the tenant boundary")
	}
}

func TestPartialPostureDoesNotResurrectAnotherEdgesOlderPositive(t *testing.T) {
	events := captureRuntimeEvents(t)
	a, b := newEndpointRuntimeStore(), newEndpointRuntimeStore()
	now := time.Date(2026, 10, 26, 11, 0, 0, 0, time.UTC)
	yes, no := true, false
	a.ingestFromReport("Mac-One", "tenant", "macOS", &yes, &yes, "collector", "", now)
	b.ingestFromReport("mac-one", "tenant", "", &no, nil, "collector", "", now.Add(100*time.Millisecond))
	a.ingestFromReport("Mac-One", "tenant", "", nil, &no, "collector", "", now.Add(200*time.Millisecond))
	p := newFleetDeviceProjection()
	for _, event := range *events {
		p.Fold(event)
	}
	records, _ := p.Devices("tenant")
	got := records[0].Posture
	if got.DiskEncryptionEnabled == nil || *got.DiskEncryptionEnabled || got.FirewallEnabled == nil || *got.FirewallEnabled {
		t.Fatalf("cached partial posture resurrected an older positive: %+v", got)
	}
	if runtimeTime(got.CollectedAt) != now.Add(100*time.Millisecond) {
		t.Fatalf("collection time refreshed an older retained signal: %s", got.CollectedAt)
	}
}

func TestExplicitRuntimeClearsWinOverOlderFleetEvidence(t *testing.T) {
	now := time.Date(2026, 10, 26, 11, 0, 0, 0, time.UTC)
	p := newFleetDeviceProjection()
	full := row("Mac-One", now.Format(time.RFC3339), "edge-a", now.Format(time.RFC3339), "user")
	full["tenant_id"], full["disk_encryption_enabled"] = "tenant", true
	p.Fold(full)
	clearTime := now.Add(time.Second).Format(time.RFC3339)
	clear := map[string]any{
		"tenant_id": "tenant", "device_id": "mac-one", "timestamp": clearTime,
		"os": "", "logged_in_users": []any{}, "disk_encryption_enabled": nil,
		"runtime_observed_at": map[string]string{"os": clearTime, "users": clearTime, "disk_encryption_enabled": clearTime},
	}
	p.Fold(clear)
	p.Fold(full) // replay of the previous complete snapshot
	records, _ := p.Devices("tenant")
	got := runtimeViewFromRecord(records[0], now.Add(2*time.Second))
	if got.OS != "" || len(got.LoggedInUsers) != 0 || got.Posture.DiskEncryptionEnabled != nil {
		t.Fatalf("an explicit clear was undone: %+v", got)
	}
	older := deviceRuntimeView{OS: "old", LastSeen: now.Format(time.RFC3339), ObservedAt: runtimeObservationTimes{"os": now.Format(time.RFC3339)}}
	if merged := mergeRuntimeViews(got, older); merged.OS != "" {
		t.Fatal("local explicit clear was filled from older fleet evidence")
	}
}

func TestRuntimeHydrationPreservesEmptyObservationMarkerAndPosture(t *testing.T) {
	now := time.Date(2026, 10, 26, 11, 0, 0, 0, time.UTC)
	s := newEndpointRuntimeStore()
	yes := true
	s.ingestFromReport("Mac-One", "tenant", "macOS", &yes, nil, "collector", "", now)
	s.ingestAgentVersion("empty", "tenant", "0.4.0", now)
	for id, view := range s.snapshot(now) {
		body, err := json.Marshal(view)
		if err != nil {
			t.Fatal(err)
		}
		var row map[string]any
		if err := json.Unmarshal(body, &row); err != nil {
			t.Fatal(err)
		}
		if _, exists := row["observed_at"]; !exists {
			t.Fatal("compact view lost the explicit unobserved marker")
		}
		row["device_id"], row["tenant_id"], row["timestamp"] = id, "tenant", row["last_seen"]
		restored := newEndpointRuntimeStore()
		restored.seedFromHistory([]map[string]any{row})
		got := restored.snapshot(now)[id]
		if id == "empty" && len(got.ObservedAt) != 0 {
			t.Fatal("heartbeat-only hydration invented runtime observations")
		}
		if id == "mac-one" && (got.Posture.DiskEncryptionEnabled == nil || !*got.Posture.DiskEncryptionEnabled || got.Posture.CollectedAt != view.Posture.CollectedAt) {
			t.Fatalf("compact hydration lost posture or its collection time: %+v", got)
		}
	}
}

func TestRuntimeHydrationMergesFactsAcrossRacingHeartbeat(t *testing.T) {
	now := time.Date(2026, 10, 26, 11, 0, 0, 0, time.UTC)
	yes, no := true, false
	fleet := newEndpointRuntimeStore()
	fleet.ingestFromReport("Mac-One", "tenant", "macOS", &yes, &yes, "collector", "", now)
	body, err := json.Marshal(fleet.snapshot(now)["mac-one"])
	if err != nil {
		t.Fatal(err)
	}
	var row map[string]any
	if err := json.Unmarshal(body, &row); err != nil {
		t.Fatal(err)
	}
	row["device_id"], row["tenant_id"], row["timestamp"] = "MAC-ONE", "tenant", row["last_seen"]

	for _, mode := range []string{"heartbeat", "newer-report", "explicit-clear", "other-tenant"} {
		t.Run(mode, func(t *testing.T) {
			local := newEndpointRuntimeStore()
			tenant := "tenant"
			if mode == "other-tenant" {
				tenant = "Tenant"
			}
			local.ingestAgentVersion("mac-one", tenant, "0.4.0", now.Add(time.Minute))
			if mode == "newer-report" {
				local.ingestFromReport("Mac-One", tenant, "newOS", &no, nil, "collector", "", now.Add(time.Second))
			}
			if mode == "explicit-clear" {
				local.m["mac-one"].observed("os", now.Add(time.Second))
				local.m["mac-one"].observed("disk_encryption_enabled", now.Add(time.Second))
			}
			local.seedFromHistory([]map[string]any{row})
			got := local.snapshot(now.Add(time.Minute))["mac-one"]
			switch mode {
			case "heartbeat":
				if got.OS != "macOS" || got.Posture.DiskEncryptionEnabled == nil || !*got.Posture.DiskEncryptionEnabled {
					t.Fatalf("racing heartbeat hid fleet facts: %+v", got)
				}
			case "newer-report":
				if got.OS != "newOS" || got.Posture.DiskEncryptionEnabled == nil || *got.Posture.DiskEncryptionEnabled || got.Posture.FirewallEnabled == nil {
					t.Fatalf("hydration overwrote live evidence or missed unobserved field: %+v", got)
				}
			case "explicit-clear":
				if got.OS != "" || got.Posture.DiskEncryptionEnabled != nil {
					t.Fatalf("hydration undid explicit clear: %+v", got)
				}
			case "other-tenant":
				if got.OS != "" || got.Posture.DiskEncryptionEnabled != nil {
					t.Fatal("hydration crossed a tenant boundary")
				}
			}
			if local.m["mac-one"].agentVersion != "0.4.0" {
				t.Fatal("hydration replaced the live version heartbeat")
			}
		})
	}
}

func TestLegacyCompactPostureKeepsCollectionTimeAndUnreportedSignal(t *testing.T) {
	now := time.Date(2026, 10, 26, 11, 0, 0, 0, time.UTC)
	collected := now.Add(-time.Hour)
	s := newEndpointRuntimeStore()
	s.seedFromHistory([]map[string]any{{
		"device_id": "Mac-One", "tenant_id": "tenant", "timestamp": now.Format(time.RFC3339),
		"posture": map[string]any{"enforcement_agent_healthy": true, "collected_at": collected.Format(time.RFC3339), "source": "collector"},
	}})
	if got := s.snapshot(now)["mac-one"].Posture; got.CollectedAt != collected.Format(time.RFC3339) {
		t.Fatalf("legacy compact hydration refreshed posture: %+v", got)
	}
	yes := true
	s.ingestFromReport("MAC-ONE", "tenant", "macOS", &yes, nil, "collector", "", now.Add(time.Second))
	got := s.snapshot(now.Add(time.Second))["mac-one"].Posture
	if got.EnforcementAgentHealthy == nil || !*got.EnforcementAgentHealthy || got.CollectedAt != collected.Format(time.RFC3339) {
		t.Fatalf("partial report erased or refreshed an unreported signal: %+v", got)
	}
}
