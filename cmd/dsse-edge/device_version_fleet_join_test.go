package main

import (
	"testing"
	"time"
)

func TestVerifiedHeartbeatVersionReachesFleetWithoutEveryBeatShipment(t *testing.T) {
	store := newEndpointRuntimeStore()
	var events []map[string]any
	prior := deviceStateChangeEmit
	deviceStateChangeEmit = func(event map[string]any) { events = append(events, event) }
	defer func() { deviceStateChangeEmit = prior }()

	start := time.Date(2026, 10, 21, 5, 0, 0, 0, time.UTC)
	store.ingestAgentVersion("Mac-01", "tenant_a", "0.4.0+one", start)
	store.ingestAgentVersion("Mac-01", "tenant_a", "0.4.0+one", start.Add(15*time.Second))
	if len(events) != 1 {
		t.Fatalf("two heartbeats in one minute shipped %d events, want one", len(events))
	}
	store.ingestAgentVersion("Mac-01", "tenant_a", "0.4.0+one", start.Add(time.Minute))
	store.ingestAgentVersion("Mac-01", "tenant_a", "0.4.0+two", start.Add(time.Minute+15*time.Second))
	if len(events) != 3 {
		t.Fatalf("minute refresh and build change shipped %d events, want three", len(events))
	}

	projection := newFleetDeviceProjection()
	for _, event := range events {
		projection.Fold(event)
	}
	reports := fleetAgentVersionsByIdentity(projection, "tenant_a")
	if got := reports["mac-01"]; got.Version != "0.4.0+two" || got.ReportedAt != start.Add(time.Minute+15*time.Second).Format(time.RFC3339) {
		t.Fatalf("fleet version = %+v", got)
	}
	if got := fleetAgentVersionsByIdentity(projection, "tenant_b"); len(got) != 0 {
		t.Fatalf("another tenant saw device version: %+v", got)
	}
	if !newerVersionReport(reports["mac-01"].ReportedAt, start.Format(time.RFC3339)) ||
		newerVersionReport(start.Format(time.RFC3339), reports["mac-01"].ReportedAt) {
		t.Fatal("the fleet version timestamp did not resolve newer/older reports")
	}
}

func TestOlderDeviceStateShipmentCannotEraseReportedVersion(t *testing.T) {
	p := newFleetDeviceProjection()
	p.Fold(map[string]any{"tenant_id": "tenant_a", "device_id": "Mac-01", "timestamp": "2026-10-21T05:00:00Z",
		"agent_version": "0.4.0+one", "agent_version_reported_at": "2026-10-21T05:00:00Z"})
	p.Fold(map[string]any{"tenant_id": "tenant_a", "device_id": "Mac-01", "timestamp": "2026-10-21T05:01:00Z",
		"os": "macOS"})
	if got := fleetAgentVersionsByIdentity(p, "tenant_a")["mac-01"]; got.Version != "0.4.0+one" || got.ReportedAt != "2026-10-21T05:00:00Z" {
		t.Fatalf("legacy shipment erased a verified version: %+v", got)
	}
	p.Fold(map[string]any{"tenant_id": "tenant_b", "device_id": "Mac-01", "timestamp": "2026-10-21T05:02:00Z",
		"agent_version": "other-tenant", "agent_version_reported_at": "2026-10-21T05:02:00Z"})
	if got := fleetAgentVersionsByIdentity(p, "tenant_a")["mac-01"].Version; got != "0.4.0+one" {
		t.Fatalf("another tenant replaced the version: %q", got)
	}
}
