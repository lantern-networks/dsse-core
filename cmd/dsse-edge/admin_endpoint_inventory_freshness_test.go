package main

import (
	"context"
	"testing"
	"time"

	devicestore "github.com/lantern-networks/dsse-core/device"
	endpointinventory "github.com/lantern-networks/dsse-core/endpointinventory"
	"github.com/lantern-networks/dsse-core/model"
)

// The endpoint inventory must reflect the device store at READ time, not at start-up.
//
// It was built once in newServerWithConfig and never refreshed, which made /admin/endpoints a boot-time
// snapshot wearing the clothes of a live inventory: on 2026-08-05 the Console reported mac-dev-1 last seen
// eleven days earlier while the device was beating every 15 seconds and every beat was in the audit log.
func TestEndpointInventoryRefreshesLastSeenFromTheDeviceStore(t *testing.T) {
	boot := time.Date(2026, 7, 25, 7, 21, 33, 0, time.UTC)
	later := time.Date(2026, 8, 5, 10, 30, 0, 0, time.UTC)

	devices := devicestore.NewStore()
	bundle := model.PolicyBundle{TenantID: "tenant_lab_001"}
	if _, err := devices.Register(model.Device{
		ID: "mac-dev-1", TenantID: "tenant_lab_001", Status: "active",
		DeviceTrustLevel: "managed", RegisteredAt: boot.Format(time.RFC3339),
		LastSeenAt: boot.Format(time.RFC3339),
	}, bundle, boot); err != nil {
		t.Fatalf("Register: %v", err)
	}
	store := newAdminEndpointInventoryStore("tenant_lab_001", devices, boot)

	// The device beats: the DEVICE store advances, exactly as the heartbeat handler makes it.
	if _, err := devices.Heartbeat(model.DeviceHeartbeat{
		ID: "mac-dev-1", TenantID: "tenant_lab_001", Status: "active",
	}, bundle, later); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}

	// Without a refresh the inventory still shows the boot value — the bug.
	got, _, err := store.Get(context.Background(), "tenant_lab_001", "mac-dev-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.LastSeenAt == later.Format(time.RFC3339) {
		t.Fatalf("precondition: the snapshot already advanced on its own; this test no longer covers the bug")
	}

	refreshAdminEndpointInventory(store, "tenant_lab_001", devices, later)

	got, found, err := store.Get(context.Background(), "tenant_lab_001", "mac-dev-1")
	if err != nil || !found {
		t.Fatalf("Get after refresh: found=%v err=%v", found, err)
	}
	if got.LastSeenAt != later.Format(time.RFC3339) {
		t.Fatalf("last_seen_at = %q, want %q — the inventory must report what the device store knows",
			got.LastSeenAt, later.Format(time.RFC3339))
	}
}

// A refresh must not delete entries that have no backing device (admin-authored ones).
func TestEndpointInventoryRefreshKeepsEntriesWithNoDevice(t *testing.T) {
	now := time.Date(2026, 8, 5, 10, 0, 0, 0, time.UTC)
	devices := devicestore.NewStore()
	store := endpointinventory.NewStore()
	if _, err := store.Upsert(context.Background(), endpointinventory.Entry{
		EndpointID: "manual-1", TenantID: "tenant_lab_001", Status: "active",
		DeviceTrustLevel: "managed", Source: "admin",
	}, "tenant_lab_001", now); err != nil {
		t.Fatalf("seed upsert: %v", err)
	}
	refreshAdminEndpointInventory(store, "tenant_lab_001", devices, now)
	if _, found, _ := store.Get(context.Background(), "tenant_lab_001", "manual-1"); !found {
		t.Fatalf("a manually authored endpoint was dropped by the refresh")
	}
}
