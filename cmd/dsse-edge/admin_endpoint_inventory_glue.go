package main

import (
	"context"
	"log"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	endpointinventory "github.com/lantern-networks/dsse-core/endpointinventory"
	"github.com/lantern-networks/dsse-core/model"
)

// newAdminEndpointInventoryStore builds the endpoint inventory from the device store. This stays in cmd/edge
// (not internal/endpointinventory) because it depends on the deviceRuntimeStore; it derives each entry via
// EntryFromDevice and populates the pure store with Upsert.
func newAdminEndpointInventoryStore(tenantID string, deviceStore deviceRuntimeStore, now time.Time) *endpointinventory.Store {
	store := endpointinventory.NewStore()
	refreshAdminEndpointInventory(store, tenantID, deviceStore, now)
	return store
}

// refreshAdminEndpointInventory re-derives the device-backed entries from the device store, which is the
// authority for a device's own facts — including when it was last seen.
//
// It exists because building this once at start-up made /admin/endpoints a BOOT-TIME SNAPSHOT wearing the
// clothes of a live inventory. Heartbeats update the device store; nothing updated this copy. On 2026-08-05
// the Console reported mac-dev-1 last seen 2026-07-25 — eleven days — while the device was beating every 15
// seconds and the audit log recorded every beat. An inventory that reports a live device as long dead is the
// same failure as a device that cannot report at all: an operator still cannot tell a working fleet from a
// dark one, and here the product had the answer and was showing something else.
//
// Called on every read rather than on a timer: the number of devices is small, the callers are admin-only,
// and a refresh interval is one more thing that can be wrong. Entries with no backing device (manually
// upserted) are left alone.
func refreshAdminEndpointInventory(store endpointinventory.RuntimeStore, tenantID string, deviceStore deviceRuntimeStore, now time.Time) {
	if store == nil || deviceStore == nil {
		return
	}
	ctx := context.Background()
	for _, device := range deviceStore.List() {
		if tenantID != "" && device.TenantID != tenantID {
			continue
		}
		entry := endpointinventory.EntryFromDevice(device)
		// SAY SO when an entry is rejected. This used to be `_, _ =` with a comment noting that a
		// normalization failure skips the entry — and on 2026-08-05 that is exactly what happened: the macOS
		// agent started reporting a real build stamp ("0.1.0+20260805170618"), the '+' failed the field
		// allowlist, and the device DISAPPEARED from /admin/endpoints while it was heartbeating every 15
		// seconds. A device vanishing from the operator's inventory is indistinguishable from a device that
		// was never there, and the product knew the reason and discarded it.
		if _, err := store.Upsert(ctx, entry, firstNonEmptyString(device.TenantID, tenantID), now); err != nil {
			log.Printf("endpoint inventory: device %q is NOT listed — %v (it is present and reporting; the inventory rejected the record)", device.ID, err)
		}
	}
}

// adminEndpointInventoryAuditLog builds the audit record for an endpoint-inventory upsert. Kept in cmd/edge
// for the decision.Evaluator binding + the shared audit-id mint.
func adminEndpointInventoryAuditLog(endpoint endpointinventory.Entry, evaluator decision.Evaluator, now time.Time) model.AuditLog {
	action := "upsert"
	result := "success"
	reason := "Endpoint inventory admin metadata upserted."
	targetType := "admin_endpoint_inventory"
	return model.AuditLog{
		ID:             randomEdgeID("audit_", now),
		TenantID:       endpoint.TenantID,
		EventType:      "admin_endpoint_inventory_upserted",
		TargetType:     &targetType,
		TargetID:       &endpoint.EndpointID,
		Action:         &action,
		Result:         &result,
		Reason:         &reason,
		PolicyBundleID: &evaluator.PolicyBundle.ID,
		EdgeRegionID:   &evaluator.EdgeRegionID,
		EdgeClusterID:  &evaluator.EdgeClusterID,
		Timestamp:      now.UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"status":                           endpoint.Status,
			"device_trust_level":               endpoint.DeviceTrustLevel,
			"user_id_present":                  endpoint.UserID != "",
			"hostname_present":                 endpoint.Hostname != "",
			"os_present":                       endpoint.OS != "",
			"os_version_present":               endpoint.OSVersion != "",
			"agent_version_present":            endpoint.AgentVersion != "",
			"policy_bundle_id_present":         endpoint.PolicyBundleID != "",
			"policy_bundle_version_present":    endpoint.PolicyBundleVersion != "",
			"registered_at_present":            endpoint.RegisteredAt != "",
			"last_seen_at_present":             endpoint.LastSeenAt != "",
			"metadata_key_count":               endpoint.MetadataKeyCount,
			"source":                           endpoint.Source,
			"endpoint_metadata_recorded_scope": "none",
			"runtime_hot_reload":               false,
			"reason_codes":                     []string{"admin_endpoint_inventory_upsert"},
		},
	}
}
