package main

import (
	"time"

	devicestore "github.com/lantern-networks/dsse-core/device"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/revocation"
)

// Read inventory once per evaluation. Both initial admission and authenticated
// release stop when the inventory cannot be read: otherwise risk or posture
// conditions may disappear and an ordinary allow rule can win.
func enrichSteerDeviceRequest(req model.DecisionRequest, connectTrust string, runtime *endpointRuntimeStore, devices deviceRuntimeStore, highRisk *revocation.HighRiskOverlay, ledger *enrolledinventory.Ledger) (model.DecisionRequest, error) {
	var device model.Device
	var exists bool
	var err error
	if devices != nil {
		device, exists, err = deviceForTenant(devices, req.TenantID, enrolledinventory.NormalizeIdentity(req.DeviceID))
	}
	if err != nil {
		return req, err
	}
	req.DeviceTrustLevel = valueOrDefault(req.DeviceTrustLevel, connectTrust)
	// Without CONNECT network posture, preserve the full inventory trust verdict.
	// A two-axis heartbeat must not promote an OS-noncompliant device.
	if connectTrust != "" {
		var posture *model.DevicePostureSignals
		var live *deviceRuntimeView
		if runtime != nil {
			runtime.mu.RLock()
			if row := runtime.m[enrolledinventory.NormalizeIdentity(req.DeviceID)]; row != nil && row.tenant == req.TenantID {
				view := row.runtimeView(time.Now())
				for _, field := range runtimePostureFields {
					if !runtimeTime(view.ObservedAt[field]).IsZero() {
						live = &view
						break
					}
				}
			}
			runtime.mu.RUnlock()
		}
		if live != nil {
			posture = &live.Posture
		}
		if err == nil && exists && device.Posture != nil {
			if at := runtimeTime(device.Posture.CollectedAt); !at.IsZero() {
				// Inventory is a complete posture snapshot. Compare each live
				// signal's original observation; a newer negative must not be
				// hidden by another signal's older collection time. Inventory
				// retains precedence on equal clocks, as before.
				inventory := deviceRuntimeView{Posture: *device.Posture, ObservedAt: runtimeObservationTimes{}}
				for _, field := range runtimePostureFields {
					inventory.ObservedAt[field] = runtimeTimeString(at)
				}
				if live != nil {
					inventory = mergeRuntimeViews(inventory, *live)
				}
				posture = &inventory.Posture
			}
		}
		if posture != nil {
			policy := posturePolicyFromEnv()
			req.DeviceTrustLevel, _, _ = devicestore.DerivePostureTrustLevel(posture, devicestore.PosturePolicy{RequireDiskEncryption: policy.RequireDiskEncryption, RequireFirewall: policy.RequireFirewall})
		}
	}
	// A missing device is distinct from an unreadable inventory. Only the
	// former reaches here without a device record; shared marks and group risk
	// still participate in that policy decision.
	req = enrichDecisionRequestWithDeviceRisk(req, nil, highRisk)
	if err == nil && exists {
		req = enrichDecisionRequestWithDeviceRecord(req, device)
	}
	req = enrichDecisionRequestWithRisk(req, nil, nil, ledger)
	return req, nil
}
