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
		device, exists, err = deviceForTenant(devices, req.TenantID, req.DeviceID)
	}
	if err != nil {
		return req, err
	}
	req.DeviceTrustLevel = valueOrDefault(req.DeviceTrustLevel, connectTrust)
	// Without CONNECT network posture, preserve the full inventory trust verdict.
	// A two-axis heartbeat must not promote an OS-noncompliant device.
	if connectTrust != "" {
		var posture *model.DevicePostureSignals
		if runtime != nil {
			runtime.mu.RLock()
			if row := runtime.m[req.DeviceID]; row != nil && row.tenant == req.TenantID && row.posture.CollectedAt != "" {
				p := row.posture
				posture = &p
			}
			runtime.mu.RUnlock()
		}
		if err == nil && exists && device.Posture != nil {
			at, parseErr := time.Parse(time.RFC3339, device.Posture.CollectedAt)
			var previous time.Time
			if posture != nil {
				previous, _ = time.Parse(time.RFC3339, posture.CollectedAt)
			}
			if parseErr == nil && !at.Before(previous) {
				posture = device.Posture
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
