package revocation

import (
	"fmt"
	"strings"
)

// SetDeviceRisk saves before publishing administrative risk changes, including
// escalation, downgrade and clearing. An explicit same-value retry also saves.
// The warning reports a volatile or completed non-atomic save, never an
// unconfirmed flush. Device identities are opaque and preserve case.
func (o *HighRiskOverlay) SetDeviceRisk(deviceID, severity string) (bool, error) {
	return o.setDeviceRisk(deviceID, severity, false)
}
func (o *HighRiskOverlay) setDeviceRisk(deviceID, severity string, legacy bool) (bool, error) {
	if o == nil {
		return false, ErrRiskUnavailable
	}
	id := NormalizeDeviceID(deviceID)
	if id == "" {
		return false, fmt.Errorf("device identity is required")
	}
	severity = strings.ToLower(strings.TrimSpace(severity))
	switch severity {
	case "", "none", "low":
		severity = ""
	case "medium", "high", "critical":
	default:
		return false, fmt.Errorf("invalid device risk severity")
	}
	o.writeMu.Lock()
	defer o.writeMu.Unlock()
	if o.loadErr != nil || o.legacy {
		return false, ErrRiskUnavailable
	}
	previous, exists := o.devices[id]
	changed := previous != severity || (exists && severity == "")
	if legacy && !changed {
		return false, nil
	}
	candidate := make(map[string]string, len(o.devices))
	for key, value := range o.devices {
		candidate[key] = value
	}
	if severity == "" {
		delete(candidate, id)
	} else {
		candidate[id] = severity
	}
	published := legacy && riskRank(severity) > riskRank(previous)
	if published {
		o.mu.Lock()
		o.devices = candidate
		o.generation.Add(1)
		o.mu.Unlock()
	}
	warning, err := o.saveStateLocked(candidate, o.users)
	if err != nil {
		return false, err
	}
	if changed && !published {
		o.mu.Lock()
		o.devices = candidate
		o.generation.Add(1)
		o.mu.Unlock()
	}
	return warning, nil
}
