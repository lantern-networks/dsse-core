package revocation

import (
	"fmt"
	"strings"
)

// AutomaticRiskResult describes the local overlay at completion, not fleet
// propagation or an administrative action. Applied means the requested minimum
// severity is present. Persistence describes this attempt only.
type AutomaticRiskResult struct {
	Severity    string `json:"severity,omitempty"`
	Applied     bool   `json:"applied"`
	Changed     bool   `json:"changed"`
	Persistence string `json:"persistence"`
}

// RaiseDeviceRisk never lowers an existing mark. It publishes escalation before
// storage, preserving protection if storage fails, and reports that partial
// outcome. The next matching detection retries an unconfirmed shared snapshot.
// Once saved, identical detections avoid repeated disk writes. Administrative
// changes continue to use SetDeviceRisk's save-before-publish contract.
func (o *HighRiskOverlay) RaiseDeviceRisk(deviceID, severity string) (AutomaticRiskResult, error) {
	result := AutomaticRiskResult{Persistence: "not_attempted"}
	if o == nil {
		return result, ErrRiskUnavailable
	}
	id := NormalizeDeviceID(deviceID)
	severity = strings.ToLower(strings.TrimSpace(severity))
	if id == "" || riskRank(severity) == 0 {
		return result, fmt.Errorf("invalid automatic device risk")
	}
	o.writeMu.Lock()
	defer o.writeMu.Unlock()
	if o.loadErr != nil || o.legacy {
		return result, ErrRiskUnavailable
	}
	previous := o.devices[id]
	result.Severity, result.Applied = previous, true
	if riskRank(severity) > riskRank(previous) {
		candidate := make(map[string]string, len(o.devices)+1)
		for key, value := range o.devices {
			candidate[key] = value
		}
		candidate[id] = severity
		o.mu.Lock()
		o.devices = candidate
		o.generation.Add(1)
		o.mu.Unlock()
		result.Severity, result.Changed = severity, true
	}
	if !result.Changed && !o.riskSavePending {
		return result, nil
	}
	warning, err := o.saveStateLocked(o.devices, o.users)
	if err != nil {
		result.Persistence = "unconfirmed"
		return result, err
	}
	result.Persistence = "saved"
	if warning {
		result.Persistence = "saved_non_atomic"
		if o.persister == nil {
			result.Persistence = "volatile"
		}
	}
	return result, nil
}
