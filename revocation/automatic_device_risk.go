package revocation

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
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
// With file storage, saved identical detections avoid repeated disk writes. Administrative
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
	if p, ok := o.persister.(contextUpdater); ok {
		return o.raiseSharedDeviceRiskLocked(p, id, severity)
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

// Local detections remain conservative on a storage outage. Shared writers
// must consult the locked row even for an unchanged detection: a local cache
// cannot certify either the current severity or the other writers' entries.
func (o *HighRiskOverlay) raiseSharedDeviceRiskLocked(p contextUpdater, id, severity string) (AutomaticRiskResult, error) {
	previous := o.devices[id]
	if riskRank(previous) > riskRank(severity) {
		severity = previous
	}
	result := AutomaticRiskResult{Severity: severity, Applied: true, Changed: previous != severity, Persistence: "unconfirmed"}
	if result.Changed {
		o.mu.Lock()
		o.devices = maps.Clone(o.devices)
		o.devices[id] = severity
		o.generation.Add(1)
		o.mu.Unlock()
	}
	o.riskSavePending = true
	var candidate highRiskOverlayStateFile
	err := p.UpdateContext(context.Background(), func(raw []byte) ([]byte, error) {
		candidate = highRiskOverlayStateFile{SchemaVersion: highRiskOverlayStateSchemaVersion, Devices: map[string]string{}, Users: map[string]UserRisk{}}
		if raw != nil {
			var err error
			candidate, err = decodeRiskSnapshot(raw)
			if err != nil {
				return nil, err
			}
			if candidate.SchemaVersion != highRiskOverlayStateSchemaVersion && len(candidate.Devices) > 0 {
				return nil, ErrRiskUnavailable
			}
		}
		// First local escalation may be the first write to this row.
		candidate.SchemaVersion = highRiskOverlayStateSchemaVersion
		o.mergeAutomaticPending(&candidate)
		if riskRank(severity) > riskRank(candidate.Devices[id]) {
			candidate.Devices[id] = severity
		}
		return json.Marshal(candidate)
	})
	if err != nil {
		if o.automaticPending == nil {
			o.automaticPending = map[string]string{}
		}
		o.automaticPending[id] = severity
		return result, ErrRiskSave
	}
	o.automaticPending = nil
	o.mu.Lock()
	if !maps.Equal(o.devices, candidate.Devices) || !reflect.DeepEqual(o.users, candidate.Users) {
		o.generation.Add(1)
	}
	o.devices, o.users = candidate.Devices, candidate.Users
	o.rebuildUserIndexLocked()
	o.riskSavePending = false
	result.Severity = candidate.Devices[id]
	result.Changed = previous != result.Severity
	result.Persistence = "saved"
	o.mu.Unlock()
	return result, nil
}

// Called under writeMu. Preserve unconfirmed local escalations when another
// target is saved; an explicit administrative edit runs after this merge.
func (o *HighRiskOverlay) mergeAutomaticPending(f *highRiskOverlayStateFile) {
	for id, severity := range o.automaticPending {
		if riskRank(severity) > riskRank(f.Devices[id]) {
			f.Devices[id] = severity
		}
	}
}
