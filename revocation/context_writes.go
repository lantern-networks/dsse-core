package revocation

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"strings"
)

type contextUpdater interface {
	UpdateContext(context.Context, func([]byte) ([]byte, error)) error
}

// RevokeCheckedContext carries request authority into shared storage. A refusal
// before the storage callback applies nothing. Once an authorized callback has
// run, an unconfirmed save retains the restrictive local decision. File-backed
// callers retain RevokeChecked's existing local-block-on-save-failure contract.
func (a *AdmissionRevocations) RevokeCheckedContext(ctx context.Context, identity, reason string) (bool, error) {
	return a.changeAdmissionContext(ctx, identity, reason, true)
}
func (a *AdmissionRevocations) RestoreCheckedContext(ctx context.Context, identity string) error {
	_, err := a.changeAdmissionContext(ctx, identity, "", false)
	return err
}
func (a *AdmissionRevocations) changeAdmissionContext(ctx context.Context, identity, reason string, revoke bool) (bool, error) {
	if a == nil {
		return false, ErrAdmissionSave
	}
	id := normalizeIdentity(identity)
	if id == "" {
		return false, nil
	}
	reason = strings.TrimSpace(reason)
	a.writeMu.Lock()
	p, ok := a.persister.(contextUpdater)
	if !ok {
		a.writeMu.Unlock()
		if revoke {
			return true, a.revokeContext(ctx, id, reason, true)
		}
		err := a.RestoreChecked(id)
		return err == nil, err
	}
	var candidate admissionRevocationsStateFile
	edited := false
	err := p.UpdateContext(ctx, func(raw []byte) ([]byte, error) {
		candidate = admissionRevocationsStateFile{SchemaVersion: admissionRevocationsStateSchemaVersion, Revoked: map[string]string{}, MeshReceived: map[string]string{}}
		if raw != nil {
			var err error
			candidate, err = decodeAdmissionSnapshot(raw)
			if err != nil {
				return nil, err
			}
		} else if a.generation.Load() != 0 {
			return nil, ErrAdmissionLoad
		}
		if revoke {
			candidate.Revoked[id] = reason
		} else {
			delete(candidate.Revoked, id)
		}
		edited = true
		return json.Marshal(candidate)
	})
	a.mu.Lock()
	previous, exists := a.revoked[id]
	notify := revoke && edited && (!exists || previous != reason)
	applied := err == nil || (revoke && edited)
	if err == nil {
		if !maps.Equal(a.revoked, candidate.Revoked) || !maps.Equal(a.meshReceived, candidate.MeshReceived) {
			a.generation.Add(1)
		}
		a.revoked, a.meshReceived = candidate.Revoked, candidate.MeshReceived
	} else if notify {
		a.revoked[id] = reason
		a.generation.Add(1)
	}
	reporter, meshReporter, onRevoked := a.reporter, a.meshReporter, a.onRevoked
	a.mu.Unlock()
	a.writeMu.Unlock()
	if notify {
		if reporter != nil {
			reporter(id, reason)
		}
		if meshReporter != nil {
			meshReporter(ctx, id, reason)
		}
		if onRevoked != nil {
			onRevoked(id, reason)
		}
	}
	if err != nil {
		return applied, ErrAdmissionSave
	}
	return applied, nil
}

// The context-aware administrative paths edit only their target in the latest
// shared row. Automatic local risk writers keep their existing contract.
func (o *HighRiskOverlay) SetDeviceRiskContext(ctx context.Context, id, severity string) (bool, error) {
	id = NormalizeDeviceID(id)
	severity = strings.ToLower(strings.TrimSpace(severity))
	if id == "" {
		return false, fmt.Errorf("device identity is required")
	}
	switch severity {
	case "", "none", "low":
		severity = ""
	case "medium", "high", "critical":
	default:
		return false, fmt.Errorf("invalid device risk severity")
	}
	handled, err := o.changeRiskContext(ctx, func(f *highRiskOverlayStateFile) {
		if severity == "" {
			delete(f.Devices, id)
		} else {
			f.Devices[id] = severity
		}
	})
	if !handled {
		return o.SetDeviceRisk(id, severity)
	}
	return false, err
}
func (o *HighRiskOverlay) SetUserRiskContext(ctx context.Context, mark UserRisk) (bool, error) {
	mark, err := normalizeUserRisk(mark)
	if err != nil {
		return false, err
	}
	handled, err := o.changeRiskContext(ctx, func(f *highRiskOverlayStateFile) {
		key := userRiskKey(mark.TenantID, mark.ID)
		if riskRank(mark.Severity) == 0 {
			delete(f.Users, key)
		} else {
			f.Users[key] = mark
		}
	})
	if !handled {
		return o.SetUserRisk(mark)
	}
	return false, err
}
func (o *HighRiskOverlay) changeRiskContext(ctx context.Context, edit func(*highRiskOverlayStateFile)) (bool, error) {
	if o == nil {
		return true, ErrRiskUnavailable
	}
	o.writeMu.Lock()
	defer o.writeMu.Unlock()
	p, ok := o.persister.(contextUpdater)
	if !ok {
		return false, nil
	}
	if o.loadErr != nil || o.legacy {
		return true, ErrRiskUnavailable
	}
	var candidate highRiskOverlayStateFile
	err := p.UpdateContext(ctx, func(raw []byte) ([]byte, error) {
		candidate = highRiskOverlayStateFile{SchemaVersion: highRiskOverlayStateSchemaVersion, Devices: map[string]string{}, Users: map[string]UserRisk{}}
		if raw != nil {
			var err error
			candidate, err = decodeRiskSnapshot(raw)
			if err != nil {
				return nil, err
			}
			if candidate.SchemaVersion != "high_risk_overlay_state.v2" && len(candidate.Devices) > 0 {
				return nil, ErrRiskUnavailable
			}
		} else if o.generation.Load() != 0 {
			return nil, ErrRiskLoad
		}
		candidate.SchemaVersion = highRiskOverlayStateSchemaVersion
		o.mergeAutomaticPending(&candidate)
		edit(&candidate)
		return json.Marshal(candidate)
	})
	if err != nil {
		return true, ErrRiskSave
	}
	o.mu.Lock()
	if !maps.Equal(o.devices, candidate.Devices) || !reflect.DeepEqual(o.users, candidate.Users) {
		o.generation.Add(1)
	}
	o.devices, o.users = candidate.Devices, candidate.Users
	o.riskSavePending = false
	o.automaticPending = nil
	o.rebuildUserIndexLocked()
	o.mu.Unlock()
	return true, nil
}
