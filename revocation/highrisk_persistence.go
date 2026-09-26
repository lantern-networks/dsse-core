package revocation

import (
	"encoding/json"
	"errors"
	"log"
	"strings"

	"github.com/lantern-networks/dsse-core/blobstore"
)

// The v1 device map also held untyped user IDs. A nonempty v1 snapshot must be
// attributed before serving; otherwise upgrading it could silently clear a
// user mark or assign it to the wrong tenant.
type highRiskOverlayStateFile struct {
	SchemaVersion      string              `json:"schema_version"`
	Devices            map[string]string   `json:"devices"`
	Users              map[string]UserRisk `json:"users,omitempty"`
	LegacyUnattributed map[string]string   `json:"legacy_unattributed,omitempty"`
}

const highRiskOverlayStateSchemaVersion = "high_risk_overlay_state.v2"

func (o *HighRiskOverlay) SetStatePath(path string) error {
	if o == nil || strings.TrimSpace(path) == "" {
		return nil
	}
	return o.SetPersister(blobstore.FilePersister{Path: strings.TrimSpace(path)})
}

// SetPersister validates a complete snapshot before publishing either risk
// namespace. A failed load leaves the previous state in memory but makes
// checked reads and writes unavailable until a valid snapshot is restored.
func (o *HighRiskOverlay) SetPersister(p blobstore.Persister) error {
	if o == nil || p == nil {
		return nil
	}
	o.writeMu.Lock()
	defer o.writeMu.Unlock()
	data, err := p.Load()
	if err != nil {
		o.mu.Lock()
		o.loadErr = ErrRiskUnavailable
		o.mu.Unlock()
		return err
	}
	state := highRiskOverlayStateFile{Devices: map[string]string{}, Users: map[string]UserRisk{}, LegacyUnattributed: map[string]string{}}
	if data != nil {
		state, err = decodeRiskSnapshot(data)
		if err != nil {
			o.mu.Lock()
			o.loadErr = ErrRiskUnavailable
			o.mu.Unlock()
			return err
		}
	} else if o.ConfigGeneration() != 0 {
		return ErrRiskUnavailable
	}
	o.mu.Lock()
	o.devices, o.users = state.Devices, state.Users
	o.legacyUnattributed = state.LegacyUnattributed
	o.persister, o.loadErr = p, nil
	o.deviceSavePending = false
	o.legacy = state.SchemaVersion == "high_risk_overlay_state.v1" && len(state.Devices) != 0
	o.rebuildUserIndexLocked()
	o.generation.Add(1)
	o.mu.Unlock()
	log.Printf("high_risk_overlay load: restored %d device and %d user marks", len(state.Devices), len(state.Users))
	return nil
}

// saveStateLocked is called with writeMu held. Checked administrative changes
// call it before publishing their candidate maps to readers or the fleet.
func (o *HighRiskOverlay) saveStateLocked(devices map[string]string, users map[string]UserRisk, legacyOverride ...map[string]string) (bool, error) {
	if o.persister == nil {
		return true, nil
	}
	legacy := o.legacyUnattributed
	if len(legacyOverride) != 0 {
		legacy = legacyOverride[0]
	}
	data, err := json.Marshal(highRiskOverlayStateFile{SchemaVersion: highRiskOverlayStateSchemaVersion, Devices: devices, Users: users, LegacyUnattributed: legacy})
	if err != nil {
		return false, ErrRiskSave
	}
	if err := o.persister.Save(data); err != nil {
		if errors.Is(err, blobstore.ErrSavedWithoutAtomicity) {
			return true, nil
		}
		return false, ErrRiskSave
	}
	return false, nil
}

// Legacy device paths retain their existing API, but persist both namespaces
// together so a later device update cannot erase previously saved user marks.
func (o *HighRiskOverlay) persistLocked() {
	if o == nil || o.loadErr != nil || o.legacy {
		return
	}
	if _, err := o.saveStateLocked(o.devices, o.users); err != nil {
		o.deviceSavePending = true
		log.Printf("high_risk_overlay persist: %v", err)
	} else {
		o.deviceSavePending = false
	}
}
