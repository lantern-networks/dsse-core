package revocation

import (
	"encoding/json"
	"errors"
	"log"
	"maps"
	"reflect"
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

// SetStatePath restores a complete file snapshot before adopting its writer.
func (o *HighRiskOverlay) SetStatePath(path string) error {
	if o == nil || strings.TrimSpace(path) == "" {
		return nil
	}
	return o.SetPersister(blobstore.FilePersister{Path: strings.TrimSpace(path)})
}

// SetPersister is for initialization or explicit recovery. Invalid replacements
// retain both live namespaces, generation and the previous writer, but mark the
// store unavailable until a complete valid snapshot is restored. Callers must
// refuse startup on error. Missing/nil storage cannot clear a prior load failure.
func (o *HighRiskOverlay) SetPersister(p blobstore.Persister) error {
	if o == nil {
		return nil
	}
	o.writeMu.Lock()
	defer o.writeMu.Unlock()
	return o.restoreSnapshotLocked(p, false)
}

// ReloadFromStore refreshes both risk namespaces before a shared-store authority
// publishes leadership. A newly encountered legacy mark needs attribution at
// startup or explicit recovery; promotion must not guess its tenant or type.
func (o *HighRiskOverlay) ReloadFromStore() error {
	if o == nil {
		return ErrRiskUnavailable
	}
	o.writeMu.Lock()
	defer o.writeMu.Unlock()
	return o.restoreSnapshotLocked(o.persister, true)
}

func (o *HighRiskOverlay) restoreSnapshotLocked(p blobstore.Persister, refresh bool) error {
	if p == nil {
		if o.loadErr != nil {
			return o.loadErr
		}
		o.persister = nil
		o.riskSavePending = true
		return nil
	}
	data, err := p.Load()
	if err != nil {
		o.mu.Lock()
		o.loadErr = ErrRiskLoad
		o.mu.Unlock()
		return o.loadErr
	}
	// Persisters reserve nil for first boot; existing zero-byte files are invalid.
	if data == nil {
		if refresh && o.generation.Load() != 0 {
			o.mu.Lock()
			o.loadErr = ErrRiskLoad
			o.mu.Unlock()
			return ErrRiskLoad
		}
		if o.loadErr != nil {
			return o.loadErr
		}
		o.persister = p
		o.riskSavePending = len(o.devices) > 0 || len(o.users) > 0 || len(o.legacyUnattributed) > 0
		return nil
	}
	f, err := decodeRiskSnapshot(data)
	if err != nil {
		o.mu.Lock()
		o.loadErr = err
		o.mu.Unlock()
		return err
	}
	legacy := f.SchemaVersion == "high_risk_overlay_state.v1" && len(f.Devices) > 0
	if refresh && legacy {
		o.mu.Lock()
		o.loadErr = ErrRiskUnavailable
		o.mu.Unlock()
		return ErrRiskUnavailable
	}
	o.mu.Lock()
	if !maps.Equal(o.devices, f.Devices) || !reflect.DeepEqual(o.users, f.Users) || o.legacy != legacy || !maps.Equal(o.legacyUnattributed, f.LegacyUnattributed) {
		o.generation.Add(1)
	}
	o.devices, o.users, o.legacy = f.Devices, f.Users, legacy
	o.legacyUnattributed = f.LegacyUnattributed
	o.persister, o.loadErr = p, nil
	o.riskSavePending = false
	o.automaticPending = nil
	o.rebuildUserIndexLocked()
	o.mu.Unlock()
	log.Printf("high_risk_overlay load: restored %d device and %d user risk marks", len(o.devices), len(o.users))
	return nil
}

// ErrRiskLoad deliberately omits paths, backend details and saved contents.
var ErrRiskLoad = errors.New("cannot read risk snapshot")

// saveStateLocked requires writeMu, never mu. All publishers hold writeMu,
// leaving the maps stable during serialization while readers continue on the
// last published state. A nil persister retains the volatile warning contract.
func (o *HighRiskOverlay) saveStateLocked(devices map[string]string, users map[string]UserRisk, legacyOverride ...map[string]string) (bool, error) {
	// Failed or volatile attempts remain eligible for a later automatic retry.
	o.riskSavePending = true
	if o.persister == nil {
		return true, nil
	}
	legacy := o.legacyUnattributed
	if len(legacyOverride) != 0 {
		legacy = legacyOverride[0]
	}
	data, err := json.Marshal(highRiskOverlayStateFile{SchemaVersion: highRiskOverlayStateSchemaVersion, Devices: devices, Users: users, LegacyUnattributed: legacy})
	if err != nil {
		log.Printf("risk state encode: %v", err)
		return false, ErrRiskSave
	}
	if err = o.persister.Save(data); err != nil {
		log.Printf("risk state save: %v", err)
		// The legacy compatibility warning also matches an unconfirmed flush.
		// Only a completed, synced in-place save may publish checked changes.
		if errors.Is(err, blobstore.ErrSavedWithoutAtomicity) && !errors.Is(err, blobstore.ErrDurabilityUnconfirmed) {
			o.riskSavePending = false
			return true, nil
		}
		return false, ErrRiskSave
	}
	o.riskSavePending = false
	return false, nil
}
