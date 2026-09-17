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

// Durable persistence for the high-risk device overlay (Phase 3). The control plane persists its set so a
// restart cannot silently CLEAR every high-risk marking (which would let risky devices be treated as clean
// fleet-wide on the next pull — a fail-open). Mirrors the admission-revocations store; a shared (Postgres)
// persister also carries it across a CP failover.

type highRiskOverlayStateFile struct {
	SchemaVersion string              `json:"schema_version"`
	Devices       map[string]string   `json:"devices"`
	Users         map[string]UserRisk `json:"users,omitempty"`
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
	o.mu.Lock()
	defer o.mu.Unlock()
	if p == nil {
		if o.loadErr != nil {
			return o.loadErr
		}
		o.persister = nil
		return nil
	}
	data, err := p.Load()
	if err != nil {
		o.loadErr = ErrRiskLoad
		return o.loadErr
	}
	// Persisters reserve nil for first boot; existing zero-byte files are invalid.
	if data == nil {
		if o.loadErr != nil {
			return o.loadErr
		}
		o.persister = p
		return nil
	}
	f, err := decodeRiskSnapshot(data)
	if err != nil {
		o.loadErr = err
		return err
	}
	legacy := f.SchemaVersion == "high_risk_overlay_state.v1" && len(f.Devices) > 0
	if !maps.Equal(o.devices, f.Devices) || !reflect.DeepEqual(o.users, f.Users) || o.legacy != legacy {
		o.generation.Add(1)
	}
	o.devices, o.users, o.legacy = f.Devices, f.Users, legacy
	o.persister, o.loadErr = p, nil
	o.rebuildUserIndexLocked()
	log.Printf("high_risk_overlay load: restored %d device and %d user risk marks", len(o.devices), len(o.users))
	return nil
}

// ErrRiskLoad deliberately omits paths, backend details and saved contents.
var ErrRiskLoad = errors.New("cannot read risk snapshot")

// saveStateLocked also serves checked user writes and legacy migration. A nil
// persister means volatile operation and is reported as a warning to user writes.
func (o *HighRiskOverlay) saveStateLocked(devices map[string]string, users map[string]UserRisk) (bool, error) {
	if o.persister == nil {
		return true, nil
	}
	data, err := json.Marshal(highRiskOverlayStateFile{SchemaVersion: highRiskOverlayStateSchemaVersion, Devices: devices, Users: users})
	if err != nil {
		log.Printf("risk state encode: %v", err)
		return false, ErrRiskSave
	}
	if err = o.persister.Save(data); err != nil {
		log.Printf("risk state save: %v", err)
		// The legacy compatibility warning also matches an unconfirmed flush.
		// Only a completed, synced in-place save may publish checked changes.
		if errors.Is(err, blobstore.ErrSavedWithoutAtomicity) && !errors.Is(err, blobstore.ErrDurabilityUnconfirmed) {
			return true, nil
		}
		return false, ErrRiskSave
	}
	return false, nil
}
