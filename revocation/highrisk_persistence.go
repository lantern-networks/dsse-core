package revocation

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
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

// SetStatePath enables durable file persistence at path (historical behaviour). A back-compat convenience over
// SetPersister(blobstore.FilePersister{...}).
func (o *HighRiskOverlay) SetStatePath(path string) {
	if o == nil {
		return
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}
	o.SetPersister(blobstore.FilePersister{Path: path})
}

// SetPersister enables durable persistence via any Persister (file or shared Postgres) and loads existing state.
func (o *HighRiskOverlay) SetPersister(p blobstore.Persister) {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.persister = p
	if p == nil {
		return
	}
	o.loadLocked()
}

func (o *HighRiskOverlay) loadLocked() {
	if o.persister == nil {
		return
	}
	data, err := o.persister.Load()
	if err != nil {
		o.loadErr = fmt.Errorf("read risk state: %w", err)
		log.Printf("high_risk_overlay load: %v", o.loadErr)
		return
	}
	if len(data) == 0 {
		return
	}
	var f highRiskOverlayStateFile
	if err := json.Unmarshal(data, &f); err != nil {
		o.loadErr = fmt.Errorf("decode risk state: %w", err)
		log.Printf("high_risk_overlay load: %v", o.loadErr)
		return
	}
	if f.SchemaVersion != highRiskOverlayStateSchemaVersion && f.SchemaVersion != "high_risk_overlay_state.v1" {
		o.loadErr = fmt.Errorf("unsupported risk state version")
		return
	}
	users := make(map[string]UserRisk, len(f.Users))
	for key, mark := range f.Users {
		normalized, err := normalizeUserRisk(mark)
		if err != nil || riskRank(normalized.Severity) == 0 || key != userRiskKey(normalized.TenantID, normalized.ID) {
			o.loadErr = fmt.Errorf("invalid saved user risk")
			return
		}
		users[key] = normalized
	}
	devices := make(map[string]string, len(f.Devices))
	for id, severity := range f.Devices {
		if id == "" || id != NormalizeDeviceID(id) || riskRank(severity) == 0 {
			o.loadErr = fmt.Errorf("invalid saved device risk")
			return
		}
		devices[id] = severity
	}
	if f.SchemaVersion == "high_risk_overlay_state.v1" && len(users) > 0 {
		o.loadErr = fmt.Errorf("typed users in legacy risk state")
		return
	}
	o.users, o.devices = users, devices
	o.loadErr = nil
	o.rebuildUserIndexLocked()
	o.legacy = f.SchemaVersion == "high_risk_overlay_state.v1" && len(devices) > 0
	log.Printf("high_risk_overlay load: restored %d high-risk device(s) from the durable store", len(o.devices))
}

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
func (o *HighRiskOverlay) persistLocked() { _, _ = o.saveStateLocked(o.devices, o.users) }
