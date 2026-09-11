package revocation

import (
	"encoding/json"
	"errors"
	"log"
	"strings"

	"github.com/lantern-networks/dsse-core/blobstore"
)

// Durable persistence for the high-risk device overlay (Phase 3). The control plane persists its set so a
// restart cannot silently CLEAR every high-risk marking (which would let risky devices be treated as clean
// fleet-wide on the next pull — a fail-open). Mirrors the admission-revocations store; a shared (Postgres)
// persister also carries it across a CP failover.

type highRiskOverlayStateFile struct {
	SchemaVersion string            `json:"schema_version"`
	Devices       map[string]string `json:"devices"`
}

const highRiskOverlayStateSchemaVersion = "high_risk_overlay_state.v1"

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
		log.Printf("high_risk_overlay load: cannot read store (starting empty): %v", err)
		return
	}
	if len(data) == 0 {
		return
	}
	var f highRiskOverlayStateFile
	if err := json.Unmarshal(data, &f); err != nil {
		log.Printf("high_risk_overlay load: ignoring unparseable store: %v", err)
		return
	}
	if f.Devices != nil {
		o.devices = f.Devices
	}
	log.Printf("high_risk_overlay load: restored %d high-risk device(s) from the durable store", len(o.devices))
}

func (o *HighRiskOverlay) persistLocked() {
	if o == nil || o.persister == nil {
		return
	}
	data, err := json.Marshal(highRiskOverlayStateFile{SchemaVersion: highRiskOverlayStateSchemaVersion, Devices: o.devices})
	if err != nil {
		log.Printf("high_risk_overlay persist: marshal failed: %v", err)
		return
	}
	if err := o.persister.Save(data); err != nil {
		// Saved-but-not-atomically is not a failure. Reporting it as one would tell an operator their
		// change was lost when it was written; saying nothing would hide that an interrupted write could
		// truncate it. Both are worth exactly one accurate sentence.
		if errors.Is(err, blobstore.ErrSavedWithoutAtomicity) {
			log.Printf("high_risk_overlay persist: saved, but NOT atomically — %v", err)
		} else {
			log.Printf("high_risk_overlay persist: save failed: %v", err)
		}
	}
}
