package revocation

import (
	"encoding/json"
	"errors"
	"log"
	"strings"

	"github.com/lantern-networks/dsse-core/blobstore"
)

// Durable persistence for the node-local admission revocation set (Phase 3). Admin kill-switches (and W-2
// auto-revocations) were in-memory only — lost on a restart, which would SILENTLY UN-REVOKE every revoked
// device on the next pull (a fail-OPEN; the worst direction for a kill-switch). The control plane persists
// its `revoked` set to a durable store and restores it on boot, so a revocation survives a CP restart and stays
// authoritative in the distributed feed. With a shared (Postgres) persister it also survives a CP failover.

type admissionRevocationsStateFile struct {
	SchemaVersion string            `json:"schema_version"`
	Revoked       map[string]string `json:"revoked"`
	// MeshReceived persists the federation layer so a CP restart never silently un-revokes a device that was
	// revoked by a peer (a fail-OPEN). Omitted by older stores -> restored empty (fail-safe).
	MeshReceived map[string]string `json:"mesh_received,omitempty"`
}

const admissionRevocationsStateSchemaVersion = "admission_revocations_state.v1"

// SetStatePath enables durable file persistence at path (historical behaviour) and immediately loads existing
// state. Best-effort. A back-compat convenience over SetPersister(blobstore.FilePersister{...}).
func (a *AdmissionRevocations) SetStatePath(path string) {
	if a == nil {
		return
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}
	a.SetPersister(blobstore.FilePersister{Path: path})
}

// SetPersister enables durable persistence via any Persister (file or shared Postgres) and loads existing state.
func (a *AdmissionRevocations) SetPersister(p blobstore.Persister) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.persister = p
	if p == nil {
		return
	}
	a.loadLocked()
}

func (a *AdmissionRevocations) loadLocked() {
	if a.persister == nil {
		return
	}
	data, err := a.persister.Load()
	if err != nil {
		log.Printf("admission_revocations load: cannot read store (starting empty): %v", err)
		return
	}
	if len(data) == 0 {
		return
	}
	var f admissionRevocationsStateFile
	if err := json.Unmarshal(data, &f); err != nil {
		log.Printf("admission_revocations load: ignoring unparseable store: %v", err)
		return
	}
	if f.Revoked != nil {
		a.revoked = f.Revoked
	}
	if f.MeshReceived != nil {
		a.meshReceived = f.MeshReceived
	}
	log.Printf("admission_revocations load: restored %d revocation(s) + %d cross-region from the durable store", len(a.revoked), len(a.meshReceived))
}

// ErrAdmissionSave deliberately omits private storage details from callers' responses.
var ErrAdmissionSave = errors.New("admission revocation persistence was not confirmed")

// saveStateLocked saves a candidate while holding a.mu. A nil persister retains
// the explicit in-memory mode; it does not promise persistence across a restart.
func (a *AdmissionRevocations) saveStateLocked(revoked map[string]string) error {
	if a == nil || a.persister == nil {
		return nil
	}
	data, err := json.Marshal(admissionRevocationsStateFile{SchemaVersion: admissionRevocationsStateSchemaVersion, Revoked: revoked, MeshReceived: a.meshReceived})
	if err != nil {
		log.Printf("admission_revocations persist: marshal failed: %v", err)
		return ErrAdmissionSave
	}
	if err := a.persister.Save(data); err != nil {
		// A completed, synced in-place write is weaker but accepted. The legacy
		// warning also matches an unconfirmed flush; that is NOT confirmed saving.
		if errors.Is(err, blobstore.ErrSavedWithoutAtomicity) && !errors.Is(err, blobstore.ErrDurabilityUnconfirmed) {
			log.Printf("admission_revocations persist: saved, but NOT atomically — %v", err)
			return nil
		} else {
			log.Printf("admission_revocations persist: save failed: %v", err)
		}
		return ErrAdmissionSave
	}
	return nil
}

func (a *AdmissionRevocations) persistLocked() error { return a.saveStateLocked(a.revoked) }
