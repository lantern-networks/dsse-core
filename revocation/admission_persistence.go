package revocation

import (
	"encoding/json"
	"errors"
	"log"
	"maps"
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

// SetStatePath loads a file snapshot using the same checked restoration as SetPersister.
func (a *AdmissionRevocations) SetStatePath(path string) error {
	if a == nil {
		return nil
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	return a.SetPersister(blobstore.FilePersister{Path: path})
}

// SetPersister restores a complete snapshot before adopting its writer. Callers
// must refuse startup on error; it is never safe to interpret that error as an
// empty revocation set. Failed restoration preserves the old writer and all live
// layers. Use at initialization or during explicit recovery, not as a mutation API.
func (a *AdmissionRevocations) SetPersister(p blobstore.Persister) error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if p == nil {
		a.persister = nil
		return nil
	}
	data, err := p.Load()
	if err != nil {
		return ErrAdmissionLoad
	}
	// The Persister contract reserves nil for a missing snapshot on first boot.
	// An existing zero-byte file is not a missing snapshot and must be rejected.
	if data == nil {
		a.persister = p
		return nil
	}
	f, err := decodeAdmissionSnapshot(data)
	if err != nil {
		return err
	}
	if !maps.Equal(a.revoked, f.Revoked) || !maps.Equal(a.meshReceived, f.MeshReceived) {
		a.generation.Add(1)
	}
	a.revoked, a.meshReceived = f.Revoked, f.MeshReceived
	a.persister = p
	log.Printf("admission_revocations load: restored %d revocation(s) + %d cross-region from the durable store", len(a.revoked), len(a.meshReceived))
	return nil
}

// ErrAdmissionLoad omits private paths, backend details and saved contents.
var ErrAdmissionLoad = errors.New("cannot read admission revocation snapshot")

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
