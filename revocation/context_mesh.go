package revocation

import (
	"context"
	"encoding/json"
	"maps"
	"strings"
)

// RevokeFromMeshCheckedContext acknowledges only a confirmed shared commit.
// An authorized edit with an unconfirmed commit retains its local block, but
// a refusal before the edit (including an expired leadership term) applies none.
func (a *AdmissionRevocations) RevokeFromMeshCheckedContext(ctx context.Context, identity, reason string) (bool, error) {
	return a.receiveMeshContext(ctx, identity, reason, true)
}
func (a *AdmissionRevocations) receiveMeshContext(ctx context.Context, identity, reason string, retry bool) (bool, error) {
	if a == nil {
		return false, ErrAdmissionSave
	}
	id := normalizeIdentity(identity)
	if id == "" {
		return false, nil
	}
	reason = strings.TrimSpace(reason)
	a.writeMu.Lock()
	p, shared := a.persister.(contextUpdater)
	if !shared {
		a.writeMu.Unlock()
		return a.revokeFromMesh(identity, reason, retry)
	}
	var candidate admissionRevocationsStateFile
	edited := false
	initial := false
	err := p.UpdateContext(ctx, func(raw []byte) ([]byte, error) {
		candidate = admissionRevocationsStateFile{SchemaVersion: admissionRevocationsStateSchemaVersion, Revoked: map[string]string{}, MeshReceived: map[string]string{}}
		if raw != nil {
			var err error
			candidate, err = decodeAdmissionSnapshot(raw)
			if err != nil {
				return nil, err
			}
		} else if a.generation.Load() != 0 && !a.meshInitialPending {
			return nil, ErrAdmissionLoad
		}
		// Received mesh blocks are monotonic; keep locally retained deliveries
		// whose earlier shared commit was unconfirmed. Origin blocks stay latest-row owned.
		for key, value := range a.meshReceived {
			if _, ok := candidate.MeshReceived[key]; !ok {
				candidate.MeshReceived[key] = value
			}
		}
		initial = raw == nil
		candidate.MeshReceived[id] = reason
		edited = true
		return json.Marshal(candidate)
	})
	if err != nil && edited && initial {
		a.meshInitialPending = true
	}
	a.mu.Lock()
	previous, exists := a.meshReceived[id]
	changed := edited && (!exists || previous != reason)
	if err == nil {
		a.meshInitialPending = false
		if !maps.Equal(a.revoked, candidate.Revoked) || !maps.Equal(a.meshReceived, candidate.MeshReceived) {
			a.generation.Add(1)
		}
		a.revoked, a.meshReceived = candidate.Revoked, candidate.MeshReceived
	} else if changed {
		a.meshReceived[id] = reason
		a.generation.Add(1)
	}
	onRevoked := a.onRevoked
	a.mu.Unlock()
	a.writeMu.Unlock()
	if changed && onRevoked != nil {
		onRevoked(id, reason)
	}
	if err != nil {
		return changed, ErrAdmissionSave
	}
	return changed, nil
}
