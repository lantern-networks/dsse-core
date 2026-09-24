package revocation

import (
	"context"
	"encoding/json"
	"maps"
	"strings"
)

// RemoveDevicesContext erases only origin-owned blocks in the latest shared
// row. Received mesh and pulled revocations retain their independent authority.
func (a *AdmissionRevocations) RemoveDevicesContext(ctx context.Context, ids []string) (int, error) {
	if a == nil || len(ids) == 0 {
		return 0, nil
	}
	a.writeMu.Lock()
	p, shared := a.persister.(contextUpdater)
	if !shared {
		a.writeMu.Unlock()
		return a.RemoveDevicesChecked(ids)
	}
	defer a.writeMu.Unlock()
	var candidate admissionRevocationsStateFile
	n := 0
	err := p.UpdateContext(ctx, func(raw []byte) ([]byte, error) {
		n = 0
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
		for _, id := range ids {
			id = normalizeIdentity(id)
			if _, ok := candidate.Revoked[id]; ok {
				delete(candidate.Revoked, id)
				n++
			}
		}
		return json.Marshal(candidate)
	})
	if err != nil {
		return 0, ErrAdmissionSave
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !maps.Equal(a.revoked, candidate.Revoked) || !maps.Equal(a.meshReceived, candidate.MeshReceived) {
		a.generation.Add(1)
	}
	a.revoked, a.meshReceived = candidate.Revoked, candidate.MeshReceived
	return n, nil
}

// RemoveTenantRisksContext preserves other tenants and devices from the latest
// row. Device ownership is supplied by the enclosing erasure operation.
func (o *HighRiskOverlay) RemoveTenantRisksContext(ctx context.Context, tenant string, ids []string) (int, error) {
	tenant = strings.TrimSpace(tenant)
	if o == nil || (tenant == "" && len(ids) == 0) {
		return 0, nil
	}
	n := 0
	shared, err := o.changeRiskContext(ctx, func(f *highRiskOverlayStateFile) {
		n = 0
		for _, id := range ids {
			id = NormalizeDeviceID(id)
			if _, ok := f.Devices[id]; ok {
				delete(f.Devices, id)
				n++
			}
		}
		if tenant != "" {
			for k, m := range f.Users {
				if m.TenantID == tenant {
					delete(f.Users, k)
					n++
				}
			}
		}
	})
	if !shared {
		return o.RemoveTenantRisksChecked(tenant, ids)
	}
	if err != nil {
		return 0, err
	}
	return n, nil
}
