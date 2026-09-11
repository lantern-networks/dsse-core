package configversion

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Config versioning + rollback (V-1). Every admin-managed config
// change appends an immutable version (the full resource snapshot) on the control plane, so an admin can
// list history and roll back any resource to a prior version. Generic across resource types.

const (
	ResourceSteerExclusion    = "steer_exclusion"
	ResourceTenantRestriction = "tenant_restriction"
	ResourceEastWest          = "east_west"
	ResourceCertificate       = "certificate"
	ActionUpsert              = "upsert"
	ActionDelete              = "delete"
	ActionRollback            = "rollback"
)

// Version is one immutable snapshot in a resource's history.
type Version struct {
	ID           string          `json:"id"`
	TenantID     string          `json:"tenant_id"`
	ResourceType string          `json:"resource_type"`
	ResourceID   string          `json:"resource_id"`
	VersionNo    int64           `json:"version_no"`
	Payload      json.RawMessage `json:"payload"`
	Action       string          `json:"action"`
	Actor        string          `json:"actor"`
	Note         string          `json:"note"`
	CreatedAt    time.Time       `json:"created_at"`
}

// Store records an immutable history of admin-managed config so any resource can be rolled back. A nil store
// means versioning is disabled (the enforcing Edge does not version; only the CP does).
type Store interface {
	// Record appends the next version for (tenant, resourceType, resourceID) with the snapshot payload.
	Record(ctx context.Context, tenantID, resourceType, resourceID, action, actor, note string, payload any) (Version, error)
	// List returns the version history, newest first.
	List(ctx context.Context, tenantID, resourceType, resourceID string) ([]Version, error)
	// Get returns a specific version (ok=false when absent).
	Get(ctx context.Context, tenantID, resourceType, resourceID string, versionNo int64) (Version, bool, error)
}

// MemoryStore is an in-memory Store (tests + non-durable fallback). The postgres store is what the control
// plane deploys.
type MemoryStore struct {
	mu    sync.Mutex
	byKey map[string][]Version
	seq   int64
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{byKey: map[string][]Version{}}
}

func key(tenantID, resourceType, resourceID string) string {
	return tenantID + "\x00" + resourceType + "\x00" + resourceID
}

func (m *MemoryStore) Record(ctx context.Context, tenantID, resourceType, resourceID, action, actor, note string, payload any) (Version, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return Version{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	k := key(tenantID, resourceType, resourceID)
	m.seq++
	v := Version{
		ID: fmt.Sprintf("cv_mem_%d", m.seq), TenantID: tenantID, ResourceType: resourceType, ResourceID: resourceID,
		VersionNo: int64(len(m.byKey[k]) + 1), Payload: raw, Action: action, Actor: actor, Note: note, CreatedAt: time.Now().UTC(),
	}
	m.byKey[k] = append(m.byKey[k], v)
	return v, nil
}

func (m *MemoryStore) List(ctx context.Context, tenantID, resourceType, resourceID string) ([]Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	src := m.byKey[key(tenantID, resourceType, resourceID)]
	out := make([]Version, 0, len(src))
	for i := len(src) - 1; i >= 0; i-- { // newest first
		out = append(out, src[i])
	}
	return out, nil
}

func (m *MemoryStore) Get(ctx context.Context, tenantID, resourceType, resourceID string, versionNo int64) (Version, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, v := range m.byKey[key(tenantID, resourceType, resourceID)] {
		if v.VersionNo == versionNo {
			return v, true, nil
		}
	}
	return Version{}, false, nil
}
