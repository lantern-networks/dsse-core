package assetcatalog

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// EnrolledDevice is a minimal descriptor of a device from the enrolled inventory, used to auto-populate the
// catalog so steered devices appear without manual entry. Identity is the stable, verified device identity.
type EnrolledDevice struct {
	Identity string // stable device identity (enrolled inventory / device cert) — becomes the read-only Identity
	Name     string // hostname / display name → default alias on first sync
	Platform string // "macos" | "windows"
}

// enrolledEndpointID derives a stable endpoint id from a device identity, so re-syncing the same device
// updates its endpoint rather than duplicating it.
func enrolledEndpointID(identity string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(identity))))
	return "enrolled-" + hex.EncodeToString(sum[:10])
}

// SyncEnrolledEndpoints upserts each enrolled device as a steered endpoint (source=enrolled). It is
// idempotent (keyed by a stable id from Identity): on re-sync it refreshes the device's platform/identity
// but KEEPS an operator-set alias and any group membership (membership lives on groups, not endpoints), so
// auto-population never clobbers admin edits. Returns the synced endpoints.
func (s *Store) SyncEnrolledEndpoints(tenantID string, devices []EnrolledDevice, now time.Time) []Endpoint {
	out := make([]Endpoint, 0, len(devices))
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return out
	}
	for _, d := range devices {
		identity := strings.TrimSpace(d.Identity)
		if identity == "" {
			continue
		}
		id := enrolledEndpointID(identity)
		alias := strings.TrimSpace(d.Name)
		if alias == "" {
			alias = identity
		}

		e, err := s.syncEnrolledEndpoint(Endpoint{
			ID:       id,
			TenantID: tenantID,
			Alias:    alias,
			Kind:     KindSteeredDevice,
			Platform: strings.TrimSpace(d.Platform),
			Steered:  true,
			Identity: identity,
			Source:   SourceEnrolled,
		})
		if err == nil {
			out = append(out, e)
		}
	}
	return out
}

// Inventory identity/platform and an operator alias are read and published under
// one lock so a concurrent list sync cannot overwrite a confirmed rename.
func (s *Store) syncEnrolledEndpoint(e Endpoint) (Endpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if current, ok := s.endpoints[e.TenantID][e.ID]; ok {
		e.Alias = current.Alias
	}
	if alias, ok := s.enrolledAliases[e.TenantID][e.ID]; ok {
		e.Alias = alias
	}
	return s.upsertEndpointLocked(e)
}
