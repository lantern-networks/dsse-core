package revocation

import (
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/lantern-networks/dsse-core/blobstore"
)

// HighRiskOverlay holds separate device and tenant-scoped user risk sets on the same fast
// feed as admission revocations (revocation-class: a device marked high-risk on the control plane must be
// treated high-risk by EVERY node's decision path, so risk-based deny/re-auth is fleet-consistent and the
// device can't reconnect elsewhere to dodge it). Unlike admission revocations there is no node-local/auto
// layer — high-risk is admin-marked (CP-authoritative). Both sets are authoritative on
// the CP and synced on pullers. Persistence keeps marks across a CP restart.
type HighRiskOverlay struct {
	// writeMu serializes every writer, including persistence and pulled snapshots.
	// Lock order is writeMu then mu. Readers take only mu; storage I/O and legacy
	// attribution never hold mu. Published maps are replaced, not edited in place.
	writeMu    sync.Mutex
	mu         sync.RWMutex
	devices    map[string]string // deviceID (normalized) -> severity (high|critical)
	users      map[string]UserRisk
	userIndex  map[string]string
	loadErr    error
	legacy     bool
	persister  blobstore.Persister
	generation atomic.Uint64
}

func NewHighRiskOverlay() *HighRiskOverlay {
	return &HighRiskOverlay{devices: map[string]string{}, users: map[string]UserRisk{}, userIndex: map[string]string{}}
}

// NormalizeDeviceID trims but PRESERVES case — device ids are opaque, case-sensitive identifiers and must
// match the east-west grant store (g.DeviceID) byte-for-byte so the grant-drop on a synced high-risk device
// (slice 3d) hits. (Unlike transport cert identities, which are lowercased.)
func NormalizeDeviceID(id string) string { return strings.TrimSpace(id) }

func (o *HighRiskOverlay) ConfigGeneration() uint64 {
	if o == nil {
		return 0
	}
	return o.generation.Load()
}

// Mark is the legacy automatic-signal path. Escalations remain visible before
// saving, as existing DLP callers expect. De-escalations require a successful
// save. Administrative callers must use SetDeviceRisk to receive save outcomes.
func (o *HighRiskOverlay) Mark(deviceID, severity string) {
	_, _ = o.setDeviceRisk(deviceID, severity, true)
}

// Clear is the compatibility wrapper; an unconfirmed clear preserves the live mark.
func (o *HighRiskOverlay) Clear(deviceID string) {
	_, _ = o.SetDeviceRisk(deviceID, "none")
}

// IsHighRisk reports whether a device is currently marked high-risk, with its severity.
func (o *HighRiskOverlay) IsHighRisk(deviceID string) (string, bool) {
	if o == nil {
		return "", false
	}
	id := NormalizeDeviceID(deviceID)
	o.mu.RLock()
	defer o.mu.RUnlock()
	sev, ok := o.devices[id]
	return sev, ok
}

// Snapshot returns a copy of the high-risk set (the control plane ships this in the shared feed).
func (o *HighRiskOverlay) Snapshot() map[string]string {
	out := map[string]string{}
	if o == nil {
		return out
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	for k, v := range o.devices {
		out[k] = v
	}
	return out
}

// ReplaceSynced atomically replaces the high-risk set from the control-plane feed (puller side).
func (o *HighRiskOverlay) ReplaceSynced(devices map[string]string) {
	if o == nil {
		return
	}
	fresh := make(map[string]string, len(devices))
	for k, v := range devices {
		if id := NormalizeDeviceID(k); id != "" {
			fresh[id] = strings.ToLower(strings.TrimSpace(v))
		}
	}
	o.writeMu.Lock()
	defer o.writeMu.Unlock()
	o.mu.Lock()
	defer o.mu.Unlock()
	o.devices = fresh
}

// List returns the sorted high-risk device ids (observability).
func (o *HighRiskOverlay) List() []string {
	if o == nil {
		return nil
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	out := make([]string, 0, len(o.devices))
	for id := range o.devices {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// CountDevices returns how many of the named devices this overlay currently marks. It takes the device ids
// rather than a tenant because the overlay is keyed by DEVICE, not by tenant: the caller resolves the
// attribution from the enrolled ledger, which is the only place that knows whose a device is.
func (o *HighRiskOverlay) CountDevices(deviceIDs []string) int {
	if o == nil || len(deviceIDs) == 0 {
		return 0
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	n := 0
	for _, id := range deviceIDs {
		if _, ok := o.devices[NormalizeDeviceID(id)]; ok {
			n++
		}
	}
	return n
}

// RemoveDevices is the compatibility wrapper. A failed save removes nothing from
// live state; callers that must distinguish failure from no matches use the checked form.
func (o *HighRiskOverlay) RemoveDevices(deviceIDs []string) int {
	n, _ := o.RemoveDevicesChecked(deviceIDs)
	return n
}
