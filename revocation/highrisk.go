package revocation

import (
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/lantern-networks/dsse-core/blobstore"
)

// HighRiskOverlay holds separate device and tenant-scoped user risk marks, distributed on the same fast
// feed as admission revocations (revocation-class: a device marked high-risk on the control plane must be
// treated high-risk by EVERY node's decision path, so risk-based deny/re-auth is fleet-consistent and the
// device can't reconnect elsewhere to dodge it). Unlike admission revocations there is no node-local/auto
// layer — high-risk is admin-marked (CP-authoritative). Device and user namespaces are persisted together;
// each is authoritative on the CP and replaced from an explicitly typed feed on a puller.
type HighRiskOverlay struct {
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

// Mark records a device as high-risk (CP-authoritative). Only a state change bumps the generation + persists.
func (o *HighRiskOverlay) Mark(deviceID, severity string) {
	id := NormalizeDeviceID(deviceID)
	if o == nil || id == "" {
		return
	}
	severity = strings.ToLower(strings.TrimSpace(severity))
	o.writeMu.Lock()
	defer o.writeMu.Unlock()
	o.mu.Lock()
	defer o.mu.Unlock()
	if prev, ok := o.devices[id]; ok && prev == severity {
		return
	}
	o.devices[id] = severity
	o.generation.Add(1)
	o.persistLocked()
}

// Clear removes a device from the high-risk set (de-escalation). Only a real removal bumps + persists.
func (o *HighRiskOverlay) Clear(deviceID string) {
	id := NormalizeDeviceID(deviceID)
	if o == nil {
		return
	}
	o.writeMu.Lock()
	defer o.writeMu.Unlock()
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, ok := o.devices[id]; !ok {
		return
	}
	delete(o.devices, id)
	o.generation.Add(1)
	o.persistLocked()
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

// RemoveDevices clears the marks on the named devices, returning how many were removed.
//
// ★ ORDER MATTERS AND IT IS THE CALLER'S TO GET RIGHT (2026-08-18). The ids come from the enrolled ledger, and
// a tenant erasure removes that ledger's entries — so the ids must be captured BEFORE the ledger is cleared or
// this receives an empty list and silently removes nothing, which is indistinguishable from "there were none".
func (o *HighRiskOverlay) RemoveDevices(deviceIDs []string) int {
	if o == nil || len(deviceIDs) == 0 {
		return 0
	}
	o.writeMu.Lock()
	defer o.writeMu.Unlock()
	o.mu.Lock()
	defer o.mu.Unlock()
	n := 0
	for _, id := range deviceIDs {
		key := NormalizeDeviceID(id)
		if _, ok := o.devices[key]; ok {
			delete(o.devices, key)
			n++
		}
	}
	if n > 0 {
		o.generation.Add(1)
		o.persistLocked()
	}
	return n
}
