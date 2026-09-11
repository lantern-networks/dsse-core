package agenttuning

import "strings"

// resolve.go — server-side (Control Plane) resolution of the per-device effective tuning policy. It
// generalizes the SteerExclusionPolicy union model to captive tuning: an admin authors tuning at three
// scopes — tenant, device_group, device — and the CP overlays them for a connecting device (tenant is the
// base, its group overrides, the device itself overrides last = most specific wins). The CP then signs the
// result (agentpolicy) and serves it; the agent applies it.
//
// Pure + platform-neutral so the overlay/precedence is unit-tested; the signing + device-identity/group lookup
// + HTTP endpoint are the CP wiring on top.

// Scope types for an authored tuning policy.
const (
	ScopeTenant      = "tenant"
	ScopeDeviceGroup = "device_group"
	ScopeDevice      = "device"
)

// ScopedTuning is one authored tuning policy at a scope. ScopeID is the device-group id or device identity
// (ignored for the tenant scope).
type ScopedTuning struct {
	ScopeType string         `json:"scope_type"`
	ScopeID   string         `json:"scope_id,omitempty"`
	Captive   *CaptiveTuning `json:"captive,omitempty"`
}

// Resolve computes the effective TuningPolicy for a device by overlaying the matching scoped policies in
// precedence order tenant → device_group(group) → device(device): the most specific scope wins per field. The
// result carries the CP-authoritative tenant/group and is ready to sign + serve. Fields no scope sets stay unset
// (the agent then keeps its current value for them).
func Resolve(tenant, group, device string, scoped []ScopedTuning) TuningPolicy {
	out := TuningPolicy{Kind: TuningKind, TenantID: tenant, DeviceGroup: group}
	order := []struct{ typ, id string }{
		{ScopeTenant, ""},
		{ScopeDeviceGroup, group},
		{ScopeDevice, device},
	}
	for _, lvl := range order {
		if lvl.typ != ScopeTenant && strings.TrimSpace(lvl.id) == "" {
			continue // no group / no device id to match at this level
		}
		for _, s := range scoped {
			if !scopeMatches(s, lvl.typ, lvl.id) || s.Captive == nil {
				continue
			}
			out.Captive = overlayCaptive(out.Captive, s.Captive)
		}
	}
	return out
}

func scopeMatches(s ScopedTuning, typ, id string) bool {
	if !strings.EqualFold(strings.TrimSpace(s.ScopeType), typ) {
		return false
	}
	if typ == ScopeTenant {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(s.ScopeID), strings.TrimSpace(id))
}

// overlayCaptive returns base with the non-zero/non-empty fields of over applied on top (per-field override).
func overlayCaptive(base, over *CaptiveTuning) *CaptiveTuning {
	if over == nil {
		return base
	}
	out := CaptiveTuning{}
	if base != nil {
		out = *base
	}
	if over.TimeoutSec > 0 {
		out.TimeoutSec = over.TimeoutSec
	}
	if over.ProbeIntervalSec > 0 {
		out.ProbeIntervalSec = over.ProbeIntervalSec
	}
	if len(cleanHosts(over.DetectHosts)) > 0 {
		out.DetectHosts = cleanHosts(over.DetectHosts)
	}
	return &out
}
