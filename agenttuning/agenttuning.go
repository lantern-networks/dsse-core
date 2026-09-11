// Package agenttuning is the L3 live signed "tuning policy" the Control Plane distributes per device-group —
// "tenant-configurable captive via signed policy". It rides the SAME Ed25519 envelope (agentpolicy) as the
// steer-exclusion policy — one trust mechanism — and carries operational tuning the CP can change centrally
// WITHOUT a reinstall: captive window timing, detection hosts, and (later) posture requirements. The agent
// VERIFIES the signature + kind, then applies the values (clamped to safe bounds).
//
// This is distinct from the L1 install profile (installprofile): L1 is the install-time seed; L3 is the live
// refresh. A tampered/unsigned/wrong-kind bundle is REJECTED and the agent keeps its current (safe) values.
// Pure, platform-neutral Go — unit-tested on any OS.
package agenttuning

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lantern-networks/dsse-core/agentpolicy"
)

// TuningKind is the payload type discriminator (checked after signature verification so a validly-signed
// envelope of another kind — e.g. an install profile or an exclusion policy — is not mistaken for tuning).
const TuningKind = "dsse_agent_tuning_policy.v1"

const (
	captiveTimeoutMin = 30
	captiveTimeoutMax = 3600
	captiveProbeMin   = 1
	captiveProbeMax   = 60
)

// TuningPolicy is the signed payload. Scope (tenant + optional device_group) lets the CP resolve/serve the
// right bundle per device — the CP owns that assignment; the agent applies whatever the CP resolved for it.
type TuningPolicy struct {
	Kind        string         `json:"kind"`
	TenantID    string         `json:"tenant_id"`
	DeviceGroup string         `json:"device_group,omitempty"`
	Captive     *CaptiveTuning `json:"captive,omitempty"`
}

// CaptiveTuning is the live-tunable subset of the captive bootstrap (the feature itself is always ON — only
// timing/hosts are tunable, never an on/off kill switch).
type CaptiveTuning struct {
	TimeoutSec       int      `json:"timeout_sec,omitempty"`
	ProbeIntervalSec int      `json:"probe_interval_sec,omitempty"`
	DetectHosts      []string `json:"detect_hosts,omitempty"`
}

// CaptiveSettings is the effective captive configuration the agent runs with.
type CaptiveSettings struct {
	TimeoutSec       int
	ProbeIntervalSec int
	DetectHosts      []string
}

// ApplyCaptive overlays the signed tuning (if any) onto the current settings, clamping to safe bounds. Fields
// the policy omits keep their current value — so a partial policy tunes only what it sets. The captive feature
// is never disabled here (no kill switch in the schema).
func (p TuningPolicy) ApplyCaptive(cur CaptiveSettings) CaptiveSettings {
	out := cur
	if p.Captive == nil {
		return out
	}
	if v := p.Captive.TimeoutSec; v > 0 {
		out.TimeoutSec = clamp(v, captiveTimeoutMin, captiveTimeoutMax)
	}
	if v := p.Captive.ProbeIntervalSec; v > 0 {
		out.ProbeIntervalSec = clamp(v, captiveProbeMin, captiveProbeMax)
	}
	if hosts := cleanHosts(p.Captive.DetectHosts); len(hosts) > 0 {
		out.DetectHosts = hosts
	}
	return out
}

// Load parses a signed Envelope, verifies it against the pinned key, checks the kind, and returns the tuning
// policy. On ANY failure it returns (zero policy, verified=false, err): the caller keeps its current settings
// (ApplyCaptive on the zero policy is a no-op), so a bad bundle never changes tuning.
func Load(envelopeJSON []byte, pinnedPubKeyHex string) (policy TuningPolicy, verified bool, err error) {
	return LoadWithKeys(envelopeJSON, []string{pinnedPubKeyHex})
}

// LoadWithKeys is Load against a SET of accepted signing keys — the provisioned pin plus anything the device
// adopted from a signed trust bundle. Every other signed-policy path (exclusions, posture, region endpoints,
// the trust bundle itself) already verifies this way; tuning did not, and that is not a cosmetic difference.
// It made this the one path that cannot survive a signing-key rotation: when the Edge moved policy signing to
// the HSM's ECDSA key while devices still pinned the Ed25519 one, exclusions kept working through the adopted
// set and tuning failed every minute with "signature is ECDSA-P256 but the pinned key is not" until the pin
// itself was changed. A rotation mechanism that one consumer opts out of is a rotation that half-works.
func LoadWithKeys(envelopeJSON []byte, pubKeyHexes []string) (policy TuningPolicy, verified bool, err error) {
	var env agentpolicy.Envelope
	if e := json.Unmarshal(envelopeJSON, &env); e != nil {
		return TuningPolicy{}, false, fmt.Errorf("agenttuning: parse envelope: %w", e)
	}
	// VerifyAny reports "no usable signing key" for an empty/unusable set, which is the same refusal the old
	// explicit empty-pin check gave — kept there rather than duplicated here so there is one rule.
	payload, e := agentpolicy.VerifyAny(env, pubKeyHexes)
	if e != nil {
		return TuningPolicy{}, false, fmt.Errorf("agenttuning: verify: %w", e)
	}
	var p TuningPolicy
	if e := json.Unmarshal(payload, &p); e != nil {
		return TuningPolicy{}, false, fmt.Errorf("agenttuning: parse policy: %w", e)
	}
	if p.Kind != TuningKind {
		return TuningPolicy{}, false, fmt.Errorf("agenttuning: wrong kind %q (want %q)", p.Kind, TuningKind)
	}
	return p, true, nil
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func cleanHosts(in []string) []string {
	var out []string
	for _, h := range in {
		if h = strings.TrimSpace(h); h != "" {
			out = append(out, h)
		}
	}
	return out
}
