package agentpolicy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// steering_posture.go — the client half of CP-controlled steering posture
// (docs/2026-07-24_cp_controlled_steering_posture_and_device_state.ja.md). The Edge SIGNS each device's
// steering posture (fail-open mode, region-failover, cooldown) with the SAME Ed25519 agent-policy signer it
// uses for steer exclusions and region endpoints; the endpoint agent fetches it over the (T) mTLS transport
// and VERIFIES it against the SAME pinned public key. This moves posture from agent STARTUP FLAGS to a
// CP-signed policy so an operator controls it centrally (and can change it without re-registering the agent),
// while the agent gains no new trust anchor.
//
// The signed ENVELOPE is identical (Type == EnvelopeType); only the PAYLOAD schema differs
// (SteeringPostureSchema), so verification reuses Verify() and we discriminate on the payload schema_version.

// SteeringPostureSchema is the payload schema marker the Edge stamps on a signed posture body
// (GET /steer/agent-policy/posture). Distinct from the exclusion + region-endpoints payloads so a mis-routed
// body is rejected.
const SteeringPostureSchema = "dsse.steering-posture.v1"

const steeringPosturePath = "/steer/agent-policy/posture"

const (
	// FailOpenOff is the fail-CLOSED absolute posture (production residency default): on a total Edge outage
	// the box stays DARK rather than egressing outside the boundary. Any unknown value is treated as this.
	FailOpenOff = "off"
	// FailOpenTerminal permits fail-open ONLY as the terminal fallback after all in-boundary Edges are
	// exhausted (PoC / early-release / stabilization). The trigger is region-exhaustion, never a single blip
	// (see Phase 4). fail-open must remain plugged into the auto-recovery monitor so it self-recovers.
	FailOpenTerminal = "terminal"
)

// SteeringPosturePayload is the verified steering-posture body the Edge signs for one device/group. It is the
// CP-authored replacement for the --fail-open / --region-failover / --fail-open-cooldown startup flags.
type SteeringPosturePayload struct {
	SchemaVersion      string `json:"schema_version"`
	TenantID           string `json:"tenant_id"`
	DeviceIdentity     string `json:"device_identity"`
	DeviceGroup        string `json:"device_group"`
	FailOpenMode       string `json:"fail_open_mode"`        // "off" (fail-CLOSED) | "terminal"
	FailOpenCooldownMS int    `json:"fail_open_cooldown_ms"` // 0 => agent default
	RegionFailover     bool   `json:"region_failover"`
	GeneratedAt        string `json:"generated_at"`
	// CaptureAddressFamilies is what the DEPLOYMENT says it can egress in — "ipv4", "ipv6". An agent captures
	// all outbound TCP, so without this it steers a family the deployment may have no leg for, and every one
	// of those flows is closed with no bytes after a wasted round trip (measured on a real endpoint,
	// 2026-08-25: 185 of 342 IPv6 flows carried nothing).
	//
	// ★ EMPTY MEANS UNCHANGED, NEVER "NONE". An older Edge, or one that has not finished measuring, sends
	// nothing here — and reading that as "capture nothing" would stop a fleet steering.
	CaptureAddressFamilies []string `json:"capture_address_families,omitempty"`
}

// FailOpenPermitted reports whether this posture allows fail-open at all. It is deliberately strict: only the
// exact "terminal" value permits it, so an empty/unknown/typo'd mode is fail-CLOSED (never accidentally widen
// the boundary from a malformed policy). This is the single interpretation point the agent must go through.
func (p SteeringPosturePayload) FailOpenPermitted() bool {
	return strings.EqualFold(strings.TrimSpace(p.FailOpenMode), FailOpenTerminal)
}

// FetchVerifiedSteeringPosture fetches the signed posture over the provided client (wire it to the (T) mTLS
// transport so the Edge serves this device its posture), verifies the envelope against the PINNED public key,
// and returns the verified payload. Fail-closed: any verify/schema mismatch is an error and never returns a
// posture — a caller must keep its previous (or the safe fail-CLOSED default), never widen on a bad fetch.
func FetchVerifiedSteeringPosture(ctx context.Context, client *http.Client, baseURL, pinnedPubKeyHex string) (SteeringPosturePayload, error) {
	return FetchVerifiedSteeringPostureWithKeys(ctx, client, baseURL, []string{pinnedPubKeyHex})
}

// FetchVerifiedSteeringPostureWithKeys is the same fetch against the SET of signing keys this device honours
// (provisioned pin plus any adopted from a signed trust bundle), so a signing-key rotation does not freeze the
// posture a device applies.
func FetchVerifiedSteeringPostureWithKeys(ctx context.Context, client *http.Client, baseURL string, pubKeyHexes []string) (SteeringPosturePayload, error) {
	if len(pubKeyHexes) == 0 {
		return SteeringPosturePayload{}, fmt.Errorf("a pinned public key is required (provision it first)")
	}
	var env Envelope
	if err := getJSON(ctx, client, strings.TrimRight(baseURL, "/")+steeringPosturePath, &env); err != nil {
		return SteeringPosturePayload{}, err
	}
	payloadBytes, err := VerifyAny(env, pubKeyHexes)
	if err != nil {
		return SteeringPosturePayload{}, fmt.Errorf("verify steering posture: %w", err)
	}
	var p SteeringPosturePayload
	if err := json.Unmarshal(payloadBytes, &p); err != nil {
		return SteeringPosturePayload{}, fmt.Errorf("parse verified steering-posture payload: %w", err)
	}
	if p.SchemaVersion != SteeringPostureSchema {
		return SteeringPosturePayload{}, fmt.Errorf("unexpected steering-posture schema_version %q (want %q)", p.SchemaVersion, SteeringPostureSchema)
	}
	return p, nil
}
