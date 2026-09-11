package agentpolicy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// region_endpoints.go — the client half of client-side region failover (docs/multi_region_client_region_failover_design.md).
// The Edge SIGNS each device's residency-filtered, home-anchored allowed-region endpoint list with the SAME
// Ed25519 agent-policy signer it uses for steer exclusions; the endpoint agent (macOS NE / Windows WFP) fetches it
// over the (T) mTLS transport and VERIFIES it against the SAME pinned public key. Sharing the signer/key means an
// agent that already pins the agent-policy key gets region endpoints for free — no second trust anchor.
//
// The signed ENVELOPE is identical (Type == EnvelopeType); only the PAYLOAD schema differs
// (RegionEndpointsSchema), so verification reuses Verify() and we discriminate on the payload schema_version.

// RegionEndpointsSchema is the payload schema marker the Edge stamps on a signed region-endpoints body
// (GET /steer/region-endpoints). Distinct from the steer-exclusion payload so a mis-routed body is rejected.
const RegionEndpointsSchema = "dsse.region-endpoints.v1"

const regionEndpointsPath = "/steer/region-endpoints"

// RegionEndpoint is one allowed region's transport endpoint, as served in the signed list. It maps 1:1 onto the
// regionfailover engine's RegionEndpoint; the agent converts it before handing the list to the selector.
type RegionEndpoint struct {
	Region   string `json:"region"`
	Endpoint string `json:"endpoint"`
}

// RegionEndpointsPayload is the verified region-endpoints body. AllowedRegionEndpoints is ALREADY
// residency-filtered + home-anchored server-side (the engine enforces residency by construction by only ever
// seeing this list); HomeRegion is the tiebreak/preferred anchor.
type RegionEndpointsPayload struct {
	SchemaVersion          string           `json:"schema_version"`
	TenantID               string           `json:"tenant_id"`
	DeviceIdentity         string           `json:"device_identity"`
	HomeRegion             string           `json:"home_region"`
	AllowedRegionEndpoints []RegionEndpoint `json:"allowed_region_endpoints"`

	// The names this organization's agents present, FLEET-WIDE. They are carried here rather than per endpoint
	// because the deployment guarantees one answer everywhere: a node that cannot keep what the fleet announces
	// refuses to join it, so failing over never changes which name to send.
	//
	// ★ THIS IS WHAT LETS A FAILED-OVER DEVICE STOP GUESSING. Until these existed the list carried addresses
	// only, so an agent that failed over had nothing to present but the region's own host name, and a region
	// serving the organization's certificate would be verified against the wrong name. The agent's rule for
	// that was "under failover the announced name is NOT sent", which is safe and also means a failed-over
	// device cannot reach any route selected by organization SNI. A name in the signed list replaces the rule
	// with a fact.
	//
	// Absent on every list issued before they existed, and absent MUST keep the old rule — see the Windows
	// agent's activeServerName. An agent that read "no name" as "send the organization name anyway" would
	// lock itself out of exactly the region it just failed over to.
	TransportServerName       string `json:"transport_server_name,omitempty"`
	EnrolmentServerName       string `json:"enrolment_server_name,omitempty"`
	RenewalRecoveryServerName string `json:"renewal_recovery_server_name,omitempty"`
}

// FetchVerifiedRegionEndpoints fetches the signed allowed-region endpoint list over the provided client (wire it
// to the (T) mTLS transport so the Edge serves this device its residency-filtered set), verifies the envelope
// against the PINNED public key, and returns the verified payload. Fail-closed: any verify/schema mismatch is an
// error and never returns a list — a caller must keep its previous list (never widen the boundary on a bad fetch).
func FetchVerifiedRegionEndpoints(ctx context.Context, client *http.Client, baseURL, pinnedPubKeyHex string) (RegionEndpointsPayload, error) {
	return FetchVerifiedRegionEndpointsWithKeys(ctx, client, baseURL, []string{pinnedPubKeyHex})
}

// FetchVerifiedRegionEndpointsWithKeys is the same fetch against the SET of signing keys this device honours,
// so a signing-key rotation cannot strand a device on a stale region list.
func FetchVerifiedRegionEndpointsWithKeys(ctx context.Context, client *http.Client, baseURL string, pubKeyHexes []string) (RegionEndpointsPayload, error) {
	if len(pubKeyHexes) == 0 {
		return RegionEndpointsPayload{}, fmt.Errorf("a pinned public key is required (provision it first)")
	}
	var env Envelope
	if err := getJSON(ctx, client, strings.TrimRight(baseURL, "/")+regionEndpointsPath, &env); err != nil {
		return RegionEndpointsPayload{}, err
	}
	payloadBytes, err := VerifyAny(env, pubKeyHexes)
	if err != nil {
		return RegionEndpointsPayload{}, fmt.Errorf("verify region endpoints: %w", err)
	}
	var p RegionEndpointsPayload
	if err := json.Unmarshal(payloadBytes, &p); err != nil {
		return RegionEndpointsPayload{}, fmt.Errorf("parse verified region-endpoints payload: %w", err)
	}
	if p.SchemaVersion != RegionEndpointsSchema {
		return RegionEndpointsPayload{}, fmt.Errorf("unexpected region-endpoints schema_version %q (want %q)", p.SchemaVersion, RegionEndpointsSchema)
	}
	return p, nil
}
