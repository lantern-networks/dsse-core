package agentpolicy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Payload is the verified steer-policy body the Edge signs for one device. The endpoint agent applies
// ExcludedAppSigningIDs additively on top of its local loop-prevention infrastructure exclusions.
type Payload struct {
	SchemaVersion         string   `json:"schema_version"`
	TenantID              string   `json:"tenant_id"`
	DeviceIdentity        string   `json:"device_identity"`
	DeviceGroup           string   `json:"device_group"`
	ExcludedAppSigningIDs []string `json:"excluded_app_signing_ids"`
	// RenewCertificatesIssuedBefore, when set, means "any certificate issued before this instant is stale" — an
	// operator's declaration that a device should renew ahead of its ordinary two-thirds-of-life schedule (used
	// after the issuing CA is replaced, so a still-valid certificate under the old CA does not pin it in place
	// for years). It is a DECLARATION, not a command: the agent compares it against its certificate's notBefore,
	// so a device that renews past the cutoff stops matching without any server-side tracking. Absent in the
	// ordinary case, and an agent that never sees it behaves exactly as before. RFC3339. Rides the SAME signed
	// envelope as the exclusions, so reading it shares this verification — accepting it unsigned would let anyone
	// on the network make a fleet replace its credentials.
	RenewCertificatesIssuedBefore string `json:"renew_certificates_issued_before,omitempty"`
	// InterceptionRootSHA256 names the interception roots this device should look for in its own trust store.
	//
	// ★★★ THE EDGE SENT THIS AND THE SHARED TYPE DID NOT MODEL IT (2026-08-19, reported from win-dev-1). The
	// announcement was moved onto this per-minute document precisely because the trust bundle is gated behind a
	// monotonic serial — an agent only takes a new bundle when the serial advances, so a deployment that is not
	// rotating never sees a changed answer. The Edge duly wrote the key; the Windows agent parses this document
	// into this struct; the key had no field, so it landed nowhere and was dropped in silence.
	//
	// That box then answered the readiness question from the fifteen-day-old bundle it had adopted on
	// 2026-08-03 and reported wanted=1 found=1 for a root nothing had signed under for days. Two rounds of
	// investigation were spent on the Edge's side of a question the agent could not have answered differently.
	//
	// It is here, on the type both sides share, so the same list cannot be sent by one and invisible to the
	// other. A key that only one side models is a key that will be dropped by whichever side is not looking.
	InterceptionRootSHA256 []string `json:"interception_root_sha256,omitempty"`
}

// PubKey is the Edge's agent-policy signing public key advertised for pinning.
type PubKey struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

const (
	policyPath = "/steer/agent-policy"
	pubKeyPath = "/steer/agent-policy/pubkey"
)

// FetchPubKey retrieves the Edge's signing public key for pinning (provisioning step, TOFU in lab). The
// client must be wired to the (T) mTLS transport — the endpoint proves its device identity to be served.
func FetchPubKey(ctx context.Context, client *http.Client, baseURL string) (PubKey, error) {
	var pk PubKey
	if err := getJSON(ctx, client, strings.TrimRight(baseURL, "/")+pubKeyPath, &pk); err != nil {
		return PubKey{}, err
	}
	if strings.TrimSpace(pk.PublicKey) == "" {
		return PubKey{}, fmt.Errorf("edge advertised an empty agent-policy public key")
	}
	return pk, nil
}

// FetchVerifiedExclusions fetches the signed agent-policy over the provided client (wire it to the (T)
// mTLS transport), verifies it against the PINNED public key, and returns the verified payload. The pin
// must be provisioned out-of-band (or via a one-time FetchPubKey at enrollment) — verifying against a
// key fetched in the same call would defeat tamper-resistance.
func FetchVerifiedExclusions(ctx context.Context, client *http.Client, baseURL, pinnedPubKeyHex string) (Payload, error) {
	return FetchVerifiedExclusionsWithKeys(ctx, client, baseURL, []string{pinnedPubKeyHex})
}

// FetchVerifiedExclusionsWithKeys is the same fetch, accepting the SET of signing keys this device honours —
// the provisioned pin plus any keys adopted from a signed trust bundle. That set is what makes the signing key
// rotatable: during the overlap either key verifies, so no device freezes on its last applied policy.
func FetchVerifiedExclusionsWithKeys(ctx context.Context, client *http.Client, baseURL string, pubKeyHexes []string) (Payload, error) {
	if len(pubKeyHexes) == 0 {
		return Payload{}, fmt.Errorf("a pinned public key is required (provision it first)")
	}
	var env Envelope
	if err := getJSON(ctx, client, strings.TrimRight(baseURL, "/")+policyPath, &env); err != nil {
		return Payload{}, err
	}
	payloadBytes, err := VerifyAny(env, pubKeyHexes)
	if err != nil {
		return Payload{}, fmt.Errorf("verify agent policy: %w", err)
	}
	var p Payload
	if err := json.Unmarshal(payloadBytes, &p); err != nil {
		return Payload{}, fmt.Errorf("parse verified policy payload: %w", err)
	}
	if p.SchemaVersion != EnvelopeType {
		return Payload{}, fmt.Errorf("unexpected policy schema_version %q", p.SchemaVersion)
	}
	return p, nil
}

func getJSON(ctx context.Context, client *http.Client, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d: %s", url, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return json.Unmarshal(body, out)
}

// MergeExclusions returns the loop-prevention infrastructure exclusions (always applied) plus the
// server-issued admin app exclusions, ADDITIVELY. The server set never replaces the local infra set —
// dropping it lets a co-located edge egress self-loop and breaks all egress (the live 502 lesson). Order
// is preserved (local infra first); case-insensitive duplicates are collapsed.
func MergeExclusions(localInfra, serverApp []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(localInfra)+len(serverApp))
	add := func(items []string) {
		for _, it := range items {
			t := strings.TrimSpace(it)
			if t == "" {
				continue
			}
			k := strings.ToLower(t)
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, t)
		}
	}
	add(localInfra)
	add(serverApp)
	return out
}
