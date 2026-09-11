package agentpolicy

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// The trust bundle is the ONE document a device may fetch over a channel it cannot authenticate.
//
// Every other signed document here rides the (T) mTLS transport, which is correct — the device proves who it is
// and the Edge tailors the answer. But that makes them all useless in the one situation where a device is in
// trouble: its pinned transport CA no longer validates the Edge, so it cannot open the tunnel, and the new
// anchor it needs is only distributed over that tunnel. Cross-signing (transportca) is what should prevent that
// deadlock from forming; this is the last resort for when it forms anyway — an unplanned key revocation, a
// shutdown longer than the overlap, a rotation performed without the cross-certificate.
//
// It is safe to carry over an unauthenticated channel because its authenticity comes from the SIGNATURE, not
// the transport. The verification key is pinned in the device's own configuration and protected by code signing;
// a bundle that does not verify against it is discarded without being looked at.
//
// What it deliberately does NOT contain: anything that identifies or authorises a device. It answers only "which
// CA should I verify the Edge with, and where do I recover". Swapping it cannot make a device trust a different
// device, and cannot get one a certificate — that still requires the recovery path, which checks the expired
// certificate, the enrolment ledger and revocation. The worst a forged bundle could do is point a device at an
// Edge it then fails to authenticate.

// TrustBundleSchema marks a trust-bundle payload. Distinct from every other payload schema so a body signed for
// another purpose cannot be replayed as a trust bundle — the envelope type is shared, so the schema is what
// keeps the documents apart.
const TrustBundleSchema = "dsse.trust-bundle.v1"

// ErrTrustBundleNotNewer marks the ONE refusal that is an ordinary answer: the served bundle does not advance
// past what this device has already accepted, which is what a healthy device gets every time it looks and
// nothing has been published.
//
// It is a distinguishable error because the alternative is worse than it sounds. A caller that cannot tell
// "nothing new" from "could not reach it" or "would not verify" has to treat a broken distribution channel as
// silence — and silence is exactly what a healthy device produces. That is how a device stops receiving
// distributions for half a day with nobody able to see it from either end (2026-08-19, win-dev-1).
var ErrTrustBundleNotNewer = errors.New("trust bundle does not advance past the accepted serial")

const trustBundlePath = "/bootstrap/trust-bundle"

// normaliseFingerprints keeps the wire predictable: lower-case hex, no separators, no duplicates, and
// nothing that is not a SHA-256. An agent compares these against what it finds in a trust store, so a value
// that is not comparable is worse than an absent one.
// normalisePolicyKeys puts the signer's own key first and appends the others, deduplicated and sanitised.
// Hex Ed25519 public keys only (64 hex chars): anything else in this list would be a key a device is being
// told to accept signatures from, so a malformed entry is dropped rather than passed along.
func normalisePolicyKeys(own string, others []string) []string {
	out := []string{}
	seen := map[string]bool{}
	add := func(raw string) {
		k := strings.ToLower(strings.TrimSpace(raw))
		// Accept either signing-key shape the verifier does — Ed25519 or ECDSA-P256 — so an ECDSA next-key
		// (the token-held kind) can be published for adoption too, not just an Ed25519 one.
		if seen[k] || !isAcceptedPublicKeyHex(k) {
			return
		}
		seen[k] = true
		out = append(out, k)
	}
	add(own)
	for _, k := range others {
		add(k)
	}
	if len(out) <= 1 {
		// Only our own key: say nothing rather than publish a one-element set. An agent reading a set of one
		// would narrow its acceptance to that key, which is a rotation step disguised as a no-op.
		return nil
	}
	return out
}

func normaliseFingerprints(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, raw := range in {
		fp := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(raw), ":", ""))
		if len(fp) != 64 || seen[fp] {
			continue
		}
		ok := true
		for _, c := range fp {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				ok = false
				break
			}
		}
		if ok {
			seen[fp] = true
			out = append(out, fp)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// TrustBundlePayload is the verified body.
type TrustBundlePayload struct {
	SchemaVersion string `json:"schema_version"`
	TenantID      string `json:"tenant_id"`
	// Serial increases with every issue. A device records the highest it has accepted and refuses anything at or
	// below it, so a captured older bundle cannot be replayed to walk a device back onto a withdrawn CA.
	Serial int64 `json:"serial"`
	// IssuedAt is informational for operators; it is NOT what rollback protection rests on. A clock on a machine
	// that has been switched off for a year is not evidence.
	IssuedAt string `json:"issued_at"`
	// TransportCAPEM holds every CA the device should accept the Edge under — a LIST, because an overlap is the
	// normal state during a rotation.
	TransportCAPEM string `json:"transport_ca_pem"`
	// RenewalRecoveryEndpoint may name only a port; the device resolves the host from the transport it already
	// has. Optional.
	RenewalRecoveryEndpoint string `json:"renewal_recovery_endpoint,omitempty"`
	// RenewalRecoverySNI is the name an agent sends when it dials the Edge to renew a certificate that has
	// ALREADY EXPIRED — the path that cannot present a valid client certificate by definition.
	//
	// ★★★ THE FIRST STEP OF FOLDING THE AGENT PLANE ONTO ONE PORT. That path is
	// a separate listener today (:18545) because it needs RequireAnyClientCert, and the main transport must
	// never be relaxed that way — a verification hole there is either "unverified certificates accepted" or
	// "every device locked out". Selecting it by SNI on the SAME port keeps the main configuration untouched
	// while removing the second address, which cannot exist on a real deployment where both would be 443.
	//
	// This field is the ANNOUNCEMENT half and lands first, deliberately: nothing about the listeners changes
	// while it is empty or ignored, agents can adopt it at their own pace on three platforms, and the port is
	// only retired once every enrolled device has been MEASURED onto a bundle that carries it — with silence
	// counted as "not yet", because a device that is switched off is the one this path exists for.
	//
	// ★★★ IT IS A SELECTOR, NOT THE NAME THE CERTIFICATE IS VERIFIED UNDER — unless the server says otherwise
	// by putting it in the certificate. Measured on a live deployment 2026-08-19: a handshake for this name was
	// answered with the ordinary transport certificate, whose names are the host's, so a client that verified
	// against the name it sent refused the server. Both agents send this name and verify under the transport
	// name they already had.
	//
	// ★ AND AN EMPTY VALUE MEANS "NOT OFFERED", NOT "NO SUCH THING". A server that cannot yet serve a
	// certificate carrying the name withdraws it and keeps the dedicated recovery endpoint working; an agent
	// that reads empty must fall back to RenewalRecoveryEndpoint rather than conclude recovery is gone. The
	// devices that read this field are, by definition, the ones whose own certificate has already expired.
	RenewalRecoverySNI string `json:"renewal_recovery_sni,omitempty"`
	// TransportServerName is the name this organization's agents should SEND as the SNI when they dial the
	// Edge, and verify the presented certificate against.
	//
	// ★★★ ROADMAP D, S3 (2026-08-19). Every organization's devices verify this Edge with one shared anchor
	// today, so whoever holds it can impersonate the Edge to any of them. The way out is a certificate per
	// organization, and the only signal that can select one is the SNI: the server must choose before the
	// client certificate arrives. No DNS is needed — an agent dials the address it already has and sends this
	// name — and the name is ANNOUNCED rather than configured on the device, so it is derived from the
	// certificate the Edge actually serves and cannot drift from it.
	//
	// Empty means what it has always meant: this organization is served the deployment's shared certificate,
	// and an agent that never sees this field behaves exactly as before. An agent must NOT invent one.
	TransportServerName string `json:"transport_server_name,omitempty"`
	// InterceptionRootSHA256 are the interception roots this deployment signs under — the ones an endpoint
	// must have in its system trust store for HTTPS inspection to work at all. Advertised so an agent can
	// LOOK for them and report which it found: nothing tells the Edge today which interception root a device
	// trusts, so switching that root would be blind, and a blind switch breaks every site at once on any
	// machine that missed the distribution. Fingerprints only — the certificates themselves are distributed
	// out of band (MDM), and a device that would accept a root because a bundle carried it would be trusting
	// the wrong thing.
	//
	// A LIST for the same reason TransportCAPEM is: an overlap is the normal state during a rotation.
	InterceptionRootSHA256 []string `json:"interception_root_sha256,omitempty"`
	// AgentPolicyPublicKeys are the signing keys a device should accept on signed policy — hex Ed25519 public
	// keys, the CURRENT one first.
	//
	// Every agent pins exactly one key today, which makes the signing key the one piece of material that
	// cannot be rotated at all: change it and every device rejects everything signed by the new one, and
	// since policy is fail-safe they freeze on their last applied set with no way to be told anything new.
	// That is also why the key cannot move into a hardware token — the token's key is a different key.
	//
	// A LIST, distributed the same way the transport CAs are, makes the ordinary overlap possible: publish
	// the next key, wait until every device holds it, start signing with it, then withdraw the old. The
	// bundle is signed by the key in force at the time, so an agent that adopts this set has verified its
	// provenance before trusting it. Empty = say nothing, and a device keeps using the key it was
	// provisioned with (exactly today's behaviour).
	AgentPolicyPublicKeys []string `json:"agent_policy_public_keys,omitempty"`
}

// Anchors parses the bundle's CAs. Fail-closed: a bundle whose PEM yields no usable CA is an error rather than
// an empty anchor set, because an empty set would be indistinguishable from "trust nothing" at the call site and
// could be mistaken for a reason to fall back.
func (p TrustBundlePayload) Anchors() ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := []byte(p.TransportCAPEM)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("trust bundle contains an unparseable certificate: %w", err)
		}
		if !cert.IsCA {
			return nil, fmt.Errorf("trust bundle contains a non-CA certificate (%q); anchors must be CAs",
				cert.Subject.CommonName)
		}
		out = append(out, cert)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("trust bundle carries no usable CA certificate")
	}
	return out, nil
}

// Fingerprints returns the sha256 of each anchor, lower-case hex — the same shape devices already report as
// pinned_transport_ca_sha256, so an operator can line up "what I published" against "what devices hold".
func (p TrustBundlePayload) Fingerprints() ([]string, error) {
	anchors, err := p.Anchors()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(anchors))
	for _, c := range anchors {
		sum := sha256.Sum256(c.Raw)
		out = append(out, hex.EncodeToString(sum[:]))
	}
	return out, nil
}

// VerifyTrustBundle checks the envelope against the pinned key, confirms the payload really is a trust bundle,
// and refuses anything that does not advance past lastAcceptedSerial.
//
// Pass the highest serial this device has ever accepted (0 if none). Rollback protection is the whole reason a
// serial exists: without it, an attacker who can serve the device anything — which is precisely the situation
// this document is fetched in — could replay a bundle from before a compromised CA was withdrawn.
func VerifyTrustBundle(env Envelope, pinnedPubKeyHex string, lastAcceptedSerial int64) (TrustBundlePayload, error) {
	return VerifyTrustBundleWithKeys(env, []string{pinnedPubKeyHex}, lastAcceptedSerial)
}

// VerifyTrustBundleWithKeys verifies against the SET of signing keys this device honours. It matters most here:
// the bundle is what CARRIES the next signing key, so a device that has already adopted a set must be able to
// keep reading bundles across the changeover — otherwise the very document that rotates the key becomes
// unreadable at the moment it is needed.
func VerifyTrustBundleWithKeys(env Envelope, pubKeyHexes []string, lastAcceptedSerial int64) (TrustBundlePayload, error) {
	if len(pubKeyHexes) == 0 {
		return TrustBundlePayload{}, fmt.Errorf("a pinned public key is required to verify a trust bundle")
	}
	payloadBytes, err := VerifyAny(env, pubKeyHexes)
	if err != nil {
		return TrustBundlePayload{}, fmt.Errorf("verify trust bundle: %w", err)
	}
	var p TrustBundlePayload
	if err := json.Unmarshal(payloadBytes, &p); err != nil {
		return TrustBundlePayload{}, fmt.Errorf("decode trust bundle: %w", err)
	}
	if p.SchemaVersion != TrustBundleSchema {
		return TrustBundlePayload{}, fmt.Errorf("payload is %q, not a trust bundle (%s)", p.SchemaVersion, TrustBundleSchema)
	}
	if p.Serial <= 0 {
		return TrustBundlePayload{}, fmt.Errorf("trust bundle has no serial; rollback could not be detected")
	}
	if p.Serial <= lastAcceptedSerial {
		return TrustBundlePayload{}, fmt.Errorf("%w: serial %d does not advance past %d — refusing a replay",
			ErrTrustBundleNotNewer, p.Serial, lastAcceptedSerial)
	}
	if _, err := p.Anchors(); err != nil {
		return TrustBundlePayload{}, err
	}
	return p, nil
}

// FetchVerifiedTrustBundle fetches and verifies the bundle. The client passed here does NOT need to authenticate
// the server — that is the point — so callers may hand it a plain client when the pinned anchor no longer
// validates the Edge. Fail-closed: nothing is returned unless the signature, the schema and the serial all pass.
func FetchVerifiedTrustBundle(ctx context.Context, client *http.Client, baseURL, pinnedPubKeyHex string, lastAcceptedSerial int64) (TrustBundlePayload, error) {
	return FetchVerifiedTrustBundleWithKeys(ctx, client, baseURL, []string{pinnedPubKeyHex}, lastAcceptedSerial)
}

// FetchVerifiedTrustBundleWithKeys is the same fetch against the SET of signing keys this device honours.
func FetchVerifiedTrustBundleWithKeys(ctx context.Context, client *http.Client, baseURL string, pubKeyHexes []string, lastAcceptedSerial int64) (TrustBundlePayload, error) {
	return FetchVerifiedTrustBundleForName(ctx, client, baseURL, "", pubKeyHexes, lastAcceptedSerial)
}

// FetchVerifiedTrustBundleForName is the same fetch, saying WHICH organization's bundle is wanted.
//
// ★★★ WITHOUT IT THE LAST RESORT IS ALIVE FOR ONE ORGANIZATION AND DEAD FOR EVERY OTHER (2026-08-20, measured
// on the lab). This endpoint is deliberately unauthenticated — it exists for a device that can no longer prove
// anything — so the server has nothing to key the answer on and returns the bundle of the organization the
// NODE belongs to. Every agent, on both platforms, asked without saying. A device of any other organization is
// therefore handed anchors that cannot verify the certificate it is served, refuses them correctly, and never
// returns. A single-organization lab cannot see this, and the day it appears is the day some other
// organization's device first expires.
//
// serverName is the announced transport name the device has ADOPTED — the value it already sends in the
// handshake. It is a SELECTOR, not a credential: it proves nothing and grants nothing, exactly as the SNI does
// on the connection this is standing in for. Empty sends nothing and behaves as before, which is what a device
// that has adopted no name must keep doing.
func FetchVerifiedTrustBundleForName(ctx context.Context, client *http.Client, baseURL, serverName string,
	pubKeyHexes []string, lastAcceptedSerial int64) (TrustBundlePayload, error) {
	target := strings.TrimRight(baseURL, "/") + trustBundlePath
	if name := strings.TrimSpace(serverName); name != "" {
		target += "?server_name=" + url.QueryEscape(name)
	}
	var env Envelope
	if err := getJSON(ctx, client, target, &env); err != nil {
		return TrustBundlePayload{}, err
	}
	return VerifyTrustBundleWithKeys(env, pubKeyHexes, lastAcceptedSerial)
}

// SignTrustBundle builds the signed envelope the Edge serves. Serial must advance on every issue; the caller
// owns that counter because it is what devices use to reject replays.
// SignTrustBundle signs the bundle without naming interception roots. Kept so existing callers and the OSS
// surface are unchanged; SignTrustBundleWithInterceptionRoots is the same thing with the roots stated.
func (s *Signer) SignTrustBundle(tenantID string, serial int64, transportCAPEM, recoveryEndpoint string, now time.Time) (Envelope, error) {
	return s.SignTrustBundleWithInterceptionRoots(tenantID, serial, transportCAPEM, recoveryEndpoint, nil, now)
}

func (s *Signer) SignTrustBundleWithInterceptionRoots(tenantID string, serial int64, transportCAPEM,
	recoveryEndpoint string, interceptionRootSHA256 []string, now time.Time) (Envelope, error) {
	return s.SignTrustBundleWithKeyring(tenantID, serial, transportCAPEM, recoveryEndpoint,
		interceptionRootSHA256, nil, now)
}

// SignTrustBundleWithKeyring is the same bundle carrying the set of policy-signing keys devices should accept.
// The signer's OWN key is always included and listed first: a bundle that advertised a set without the key
// that signed it would tell a device to stop trusting the sender of that very instruction.
func (s *Signer) SignTrustBundleWithKeyring(tenantID string, serial int64, transportCAPEM,
	recoveryEndpoint string, interceptionRootSHA256, agentPolicyPublicKeys []string, now time.Time) (Envelope, error) {
	if serial <= 0 {
		return Envelope{}, fmt.Errorf("trust bundle serial must be positive")
	}
	p := TrustBundlePayload{
		SchemaVersion:           TrustBundleSchema,
		TenantID:                strings.TrimSpace(tenantID),
		Serial:                  serial,
		IssuedAt:                now.UTC().Format(time.RFC3339),
		TransportCAPEM:          transportCAPEM,
		RenewalRecoveryEndpoint: strings.TrimSpace(recoveryEndpoint),
		InterceptionRootSHA256:  normaliseFingerprints(interceptionRootSHA256),
		AgentPolicyPublicKeys:   normalisePolicyKeys(s.PublicKeyHex(), agentPolicyPublicKeys),
	}
	return s.SignTrustBundlePayload(p, now)
}

// SignTrustBundlePayload signs a bundle the caller has filled in, for the fields the positional forms above do
// not carry.
//
// ★ ADDITIVE ON PURPOSE (2026-08-19). The positional signatures have eighteen call sites, several of them in
// the Windows agent's own tests, and this package is what that agent builds against. Widening the signature to
// carry one more field would have churned another platform's tests for a field they do not use yet — so the
// callers that need it fill the payload, and the ones that do not are untouched.
func (s *Signer) SignTrustBundlePayload(p TrustBundlePayload, now time.Time) (Envelope, error) {
	if p.Serial <= 0 {
		return Envelope{}, fmt.Errorf("trust bundle serial must be positive")
	}
	if strings.TrimSpace(p.SchemaVersion) == "" {
		p.SchemaVersion = TrustBundleSchema
	}
	if strings.TrimSpace(p.IssuedAt) == "" {
		p.IssuedAt = now.UTC().Format(time.RFC3339)
	}
	p.AgentPolicyPublicKeys = normalisePolicyKeys(s.PublicKeyHex(), p.AgentPolicyPublicKeys)
	p.InterceptionRootSHA256 = normaliseFingerprints(p.InterceptionRootSHA256)
	if _, err := p.Anchors(); err != nil {
		// Refuse to sign something no device could use; a signed-but-useless bundle would advance the serial and
		// lock out the good one behind it.
		return Envelope{}, err
	}
	return s.Sign(p, now)
}
