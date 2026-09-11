package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
)

// trust_anchor_recovery.go — anchor self-healing for the Windows agent, the same mechanism the macOS NE runs
// (DsseTrustAnchorRecovery / DsseAdoptedTrustAnchorStore) so one description covers both clients.
//
// The situation this exists for: this device's pinned transport CA no longer validates the Edge, so the (T)
// tunnel cannot open — and everything that would repair it is distributed over that tunnel. Cross-signing is
// what should stop the deadlock forming at all; this is what the device does when it forms anyway (a shutdown
// longer than the rotation overlap, an unplanned key revocation, a rotation performed without the
// cross-certificate).
//
// It is a PERIODIC CHECK, not a reaction to a failed handshake. Reacting to an error only covers devices
// already running and trying; a device that BOOTS holding a stale anchor never gets a meaningful failure to
// react to, and that is exactly the returning-from-leave case. A probe that finds the anchors valid costs one
// TLS handshake and fetches nothing.
//
// Nothing here trusts the network. The probe decides only WHETHER to look; the bundle then fetched is verified
// against the Ed25519 key pinned in this device's configuration (--agent-policy-pin) and refused unless its
// serial advances past the highest ever accepted.

const (
	// Same file names as the macOS store, deliberately: one runbook line ("look for trust_anchor_pointer.json
	// next to the pinned CA") covers both platforms.
	adoptedAnchorsFile = "trust_anchors_adopted.pem"
	adoptedPointerFile = "trust_anchor_pointer.json"
	// provisionedTransportCAFile is the anchor an MSI-installed device is born with, at a well-known name
	// beside its state. It is the config-store equivalent of --transport-pinned-ca, which that install never
	// passes; transportPinPath is where that is resolved, and carries what its absence cost.
	provisionedTransportCAFile = "transport_ca.pem"
	// The port to fall back to when the transport carries none. 443 because every agent-facing path is answered
	// on the transport port — see trustBundleBaseURL. It is NOT a second agent-facing port.
	trustBundleDefaultPort = "443"
	// A healthy probe is one handshake; six-hourly matches the certificate-renewal ceiling. A device that
	// PROBES STALE but cannot recover retries much sooner — it is dark, and urgency is correct there.
	trustRecoveryInterval      = 6 * time.Hour
	trustRecoveryRetryInterval = 15 * time.Minute
)

// adoptedTrustPointer records what was adopted and at which serial. Non-secret by construction: the serial,
// fingerprints and a date — the anchors themselves are public certificates in the file beside it.
//
// The serial is the point of persisting anything at all: replay protection is a comparison against the highest
// bundle ever accepted, and forgetting it on restart would make an old bundle acceptable again — restoring a CA
// the fleet withdrew. It lives in THIS file, not the anchors file, precisely so losing the anchors does not
// lose the serial.
type adoptedTrustPointer struct {
	Serial int64 `json:"serial"`
	// TenantID is the organization the adopted distribution belongs to.
	//
	// ★★★ SERIALS ARE PER-ORGANIZATION, SO COMPARING THEM ACROSS ONE MEANS NOTHING (2026-08-29, win-dev-1).
	// This box held tenant_default's distribution at serial 3; its own organization publishes serial 3 too. The
	// "does it advance" gate therefore answered no to the CORRECT distribution, for ever — a device stuck on
	// another organization's authority with nothing red anywhere. Replay protection is a comparison against a
	// predecessor, and a stranger is not one.
	//
	// Empty on every pointer written before this field existed. Those are not silently discarded — see
	// trustSerialFloor: an unnamed distribution keeps gating, and the ambiguity is stated with its repair,
	// because forgetting a replay floor on a suspicion is an automatic root decision and this product does not
	// make those.
	TenantID     string   `json:"tenant_id,omitempty"`
	Fingerprints []string `json:"fingerprints"`
	AdoptedAt    string   `json:"adopted_at"`
	// RenewalRecoveryEndpoint is the RESOLVED host:port carried by the adopted bundle (empty when the bundle
	// carried none). Persisted so a device that restarts after adopting — the long-shutdown case — still knows
	// where certificate recovery lives without waiting for the next bundle.
	RenewalRecoveryEndpoint string `json:"renewal_recovery_endpoint,omitempty"`
	// InterceptionRootSHA256 are the interception roots this deployment says it signs intercepted traffic under
	// — the fingerprints the agent then LOOKS FOR in its own trust store and reports which it holds. Persisted
	// from the adopted bundle so the report has a stable "wanted" list between bundle changes (a deployment that
	// is not rotating publishes a new bundle never). It is a QUESTION, not a change to what the device trusts.
	InterceptionRootSHA256 []string `json:"interception_root_sha256,omitempty"`
	// AgentPolicyPublicKeys are the policy-signing keys this device should ACCEPT, adopted from a bundle that
	// was itself signed by the key already in force — so the set arrives with the same provenance as everything
	// else. Persisted because it is what makes the signing key rotatable at all: with a single pinned key,
	// changing it makes every device reject the new signatures and freeze on its last applied policy. Empty =
	// nothing was published, and the device keeps verifying with its provisioned pin alone (today's behaviour).
	AgentPolicyPublicKeys []string `json:"agent_policy_public_keys,omitempty"`
	// TransportServerName is the name this organization's agents send as the SNI on the (T) transport and
	// verify the presented certificate against. Persisted for the same reason the recovery endpoint is: a
	// device that restarts must go on dialing the way it was told to, without waiting for the next bundle.
	//
	// Written only after this device has PROVED it can still verify the Edge under that name — see
	// proveAnnouncedServerName. An announcement is not evidence; the served chain is.
	TransportServerName string `json:"transport_server_name,omitempty"`
	// TransportServerNameAnnounced is what the bundle CLAIMED, proved or not, and it exists so a refusal is a
	// DELAY rather than a verdict. The proof is one network probe: a blip during it must not cost the device
	// this name until some unrelated serial happens to advance — which on a deployment that is not rotating is
	// never. Kept beside the proved name so each recovery tick can retry exactly what is still outstanding.
	TransportServerNameAnnounced string `json:"transport_server_name_announced,omitempty"`
	// RenewalRecoverySNI is the name to SEND on the expired-certificate recovery dial. Stored unproved,
	// deliberately: it is a selector for a listener that does not exist yet (step 3 of the one-port fold), and the name this
	// device VERIFIES against is unchanged until it does. Sending a label nothing answers to costs nothing;
	// being unable to send it is what would strand this device when the second port goes away.
	RenewalRecoverySNI string `json:"renewal_recovery_sni,omitempty"`
}

func readAdoptedPointer(stateDir string) (adoptedTrustPointer, bool) {
	var p adoptedTrustPointer
	raw, err := os.ReadFile(filepath.Join(stateDir, adoptedPointerFile))
	if err != nil {
		return p, false
	}
	if json.Unmarshal(raw, &p) != nil || p.Serial <= 0 {
		return p, false
	}
	return p, true
}

// lastAcceptedTrustSerial is what verification compares against. 0 when this device has never adopted a bundle.
func lastAcceptedTrustSerial(stateDir string) int64 {
	p, ok := readAdoptedPointer(stateDir)
	if !ok {
		return 0
	}
	return p.Serial
}

// trustSerialFloor is lastAcceptedTrustSerial asked correctly: what a distribution from THIS organization must
// advance past. A distribution belonging to a different organization is not a predecessor of this one, and
// comparing their serials is comparing two unrelated counters.
//
// ★★★ AND THE NAME IS EVIDENCE WHEN THE TENANT IS NOT RECORDED (2026-08-30, the macOS session's finding,
// adopted here because this box hit the same case and had to be repaired by hand).
//
// The first version of this refused to act on a pointer that names no organization: it could not tell a
// stranger's from its own, and forgetting a replay floor on a suspicion would be adopting an authority on a
// guess. That reasoning is right and the consequence was wrong — EVERY pointer in the world today predates the
// field, so the check protected only devices that did not need protecting, and the fleet that did walked
// straight through. The macOS side shipped the same fix and found it changed nothing on the machine it was
// written for, for exactly this reason.
//
// The evidence was already on disk. A pointer records the transport name its distribution announced; the
// profile states the name THIS deployment serves for this organization. Two different names is not "cannot
// prove it is mine" — it is PROVED TO BE SOMEBODY ELSE'S, which is a fact, not a suspicion, and acting on a
// fact is not an automatic trust decision.
//
// ★ THE TENANT STILL DECIDES WHEN BOTH SIDES HAVE ONE. Within one organization a changed name is a RENAME, and
// discarding there would reset the replay floor to zero and let a withdrawn CA come back. The name is consulted
// only where the tenant cannot answer.
func trustSerialFloor(stateDir, tenantID string) int64 {
	return trustSerialFloorForName(stateDir, tenantID, "")
}

// trustSerialFloorForName is trustSerialFloor with the name this deployment serves for this organization —
// installprofile.OrganizationSpec.TransportServerName — so a legacy pointer can be judged on evidence.
func trustSerialFloorForName(stateDir, tenantID, profileServerName string) int64 {
	p, ok := readAdoptedPointer(stateDir)
	if !ok {
		return 0
	}
	if foreign, why := adoptedIsProvenForeign(p, tenantID, profileServerName); foreign {
		log.Printf("trust_anchor_recovery %s — so its serial %d does not gate this organization's", why, p.Serial)
		return 0
	}
	if strings.TrimSpace(p.TenantID) == "" && strings.TrimSpace(tenantID) != "" {
		log.Printf("trust_anchor_recovery the adopted distribution at serial %d names no organization and no "+
			"name to compare, so this device cannot tell whether it is its own. The serial still gates: if it "+
			"is a stranger's, %s must be removed by hand",
			p.Serial, filepath.Join(stateDir, adoptedPointerFile))
	}
	return p.Serial
}

// adoptedIsProvenForeign reports whether the adopted distribution can be SHOWN to belong to another
// organization — never merely suspected of it. The returned sentence is the evidence, written for the log.
func adoptedIsProvenForeign(p adoptedTrustPointer, tenantID, profileServerName string) (bool, string) {
	adopted, want := strings.TrimSpace(p.TenantID), strings.TrimSpace(tenantID)
	if adopted != "" && want != "" {
		if !strings.EqualFold(adopted, want) {
			return true, fmt.Sprintf("the adopted distribution belongs to %q and this device belongs to %q — "+
				"a stranger is not a predecessor", adopted, want)
		}
		// Same organization. A different name here is a rename, and the tenant has already answered.
		return false, ""
	}
	// No tenant on one side or the other: fall back to the name, which is the other durable fact on disk.
	mine := strings.TrimSpace(profileServerName)
	theirs := strings.TrimSpace(p.TransportServerName)
	if theirs == "" {
		theirs = strings.TrimSpace(p.TransportServerNameAnnounced)
	}
	if mine != "" && theirs != "" && !strings.EqualFold(mine, theirs) {
		return true, fmt.Sprintf("the adopted distribution asks this device to present %q and the deployment "+
			"it is installed for serves %q — that is not an unprovable claim, it is proof the distribution is "+
			"somebody else's", theirs, mine)
	}
	return false, ""
}

// adoptedTrustAnchors returns the anchors this device adopted, or ok=false when there is nothing usable.
//
// ok=false — not an empty set — when the pointer exists but the anchor file is missing or yields nothing. An
// empty set at the call site is indistinguishable from "trust nothing" and would fail the transport closed
// forever; "nothing adopted" lets the caller fall back to the provisioned anchors, the state the device was
// working in before.
func adoptedTrustAnchors(stateDir string) (pemBytes []byte, cas []*x509.Certificate, serial int64, ok bool) {
	p, pok := readAdoptedPointer(stateDir)
	if !pok {
		return nil, nil, 0, false
	}
	raw, err := os.ReadFile(filepath.Join(stateDir, adoptedAnchorsFile))
	if err != nil {
		return nil, nil, 0, false
	}
	parsed := parsePinnedCAs(raw)
	if len(parsed) == 0 {
		return nil, nil, 0, false
	}
	// The anchors file is written FIRST and the pointer SECOND, so a crash during a RE-adoption can leave the
	// NEW anchors file beside the STILL-OLD pointer. The write order's stated guarantee — "a crash leaves the
	// device on its provisioned anchors" — only holds for the very first adoption (no prior pointer); on a
	// re-adoption the torn pair would otherwise be served as the new anchors under the OLD serial, weakening the
	// monotonic replay guard (a withdrawn CA at an intermediate serial could then be re-adopted). The pointer
	// records the fingerprints it was committed WITH, so a file that does not match them is exactly that torn
	// pair: fall back to the provisioned anchors (the safe state the order is meant to give) and let the next
	// recovery cycle re-adopt cleanly. Skipped for a pre-fingerprint pointer, which cannot be checked this way.
	if len(p.Fingerprints) > 0 && !anchorsMatchFingerprints(parsed, p.Fingerprints) {
		return nil, nil, 0, false
	}
	return raw, parsed, p.Serial, true
}

// anchorsMatchFingerprints reports whether the anchor set on disk is EXACTLY the set the pointer was committed
// with (compared as a set of SHA-256 fingerprints). A mismatch means the anchors file and the pointer are from
// different adoptions — a torn two-file write — and must not be trusted as a consistent pair.
func anchorsMatchFingerprints(anchors []*x509.Certificate, want []string) bool {
	have := make(map[string]struct{}, len(anchors))
	for _, c := range anchors {
		sum := sha256.Sum256(c.Raw)
		have[hex.EncodeToString(sum[:])] = struct{}{}
	}
	wantSet := make(map[string]struct{}, len(want))
	for _, f := range want {
		if t := strings.ToLower(strings.TrimSpace(f)); t != "" {
			wantSet[t] = struct{}{}
		}
	}
	if len(have) != len(wantSet) {
		return false
	}
	for f := range wantSet {
		if _, ok := have[f]; !ok {
			return false
		}
	}
	return true
}

// adoptedRecoveryEndpoint returns the resolved certificate-recovery endpoint the adopted bundle carried, if any.
func adoptedRecoveryEndpoint(stateDir string) string {
	p, ok := readAdoptedPointer(stateDir)
	if !ok {
		return ""
	}
	return strings.TrimSpace(p.RenewalRecoveryEndpoint)
}

// adoptedTransportServerName returns the organization's transport name the last adopted bundle announced and
// this device PROVED it can verify the Edge under. Empty when nothing was announced (the shared certificate).
func adoptedTransportServerName(stateDir string) string {
	p, ok := readAdoptedPointer(stateDir)
	if !ok {
		return ""
	}
	return strings.TrimSpace(p.TransportServerName)
}

// adoptedRecoverySNI returns the name to send on the recovery dial, as last announced. Empty = send nothing
// new, which is what an agent that never saw the field does.
func adoptedRecoverySNI(stateDir string) string {
	p, ok := readAdoptedPointer(stateDir)
	if !ok {
		return ""
	}
	return strings.TrimSpace(p.RenewalRecoverySNI)
}

// advertisedInterceptionRoots returns the interception-root fingerprints the last adopted bundle named — the
// "wanted" list the agent looks for in its own trust store. Empty when nothing has been adopted or the bundle
// named none.
func advertisedInterceptionRoots(stateDir string) []string {
	p, ok := readAdoptedPointer(stateDir)
	if !ok {
		return nil
	}
	return p.InterceptionRootSHA256
}

// policyKeyStateDir is where the adopted key set lives: beside the pinned CA, the same directory the trust
// anchors and the renewal pointer use. Empty when no pin file is configured (nothing has been adopted either).
func policyKeyStateDir(transportPinnedCAFile string) string {
	if strings.TrimSpace(transportPinnedCAFile) == "" {
		return ""
	}
	return filepath.Dir(transportPinnedCAFile)
}

// policyVerificationKeys is the set of signing keys this device accepts on signed policy: the PROVISIONED PIN
// first, plus any adopted from a signed trust bundle. Duplicates and malformed entries are dropped.
//
// The pin is always included and never displaced. A published set is additive during the overlap — if it were
// treated as a replacement, one bad publication (or one adopted before the fleet was ready) would cut a device
// off from the only key it was provisioned to trust, and policy is fail-safe, so it would then freeze silently.
// Withdrawing the old key is a later, deliberate step on the Edge side, not something a device infers.
func policyVerificationKeys(pinHex, stateDir string) []string {
	keys := sanitisePolicyKeys([]string{pinHex})
	if stateDir != "" {
		if p, ok := readAdoptedPointer(stateDir); ok {
			for _, k := range sanitisePolicyKeys(p.AgentPolicyPublicKeys) {
				keys = appendUniqueKey(keys, k)
			}
		}
	}
	return keys
}

// sanitisePolicyKeys keeps only keys the verifier can actually use, lower-cased and deduplicated, preserving
// order. Anything else is dropped SILENTLY: these are keys a device would accept signed instructions from, so a
// malformed entry must never be carried forward on the chance it means something.
//
// The accept rule is agentpolicy's, not a copy of it. This function used to test the length itself and so
// admitted Ed25519 only; once the shared verifier learned ECDSA-P256, a published ECDSA next-key would have
// been dropped right here, at adoption — the device would have reported no such key, looked ready for the
// switch, and then failed to verify the first ECDSA-signed policy. What a device stores has to be exactly
// what it can later verify with, which means one rule and one place for it.
func sanitisePolicyKeys(in []string) []string {
	var out []string
	for _, raw := range in {
		k := strings.ToLower(strings.TrimSpace(raw))
		if !agentpolicy.AcceptedPublicKeyHex(k) {
			continue
		}
		out = appendUniqueKey(out, k)
	}
	return out
}

func appendUniqueKey(keys []string, k string) []string {
	for _, existing := range keys {
		if existing == k {
			return keys
		}
	}
	return append(keys, k)
}

// installTrustBundle writes a VERIFIED bundle's anchors. Refuses anything that would leave the device worse
// off: an unusable anchor set, or a serial that does not advance past what is already installed.
//
// Write order is anchors first, pointer second. The pointer is what makes the anchors live, so a crash between
// the two leaves the device on its provisioned anchors — the state it was already working in — rather than
// pointing at a file that is not there yet.
//
// provedServerName is the organization's announced transport name AFTER this device has confirmed it can still
// verify the Edge under it — "" when nothing was announced or the proof failed. It is a parameter rather than
// a field read off the payload because the payload is what was CLAIMED, and only the caller has stood on the
// wire and checked.
func installTrustBundle(stateDir string, payload agentpolicy.TrustBundlePayload, recoveryEndpoint, provedServerName string) (adoptedTrustPointer, error) {
	anchors, err := payload.Anchors()
	if err != nil {
		return adoptedTrustPointer{}, err
	}
	if prev := lastAcceptedTrustSerial(stateDir); payload.Serial <= prev {
		return adoptedTrustPointer{}, fmt.Errorf("bundle serial %d does not advance past installed %d", payload.Serial, prev)
	}
	fingerprints := make([]string, 0, len(anchors))
	for _, c := range anchors {
		sum := sha256.Sum256(c.Raw)
		fingerprints = append(fingerprints, hex.EncodeToString(sum[:]))
	}
	if err := writeFileAtomically(filepath.Join(stateDir, adoptedAnchorsFile), []byte(payload.TransportCAPEM)); err != nil {
		return adoptedTrustPointer{}, fmt.Errorf("write adopted anchors: %w", err)
	}
	pointer := adoptedTrustPointer{
		Serial:                  payload.Serial,
		TenantID:                strings.TrimSpace(payload.TenantID),
		Fingerprints:            fingerprints,
		AdoptedAt:               time.Now().UTC().Format(time.RFC3339),
		RenewalRecoveryEndpoint: strings.TrimSpace(recoveryEndpoint),
		InterceptionRootSHA256:  payload.InterceptionRootSHA256,
		// Sanitised on the way IN as well as out: an entry here is a key this device will accept instructions
		// from, so a malformed one is dropped rather than stored. The Edge already filters, but the receiving
		// side is where it actually matters.
		AgentPolicyPublicKeys:        sanitisePolicyKeys(payload.AgentPolicyPublicKeys),
		TransportServerName:          strings.TrimSpace(provedServerName),
		TransportServerNameAnnounced: strings.TrimSpace(payload.TransportServerName),
		RenewalRecoverySNI:           strings.TrimSpace(payload.RenewalRecoverySNI),
	}
	raw, err := json.MarshalIndent(pointer, "", "  ")
	if err != nil {
		return adoptedTrustPointer{}, err
	}
	if err := writeFileAtomically(filepath.Join(stateDir, adoptedPointerFile), raw); err != nil {
		return adoptedTrustPointer{}, fmt.Errorf("commit adopted anchors: %w", err)
	}
	return pointer, nil
}

func writeFileAtomically(path string, data []byte) error {
	tmp := path + ".tmp"
	// 0644: anchors are public certificates and the pointer names only fingerprints. On Windows the mode is a
	// no-op and the file inherits the (administrator-only) directory ACL, same as the renewal store beside it.
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// servedTransportChain fetches the certificate chain the Edge's TRANSPORT listener presents, without
// validating it. Reading the chain is not trusting it — the only use below is an explicit evaluation against
// pinned anchors.
//
// Two deliberate choices, both paid for on the macOS side first:
//   - The probe targets the TRANSPORT port, not the data port. The two listeners serve entirely different
//     certificates; probing the wrong one answers a question about the wrong listener.
//   - The verdict is NEVER read out of a TLS error. The transport requires a client certificate, so a probe
//     without one fails the handshake for a reason indistinguishable from an untrusted chain — every healthy
//     device would conclude its anchors were stale. Fetch the chain, then verify locally.
func servedTransportChain(tc transportConfig, timeout time.Duration) ([]*x509.Certificate, error) {
	return servedTransportChainForName(tc, tc.sniToSend(), timeout)
}

// servedTransportChainForName is the same probe under an EXPLICIT name. The name is what selects the
// certificate now that the Edge serves one per organization, so asking "what would I get" has to be able to
// ask it under a name this device does not send yet.
func servedTransportChainForName(tc transportConfig, serverName string, timeout time.Duration) ([]*x509.Certificate, error) {
	raw, err := net.DialTimeout("tcp", tc.dialTarget(), timeout)
	if err != nil {
		return nil, err
	}
	defer raw.Close()
	conn := tls.Client(raw, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, // the chain is CAPTURED here and VERIFIED below, anchors-only
		MinVersion:         tls.VersionTLS12,
	})
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := conn.Handshake(); err != nil {
		return nil, err
	}
	chain := conn.ConnectionState().PeerCertificates
	if len(chain) == 0 {
		return nil, fmt.Errorf("the transport listener presented no certificate")
	}
	return chain, nil
}

// chainValidatesWithAnchors evaluates a served chain against ONLY the given anchors — the same anchors-only
// rule tlsConfig() applies, so the probe cannot pass where the real handshake would fail.
func chainValidatesWithAnchors(chain []*x509.Certificate, anchors []*x509.Certificate, serverName string) bool {
	if len(chain) == 0 || len(anchors) == 0 {
		return false
	}
	roots := x509.NewCertPool()
	for _, a := range anchors {
		roots.AddCert(a)
	}
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	_, err := chain[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       serverName,
	})
	return err == nil
}

// resolveRecoveryEndpoint tolerates a fleet config that names only the port ("18545" or ":18545"), taking the
// HOST from the transport the device already has. The transport address is written at provisioning time — a
// device without it cannot reach the Edge at all — whereas the recovery endpoint arrives later and by another
// route, so a port-only value is what lets one fleet-wide setting be correct for every Edge. Returns "" when
// the value is unusable.
func resolveRecoveryEndpoint(raw, transportHostPort string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(raw); err == nil && host != "" {
		return raw
	}
	port := strings.TrimPrefix(raw, ":")
	if port == "" {
		return ""
	}
	for _, r := range port {
		if r < '0' || r > '9' {
			return ""
		}
	}
	host, _, err := net.SplitHostPort(transportHostPort)
	if err != nil {
		host = transportHostPort
	}
	if host == "" {
		return ""
	}
	// JoinHostPort brackets an IPv6 literal exactly once, which hand-concatenation reliably gets wrong.
	return net.JoinHostPort(host, port)
}

// trustBundleBaseURL derives where the bundle lives when no explicit URL is configured: the transport's host AND
// ITS PORT, where GET /bootstrap/trust-bundle is served without device authentication. That is intentional on
// the Edge side — a device that can prove its identity does not need this document, and the device that needs it
// cannot prove anything.
//
// ★ IT KEEPS THE TRANSPORT'S PORT. It used to substitute 8443, and that is the enrolment fold's last unfinished
// piece: the agent dialling the transport port, which is where every agent-facing route is answered. Every
// agent-facing path — enrolment, this bundle, the policy key, the region list — is answered on the transport
// port, and a SECOND agent-facing port must not exist: a network that passes one and blocks the other produces a
// deployment that half works. Certificate-renewal recovery was folded already; this was the straggler.
//
// ★ MEASURED, NOT DEDUCED (2026-08-26, win-dev-1 on the generated deployment): the deployment published 443 and
// 10443 and served the bundle on 443, the agent dialled 8443, and the connection was refused every minute. The
// device therefore reported wanted=0 — indistinguishable from "this deployment does not inspect" — while its
// traffic was being decrypted. Nothing could have reconciled those two numbers, because the install profile has
// no field for a bundle URL and must not grow one.
func trustBundleBaseURL(explicit, transportHostPort string) string {
	if u := strings.TrimSpace(explicit); u != "" {
		return strings.TrimRight(u, "/")
	}
	host, port, err := net.SplitHostPort(transportHostPort)
	if err != nil {
		host, port = transportHostPort, trustBundleDefaultPort
	}
	if strings.TrimSpace(host) == "" {
		return ""
	}
	if strings.TrimSpace(port) == "" {
		port = trustBundleDefaultPort
	}
	return "https://" + net.JoinHostPort(host, port)
}

// unverifiedChannelClient fetches WITHOUT validating the server certificate. That is not a weakening: this runs
// precisely when the device cannot validate the Edge, and the document's authenticity comes from its signature.
// Verifying the channel here would make the fallback unusable in the only situation it exists for. Nothing read
// from this channel is used before it verifies against the pinned key.
//
// ★ AND DO NOT "HARDEN" IT LATER — IT WOULD BREAK THIS DEPLOYMENT TODAY, NOT HYPOTHETICALLY (measured
// 2026-08-20). The bundle URL is derived from the transport host, which on this lab is a tailnet name, and the
// certificate that endpoint serves does not carry it: a dial there with verification on fails
// ERR_TLS_CERT_ALTNAME_INVALID. Turning verification on here would therefore take away the recovery channel
// from exactly the devices that need it, and the symptom — "cannot fetch a bundle" — reads like an outage
// rather than like a change somebody made on purpose. The signature is the check; the channel is not.
func unverifiedChannelClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
		},
		Timeout: timeout,
	}
}

type trustRecoveryConfig struct {
	// stateDir is where adopted anchors + the pointer live — the directory of the provisioned pin file, so an
	// operator finds both generations of trust material in one place.
	stateDir string
	// pinHex is the Ed25519 verification key (--agent-policy-pin). The bundle's whole authenticity rests on it.
	pinHex string
	// tenantID is the organization THIS device belongs to, from the signed profile. It is what makes a serial
	// comparison meaningful (see trustSerialFloor) and what a fetched distribution is checked against before it
	// is adopted: a document signed by the right authority for the wrong organization is still the wrong
	// document, and this device measured what adopting one costs.
	tenantID string
	// bundleURL overrides the derived https://<transport-host>:8443 base (empty = derive).
	bundleURL string
	// liveRecovery, when non-nil, receives the resolved certificate-recovery endpoint carried by an adopted
	// bundle, so the renewal loop picks it up without a restart.
	liveRecovery *atomic.Pointer[string]
	// wake, when non-nil, shortens the wait between passes: the report loop sends on it when the Edge's
	// response says a newer distribution exists. Buffered by the caller and non-blocking on send, so a hint
	// arriving while a pass is running is coalesced rather than queued. nil = timer only.
	wake    chan struct{}
	timeout time.Duration
	// client overrides the unverified-channel HTTP client (tests); nil = production client.
	client *http.Client
}

// trustRecoveryOutcome says what one check concluded. The codes are stable log/test vocabulary.
//
//	anchors_valid          — the current anchors validate the Edge and nothing newer was adopted.
//	adopted                — the device could NOT validate the Edge and recovered onto a newer bundle.
//	adopted_while_healthy  — the device WAS fine and moved to a newer distribution anyway (routine catch-up,
//	                         so an overlap-then-retire rotation can actually reach the overlap on healthy devices).
//	refused_would_strand   — a newer bundle was offered but its anchors do NOT validate the served chain, so
//	                         adopting would cut this device off; it stays on working anchors and says so loudly.
//	undetermined           — the Edge was unreachable; validity could not be judged.
//	unrecovered            — the device is broken and no usable bundle could be obtained.
type trustRecoveryOutcome struct {
	code   string
	detail string
}

// runTrustAnchorRecoveryOnce is the whole check: probe, and only on a definite trust failure fetch, verify and
// adopt. The orderings that matter:
//
//   - "Unreachable" is UNDETERMINED, never "stale". Conflating them would have a fleet re-fetching trust
//     material every time the network blips. Nothing is done.
//   - But holding NO anchors at all is decided WITHOUT asking the network: a device with nothing to verify
//     against cannot verify anything whether or not the Edge answers, and probing first would leave a device
//     that lost its anchor file waiting for a human.
func runTrustAnchorRecoveryOnce(tc *transportConfig, cfg trustRecoveryConfig) trustRecoveryOutcome {
	timeout := cfg.timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	anchors := tc.currentTrustAnchors()
	var servedChain []*x509.Certificate
	if len(anchors) > 0 {
		chain, err := servedTransportChain(*tc, timeout)
		if err != nil {
			return trustRecoveryOutcome{code: "undetermined", detail: fmt.Sprintf("edge unreachable (%v); anchor validity undetermined", err)}
		}
		servedChain = chain
		if chainValidatesWithAnchors(chain, anchors, tc.activeServerName()) {
			// Healthy — but "healthy" is not "current". A distribution the fleet has moved on to is adopted here
			// in the ordinary case, not only as a rescue: a device that is updated only once it breaks can never
			// be brought onto a new CA BEFORE the old one is retired, which is the whole mechanism an
			// overlap-then-retire rotation depends on (2026-08-01: win-dev-1 sat on serial 1 while the Edge
			// served 3, so the withdrawal gate could never open for it). Mirrors macOS adoptNewerIfOffered.
			out := adoptNewerWhileHealthy(tc, cfg, timeout, servedChain)
			// An announcement this device could not prove earlier is retried AFTER the health judgement, never
			// before it: promoting the name first would leave the chain fetched under the old name being
			// checked against the new one, and a healthy device would read as broken. It has to be retried
			// somewhere, because the fetch above refuses a bundle whose serial does not advance — so a name
			// refused once (a probe that hit a blip) would otherwise wait for an unrelated rotation to carry
			// it again, and a deployment that is not rotating publishes one never.
			if note := retryOutstandingServerName(tc, cfg, timeout); note != "" {
				out.detail = strings.TrimSpace(out.detail + note)
			}
			return out
		}
	}

	// Not healthy (or no anchors): recover. The fetch's verification is pinned signature + trust-bundle schema +
	// a serial that advances past the highest ever accepted (the replay guard against a withdrawn CA).
	payload, err := fetchVerifiedTrustBundleFor(tc, cfg, timeout)
	if err != nil {
		return trustRecoveryOutcome{code: "unrecovered", detail: fmt.Sprintf("trust bundle rejected or unavailable: %v", err)}
	}
	outcome, ok := adoptVerifiedBundle(tc, cfg, payload, timeout)
	if !ok {
		return outcome
	}
	outcome.code = "adopted"
	return outcome
}

// fetchVerifiedTrustBundleFor fetches and verifies the bundle over the unverified channel (the whole point: a
// device that cannot verify the Edge can still fetch this, because its authenticity is the SIGNATURE). The
// verification is inside FetchVerifiedTrustBundle: pinned key, schema, and a serial strictly past the highest
// this device ever accepted (so a bundle at or below it — a replay onto a withdrawn CA — is refused).
func fetchVerifiedTrustBundleFor(tc *transportConfig, cfg trustRecoveryConfig, timeout time.Duration) (agentpolicy.TrustBundlePayload, error) {
	baseURL := trustBundleBaseURL(cfg.bundleURL, tc.host)
	if baseURL == "" {
		return agentpolicy.TrustBundlePayload{}, fmt.Errorf("no trust-bundle URL could be derived")
	}
	client := cfg.client
	if client == nil {
		client = unverifiedChannelClient(timeout)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// Verify against the pin PLUS any keys already adopted: the bundle is the document that carries the next
	// signing key, so it has to stay readable across the changeover it is itself announcing.
	//
	// And SAY WHICH ORGANIZATION. This endpoint cannot authenticate the caller — that is the point — so without
	// a name it answers with the bundle of the organization the NODE belongs to, and a device of any other
	// organization is handed anchors that cannot verify the certificate it is served. The name is the one thing
	// such a device still has: it is in the distribution it adopted, and BEFORE it has adopted anything it is
	// what the signed profile stated at install — see trustBundleServerName.
	//
	// The SERIAL is asked the same way. A distribution belonging to another organization is not a predecessor
	// of this one, and this box proved what comparing them costs: it held tenant_default at serial 3 while its
	// own organization published serial 3, so the correct distribution could never advance past the stranger.
	return agentpolicy.FetchVerifiedTrustBundleForName(ctx, client, baseURL, tc.trustBundleServerName(),
		policyVerificationKeys(cfg.pinHex, cfg.stateDir), trustSerialFloor(cfg.stateDir, cfg.tenantID))
}

// adoptVerifiedBundle persists a verified payload and swaps it live for every transportConfig copy — no restart,
// established tunnels untouched. The serial travels WITH the anchors so the effective-set report pairs this
// serial with these fingerprints, never a serial from one reality and a fingerprint set from another. ok=false
// (with an unrecovered outcome) when the install itself fails.
func adoptVerifiedBundle(tc *transportConfig, cfg trustRecoveryConfig, payload agentpolicy.TrustBundlePayload,
	timeout time.Duration) (trustRecoveryOutcome, bool) {
	// ★★★ A DOCUMENT SIGNED BY THE RIGHT AUTHORITY FOR THE WRONG ORGANIZATION IS STILL THE WRONG DOCUMENT
	// (2026-08-29, win-dev-1). Every deployment-wide signature check this bundle passes says nothing about WHOSE
	// it is: one Edge signs every organization's distribution with the same key. This device adopted
	// tenant_default's — correctly signed, correctly serialised, and naming the deployment's own root as the
	// authority under which its traffic is inspected. It logged ADOPTED and every screen stayed green.
	//
	// Refused rather than reconciled: a device holding the wrong organization's anchors cannot verify its own
	// door, and the failure it then produces names TLS rather than the adoption that caused it.
	if want := strings.TrimSpace(cfg.tenantID); want != "" {
		if got := strings.TrimSpace(payload.TenantID); got != "" && !strings.EqualFold(got, want) {
			log.Printf("trust_anchor_recovery REFUSED a distribution belonging to %q — this device belongs to %q. "+
				"It is correctly signed; it is somebody else's. Nothing was adopted.", got, want)
			return trustRecoveryOutcome{code: "refused_other_organization",
				detail: fmt.Sprintf("bundle names organization %q, this device is %q", got, want)}, false
		}
	}
	resolvedRecovery := resolveRecoveryEndpoint(payload.RenewalRecoveryEndpoint, tc.host)
	// The anchors go in force FIRST: the name below is proved against them, and an organization's own
	// certificate chains to the anchor that arrives in the same bundle. Proving the name against the outgoing
	// anchor set would refuse exactly the certificate this step exists to move onto.
	tc.setTrustAnchors([]byte(payload.TransportCAPEM), payload.Serial)
	provedName, nameNote := proveAnnouncedServerName(tc, payload, timeout)
	pointer, err := installTrustBundle(cfg.stateDir, payload, resolvedRecovery, provedName)
	if err != nil {
		return trustRecoveryOutcome{code: "unrecovered", detail: fmt.Sprintf("adopting the verified bundle failed: %v", err)}, false
	}
	tc.setAnnouncedNames(provedName, payload.RenewalRecoverySNI)
	if cfg.liveRecovery != nil && resolvedRecovery != "" {
		cfg.liveRecovery.Store(&resolvedRecovery)
	}
	return trustRecoveryOutcome{detail: fmt.Sprintf("serial=%d anchors=%d recovery_endpoint=%q%s",
		pointer.Serial, len(pointer.Fingerprints), resolvedRecovery, nameNote)}, true
}

// retryOutstandingServerName promotes an announced transport name this device has not managed to prove yet.
// Returns a note for the outcome line, or "" when there is nothing outstanding and nothing changed.
//
// It only ever moves a device FROM the shared certificate TO its organization's own — never the reverse, and
// never onto a name that does not verify. A deployment that withdraws an announcement does so through a new
// bundle, where the clearing path in proveAnnouncedServerName applies.
func retryOutstandingServerName(tc *transportConfig, cfg trustRecoveryConfig, timeout time.Duration) string {
	if cfg.stateDir == "" {
		return ""
	}
	p, ok := readAdoptedPointer(cfg.stateDir)
	if !ok {
		return ""
	}
	announced := strings.TrimSpace(p.TransportServerNameAnnounced)
	if announced == "" {
		// ★ AN AGENT IS UPGRADED AFTER A BUNDLE IS ADOPTED, NOT BEFORE (2026-08-19, found on win-dev-1 while
		// preparing the build that carries this). A device that adopted its current distribution under an agent
		// that did not know these fields has NO record of what was announced — and the ordinary fetch refuses a
		// serial that does not advance, so the new agent would wait for the next rotation to learn a name that
		// was published before it was installed. On a deployment that is not rotating, that is never. Every
		// device in a fleet passes through this state exactly once, at upgrade, which makes it the normal case
		// rather than an edge one.
		//
		// So the announcement is RE-READ at the serial already in force. It is not a re-adoption: the anchors,
		// the serial and the key set are untouched, and the only thing taken from the document is the pair of
		// names — which are then proved on the wire like any other. The floor is the adopted serial MINUS ONE,
		// which admits the current distribution and nothing older, so this cannot be walked backwards onto a
		// withdrawn announcement.
		announced = strings.TrimSpace(reReadAnnouncedNames(tc, cfg, timeout, &p))
		if announced == "" {
			return ""
		}
	}
	if announced == strings.TrimSpace(p.TransportServerName) {
		return ""
	}
	anchors := tc.currentTrustAnchors()
	if len(anchors) == 0 {
		return ""
	}
	chain, err := servedTransportChainForName(*tc, announced, timeout)
	if err != nil || !chainValidatesWithAnchors(chain, anchors, announced) {
		return "" // still not provable; silent, because it is retried every tick and the device is fine
	}
	p.TransportServerName = announced
	p.TransportServerNameAnnounced = announced
	raw, merr := json.MarshalIndent(p, "", "  ")
	if merr != nil {
		return ""
	}
	if werr := writeFileAtomically(filepath.Join(cfg.stateDir, adoptedPointerFile), raw); werr != nil {
		return ""
	}
	tc.setAnnouncedNames(announced, p.RenewalRecoverySNI)
	return fmt.Sprintf(" transport_server_name=%q(proved on retry)", announced)
}

// reReadAnnouncedNames re-reads the CURRENT distribution for its announced names only, and returns the
// transport name it announces (""; nothing usable). It also persists the recovery name when the pointer has
// none, for the same upgrade reason.
//
// It deliberately takes NOTHING else from the document. The anchors, the serial and the accepted key set stay
// exactly as adopted: this is a device asking "what name were you told to send", not a device adopting
// anything. The serial floor is adopted-1, so the answer can only come from the distribution already in force
// or a newer one — never from an older bundle replayed to name something withdrawn.
func reReadAnnouncedNames(tc *transportConfig, cfg trustRecoveryConfig, timeout time.Duration,
	p *adoptedTrustPointer) string {
	baseURL := trustBundleBaseURL(cfg.bundleURL, tc.host)
	if baseURL == "" {
		return ""
	}
	client := cfg.client
	if client == nil {
		client = unverifiedChannelClient(timeout)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	payload, err := agentpolicy.FetchVerifiedTrustBundleForName(ctx, client, baseURL, tc.trustBundleServerName(),
		policyVerificationKeys(cfg.pinHex, cfg.stateDir), p.Serial-1)
	if err != nil {
		return ""
	}
	// The recovery name is stored unproved (it is a selector, not an identity), so an upgraded agent that
	// finds none recorded takes it here too — otherwise the one-port fold would wait on the same rotation.
	if strings.TrimSpace(p.RenewalRecoverySNI) == "" && strings.TrimSpace(payload.RenewalRecoverySNI) != "" {
		p.RenewalRecoverySNI = strings.TrimSpace(payload.RenewalRecoverySNI)
		if raw, merr := json.MarshalIndent(p, "", "  "); merr == nil {
			if writeFileAtomically(filepath.Join(cfg.stateDir, adoptedPointerFile), raw) == nil {
				tc.setAnnouncedNames(tc.currentAnnouncedServerName(), p.RenewalRecoverySNI)
			}
		}
	}
	return strings.TrimSpace(payload.TransportServerName)
}

// proveAnnouncedServerName decides whether this device may start sending an organization's announced transport
// name. It returns the name to adopt ("" = keep sending nothing new) and a note for the outcome line.
//
// ★ AN ANNOUNCEMENT IS NOT EVIDENCE, AND THE FAILURE IS A LOCKOUT (2026-08-19). The name is verified as well
// as sent — tlsConfig passes it to Verify as the DNSName — so a name the Edge has no certificate for turns
// every subsequent dial into a refusal, on a device that was working a moment earlier. This is the same shape
// adoptNewerWhileHealthy already refuses for anchors ("refused_would_strand"), one field over, so it gets the
// same treatment: stand on the wire, ask for the certificate under that exact name, and adopt only if what
// comes back verifies. If it does not, this device keeps the name it has and SAYS SO — the Edge is then free
// to be ahead of it without either side being broken.
func proveAnnouncedServerName(tc *transportConfig, payload agentpolicy.TrustBundlePayload,
	timeout time.Duration) (string, string) {
	announced := strings.TrimSpace(payload.TransportServerName)
	if announced == "" {
		// Nothing announced means the deployment's shared certificate — today's behaviour, and it must CLEAR a
		// previously adopted name rather than leave the device asking for a certificate withdrawn from service.
		if prev := tc.currentAnnouncedServerName(); prev != "" {
			return "", fmt.Sprintf(" transport_server_name=cleared(was %q)", prev)
		}
		return "", ""
	}
	if announced == tc.currentAnnouncedServerName() {
		return announced, "" // already in force and working; nothing to prove again
	}
	anchors, err := payload.Anchors()
	if err != nil || len(anchors) == 0 {
		return "", fmt.Sprintf(" transport_server_name=refused(%q: the bundle carries no usable anchor)", announced)
	}
	chain, cerr := servedTransportChainForName(*tc, announced, timeout)
	if cerr != nil {
		return "", fmt.Sprintf(" transport_server_name=refused(%q: the Edge could not be probed under that name: %v)", announced, cerr)
	}
	if !chainValidatesWithAnchors(chain, anchors, announced) {
		return "", fmt.Sprintf(" transport_server_name=refused(%q: the served certificate does not verify under that name)", announced)
	}
	return announced, fmt.Sprintf(" transport_server_name=%q(proved)", announced)
}

// adoptNewerWhileHealthy takes a newer signed distribution on a device that is currently FINE — the routine
// half of the mechanism, the recovery path above being the emergency half. The check that matters is the last
// one: the offered anchors are installed ONLY once this device has confirmed it can still verify the Edge with
// them, against the chain the Edge is ACTUALLY serving. The Edge cannot make that judgement — it does not know
// what any device holds — so a distribution that would strand this machine is refused here, loudly, leaving it
// on anchors that work.
func adoptNewerWhileHealthy(tc *transportConfig, cfg trustRecoveryConfig, timeout time.Duration, servedChain []*x509.Certificate) trustRecoveryOutcome {
	payload, err := fetchVerifiedTrustBundleFor(tc, cfg, timeout)
	if err != nil {
		// Healthy and nothing newer to adopt is the common case and is SILENT.
		if errors.Is(err, agentpolicy.ErrTrustBundleNotNewer) {
			return trustRecoveryOutcome{code: "anchors_valid", detail: "the fetched signed bundle did not advance past the accepted serial; kept the working anchors"}
		}
		// ★ ANYTHING ELSE IS A DEVICE THAT HAS STOPPED RECEIVING DISTRIBUTIONS, AND IT USED TO LOOK IDENTICAL
		// (2026-08-19, asked from the Edge side: "if it is failing, does the failure appear in a log?"). This
		// branch treated a broken channel — unreachable, unverifiable, a signature that no longer checks — as
		// "nothing new", which is exactly what a healthy device produces. The device stays on its working
		// anchors either way, so this is not an outage; it is the difference between a fleet that can be seen
		// to be current and one that is merely quiet.
		return trustRecoveryOutcome{code: "anchors_valid",
			detail: fmt.Sprintf("could not read a distribution: %v — this device is still on the anchors it has, "+
				"and is NOT receiving new ones", err)}
	}
	offered, aerr := payload.Anchors()
	if aerr != nil || len(offered) == 0 {
		return trustRecoveryOutcome{code: "anchors_valid",
			detail: fmt.Sprintf("newer serial=%d carried no usable anchor; kept the working set", payload.Serial)}
	}
	if len(servedChain) == 0 || !chainValidatesWithAnchors(servedChain, offered, tc.activeServerName()) {
		return trustRecoveryOutcome{code: "refused_would_strand",
			detail: fmt.Sprintf("serial=%d anchors=%d — this device cannot verify the Edge with them; staying on the current anchors",
				payload.Serial, len(offered))}
	}
	outcome, ok := adoptVerifiedBundle(tc, cfg, payload, timeout)
	if !ok {
		// The install failed — but the device is healthy, so stay quietly on the working anchors rather than
		// reporting an outage.
		return trustRecoveryOutcome{code: "anchors_valid", detail: outcome.detail}
	}
	outcome.code = "adopted_while_healthy"
	return outcome
}

// startTrustAnchorRecovery runs the periodic check for as long as the agent steers. Alongside steering, never
// fatal to it — the same rule as certificate renewal and for the same reason.
func startTrustAnchorRecovery(tc *transportConfig, cfg trustRecoveryConfig) {
	if tc == nil || !tc.enabled {
		return
	}
	if strings.TrimSpace(cfg.pinHex) == "" {
		log.Printf("trust_anchor_recovery disabled (no --agent-policy-pin; the signed bundle could not be verified)")
		return
	}
	if strings.TrimSpace(cfg.stateDir) == "" {
		log.Printf("trust_anchor_recovery disabled (no state directory; provisioned via in-memory identity)")
		return
	}
	go func() {
		// A short delay so a start-up burst does not contend with bringing steering up; short enough that a
		// device that BOOTED stale heals in minutes, not hours.
		//
		// ★ AND IT YIELDS TO NEWS, BECAUSE THE STALE DEVICE IS THE ONE THAT JUST STARTED (2026-08-20, Lane B
		// scenario D-03). Measured: a device dark for eleven minutes came back at serial 95 while the fleet had
		// moved to 98, sent its first report 1.5 seconds after start, was told immediately that something newer
		// existed — and then sat for the rest of a fixed minute before looking, because this delay was a plain
		// sleep the wake could not reach. The floor is right when there is no news; it is exactly wrong when
		// there is, since coming back stale after an outage is the single most likely moment for a device to be
		// behind.
		select {
		case <-time.After(time.Minute):
		case <-cfg.wake:
			log.Printf("trust_anchor_recovery start-up delay cut short: the Edge reports a newer distribution")
		}
		for {
			outcome := runTrustAnchorRecoveryOnce(tc, cfg)
			next := trustRecoveryInterval
			switch outcome.code {
			case "anchors_valid":
				// The healthy path SAYS SO — same line as macOS, ~4/day at this interval. A silent healthy path
				// reads identically to "feature off" and "feature broken", and for a mechanism whose whole job is
				// rescuing locked-out devices, an operator must be able to tell those apart from the log alone.
				//
				// ★ AND IT CARRIES THE DETAIL, BECAUSE THIS IS WHERE A NAME IS ADOPTED (2026-08-19, seen on the
				// verification build of this very change). Nothing about the anchors changes when a device
				// starts sending an organization's announced name, so the outcome is "anchors_valid" — and this
				// line dropped the detail, which meant the device changed what it puts in every ClientHello and
				// said nothing. That is exactly the silence the macOS side called the dangerous half: a fleet
				// the Edge believes has adopted something, with no record on the device that it did.
				note := strings.TrimSpace(outcome.detail)
				if note != "" {
					note = " — " + note
				}
				log.Printf("trust_anchor_recovery anchors_valid=yes adopted_serial=%d (no action needed)%s",
					lastAcceptedTrustSerial(cfg.stateDir), note)
			case "adopted":
				log.Printf("trust_anchor_recovery ADOPTED %s — the provisioned pin is superseded", outcome.detail)
			case "adopted_while_healthy":
				// Routine catch-up: the device was fine and moved to a newer distribution after verifying it
				// against the served chain. This is what lets a rotation's overlap actually reach healthy devices.
				log.Printf("trust_anchor_recovery ADOPTED (healthy) %s — verified against the served chain first", outcome.detail)
			case "refused_would_strand":
				// A newer distribution would have cut this device off. It stayed on working anchors — say so
				// loudly, because a rotation that keeps failing this check is publishing a set some device cannot
				// verify, and the operator needs to see WHICH device is refusing before they retire anything.
				log.Printf("trust_anchor_recovery REFUSED a newer distribution %s", outcome.detail)
			case "undetermined":
				log.Printf("trust_anchor_recovery skipped: %s", outcome.detail)
			default:
				// Dark and not healing: retry with urgency, and say so every time — this is the state an operator
				// must notice.
				log.Printf("trust_anchor_recovery UNRECOVERED: %s — retrying in %s", outcome.detail, trustRecoveryRetryInterval)
				next = trustRecoveryRetryInterval
			}
			// Sleep until the timer, OR until the Edge says on the next report that it is distributing
			// something newer. The hint only ever SHORTENS this wait. Everything the loop then does is
			// unchanged — fetch, verify against the pinned key, refuse a serial that does not advance, refuse
			// anchors that would strand this device — so the worst a wrong hint can cost is one early pass
			// that finds nothing.
			select {
			case <-time.After(next):
			case <-cfg.wake:
				log.Printf("trust_anchor_recovery woken: the Edge reports a newer distribution")
			}
		}
	}()
	log.Printf("trust_anchor_recovery scheduler started (probe every %s, or sooner when the Edge says there is "+
		"something newer, state in %q)", trustRecoveryInterval, cfg.stateDir)
}

// discardForeignAdoptedAnchors removes an adopted distribution that can be SHOWN to belong to another
// organization, and reports what it did.
//
// ★ IT MOVES RATHER THAN DELETES. The pointer is the evidence of what this device was carrying and why it
// could not talk to its own deployment; an operator arriving after the fact needs to be able to read it. The
// replay floor is what must stop applying, not the record.
//
// ★ AND IT RUNS BEFORE ANYTHING READS THE STORE. Leaving the files in place and merely declining to use them
// was the shape that made this defect survive one fix already: every reader has to remember the exception, and
// the one that forgets is the one that verifies the Edge. Repairing the device is one act in one place.
func discardForeignAdoptedAnchors(stateDir, tenantID, profileServerName string) (bool, string) {
	p, ok := readAdoptedPointer(stateDir)
	if !ok {
		return false, ""
	}
	foreign, why := adoptedIsProvenForeign(p, tenantID, profileServerName)
	if !foreign {
		return false, ""
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	moved := 0
	for _, name := range []string{adoptedPointerFile, adoptedAnchorsFile} {
		src := filepath.Join(stateDir, name)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		if err := os.Rename(src, src+".foreign-"+stamp); err != nil {
			return false, fmt.Sprintf("adopted anchors are somebody else's (%s) but %s could not be moved aside: %v — "+
				"this device will keep failing to verify its own Edge until it is removed by hand", why, src, err)
		}
		moved++
	}
	if moved == 0 {
		return false, ""
	}
	return true, fmt.Sprintf("adopted anchors DISCARDED — %s. The %d file(s) are kept beside their place with a "+
		".foreign-%s suffix; the provisioned anchors are in force again", why, moved, stamp)
}
