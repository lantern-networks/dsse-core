// steer_exclusion_sync.go — admin-managed, server-signed steer-exclusion sync for the Windows steering
// agent (the Windows analog of the macOS NE signed-policy feature). Portable Go (no OS build tag) so it
// compiles + unit-tests on any host; the OS-specific APPLY target is injected as a callback.
//
// Loop: periodically pull the Edge's SIGNED steer-exclusion policy over the (T) mTLS transport, VERIFY it
// against the PINNED Ed25519 public key (shared internal/agentpolicy verifier — same bytes the macOS NE
// verifies), MERGE it ADDITIVELY on top of the local loop-prevention baseline (the agent self + the
// --bypass-app infra), and APPLY the result. A fetch/verify error KEEPS the current set (fail-safe: a
// transient Edge outage must never drop exclusions and start steering an excluded app). The additive
// merge is the live 502 lesson from the NE — the server set must never replace the infra/self exclusions.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
)

// effectiveReportPath is the fixed Edge contract sibling of the agent-policy endpoint. The Edge keys the
// report to the cert-proven device identity (the (T) mTLS client cert), so NO device id is sent.
const effectiveReportPath = "/steer/agent-policy/effective"

// trustSerialHintHeader is the Edge's answer to "is there anything newer", carried on the response to the
// report this agent already sends every minute.
//
// ★ IT IS A NUDGE, NOT AN AUTHORITY, AND THAT IS WHAT MAKES IT SAFE (2026-08-20). A serial means something
// only inside a signed bundle: this agent still fetches, still verifies against its pinned key, and still
// refuses anything that does not advance past what it has adopted. A hostile or broken value can therefore
// cost exactly one wasted fetch — it cannot install, downgrade, or roll anything back.
//
// It exists because adoption was on a six-hour timer, and a fleet operation that waits on every device's
// timer is not a mechanism: twice in one day a rotation stalled here and the only way to hurry it was a
// person restarting a service on this machine. A header keeps the response shape unchanged (still 204) for
// agents that do not know about it.
const trustSerialHintHeader = "X-DSSE-Trust-Serial"

type exclusionSync struct {
	client        *http.Client // wired to the (T) mTLS transport (transportHTTPClient)
	baseURL       string       // Edge base, e.g. https://<transport-host>
	pinHex        string       // pinned agent-policy signing public key (provisioned out-of-band)
	localBaseline []string     // --bypass-app infra (always kept); server set is added on top
	interval      time.Duration
	apply         func([]string) // OS-specific: windivert appBypass.setAppSubs (or wfp policy re-push)
	logf          func(string, ...any)
	// state (optional) supplies the live device steering state reported alongside the effective exclusions,
	// so the CP/console can see each device's posture without a separate telemetry channel. nil => report the
	// exclusion set only (backward-compatible; used by unit tests and any caller that has no live state).
	state func() deviceStateExtra
	// pinnedCAFingerprints (optional) supplies the SHA-256 of every transport CA this device currently pins.
	// nil => the field is omitted, and the Edge reports the device as "silent" for rotation readiness rather
	// than assuming it is ready — an unheard-from device is exactly the one that must not be cut off.
	pinnedCAFingerprints func() []string
	// adoptedTrustSerial (optional) supplies the serial of the trust bundle whose anchors are CURRENTLY in force
	// — read from the same source as pinnedCAFingerprints, so the Edge's CA-withdrawal gate sees a serial and a
	// fingerprint set that describe one reality. nil or 0 => "no adopted bundle" and the Edge falls back to the
	// prior fingerprint-only judgement (so not sending it is backward-compatible). A device reporting a serial
	// OLDER than the distribution the Edge is on is NotReady, keeping the gate closed until it catches up.
	adoptedTrustSerial func() int64
	// publishRenewCutoff (optional) receives the operator's "renew anything issued before this" declaration
	// from the SAME verified policy this loop already fetches — so the renewal scheduler reads it without a
	// second fetch OR a second signature check (the duplicate check is always where the weaker one ends up).
	// Called ONLY on a successful verify: a fetch/verify failure leaves the last verified value in force
	// (fail-safe, mirroring the macOS cache), and a verified policy with the field absent publishes the zero
	// time, which puts renewal back on its ordinary schedule.
	publishRenewCutoff func(time.Time)
	// refusals (optional) is the trust-refusal journal. This report is the connection a refused device is
	// finally making, so it carries what the device refused — and clears it ONLY after the Edge accepts (2xx),
	// because the report is the only copy and it is travelling over a connection that only just came back.
	refusals *trustRefusalJournal
	// interceptionRefusals (optional) is the same idea for the (I) interception path: which PROCESSES on this
	// device cannot use the certificates interception is handing them. Carried and cleared exactly like the
	// transport journal above, and for the same reason — it is the fleet's only way to tell a device that is
	// steering happily from one whose user has no working HTTPS. See interception_observation.go.
	interceptionRefusals *interceptionRefusalJournal
	// interceptionRoots (optional) returns which of the interception roots the deployment named are actually in
	// this machine's trust store. nil => the field is omitted; the Edge reads "not reported" as UNKNOWN, never
	// as "trusts none" — a device that has not answered must not be mistaken for one that would break on a switch.
	interceptionRoots func() []string
	// sentServerNames (optional) returns the two names this device would actually put in a ClientHello: the
	// transport SNI and the recovery SNI. nil or empty => omitted, and the Edge must read that as UNKNOWN.
	//
	// ★ THE SERIAL SAYS WHAT WAS DISTRIBUTED, NOT WHAT THE AGENT DOES WITH IT (2026-08-19). Both names are
	// announced so a port can be retired and a per-organization certificate can be served, and both switches
	// are gated on "every device can send it". An older agent adopts a bundle carrying the field and IGNORES
	// it — reporting a current serial the whole time — so a gate that reads the serial alone would open on
	// devices that never learned to send the name, which is the shape of lockout this whole area exists to
	// avoid. This reports the behaviour instead of the distribution.
	sentServerNames func() (transportSNI, recoverySNI string)
	// trustSerialHint (optional) receives the serial the Edge says it is currently distributing, read from the
	// response to this report. nil => the hint is ignored and adoption stays on its own timer, which is the
	// behaviour of every agent built before the header existed.
	trustSerialHint func(int64)
	// adoptedTrustSerialNow (optional) is what this device has adopted, used only to decide whether the hint
	// is worth acting on. Deliberately the same accessor the report uses, so the comparison and the reported
	// value can never disagree.
	adoptedTrustSerialNow func() int64
	// renewalRecoveryTarget (optional) returns the address a recovering device would ACTUALLY dial, resolved by
	// the same function recovery uses. nil or empty => omitted, and the Edge must read that as UNKNOWN.
	//
	// ★ A NAME IS NOT A DESTINATION, AND A PORT WAS RETIRED ON THAT CONFUSION (2026-08-20). The gate that
	// closed the dedicated recovery listener read "this agent reports the recovery name" as "this agent can
	// reach the folded path". This agent reported the name and still dialled the endpoint being retired.
	renewalRecoveryTarget func() string
	// policyKeys (optional) returns the SET of signing keys this device accepts — the provisioned pin plus any
	// adopted from a signed trust bundle. nil => verify against pinHex alone, which is the behaviour before a
	// key set was ever published, so a deployment that never publishes one is unaffected.
	policyKeys func() []string
	// fallbackClientCert (optional) returns the leaf PEM of the certificate this device would present if its
	// RENEWED identity became unusable — the bootstrap credential loadDeviceIdentity falls back to. The Edge's
	// retire gate can otherwise only see what a device is presenting NOW, which is how retiring a CA that every
	// device had already moved off still took the fleet down for seven minutes on 2026-08-02: a device whose
	// pointer was set aside fell back to a bootstrap certificate under the retired CA and was refused. nil or
	// empty => the field is omitted and the gate adds no constraint for this device, exactly as before.
	fallbackClientCert func() string
}

// deviceStateExtra is the live steering state reported with the effective exclusion set (Phase 1 device-state
// visibility). Plain fields so this file stays portable/unit-testable; the OS-specific wiring computes it from
// the agent's live disarmed/captive flags, the configured fail-open posture, and the active region endpoint.
type deviceStateExtra struct {
	Posture                  string // agentstatus.Protection string: steering|disarmed|captive_onboarding|dark|stopped
	FailOpenConfigured       bool   // whether fail-open is permitted by config/policy (vs fail-CLOSED)
	RegionFailoverEnabled    bool   // region-failover active on this device
	ActiveRegion             string // serverName/host of the region endpoint currently in use
	ServerInitiatedRuleCount int    // count of applied server-initiated (inbound) rules
}

// refreshOnce reconciles the effective steer-exclusion set and reports it. Two modes, keyed on pinHex:
//
//   - pinHex set (signed policy): fetch+verify the Edge's signed set, MERGE it additively onto the local
//     baseline, APPLY the result. A fetch/verify error returns early WITHOUT apply/report — fail-safe: a
//     transient Edge outage must never drop exclusions or start steering an excluded app.
//   - pinHex empty (no signed policy): there is nothing to fetch and the local baseline is already applied
//     at startup, so we do NOT re-apply — but we STILL report. The effective-set report (admin
//     observability of what this device actually bypasses, incl. the local --bypass-app baseline) must not
//     be gated on signed policy: a box with only a local --bypass-app is exactly the case an admin most
//     needs to see (an unmanaged bypass = a potential exfil path invisible to the console otherwise).
//
// In BOTH modes the REVERSE telemetry (parity with the macOS NE) reports the effective set the device
// actually excludes — including the infra/self baseline the server never issued. Best-effort, fail-safe: a
// report failure NEVER changes steering and NEVER fails the refresh.
func (s *exclusionSync) refreshOnce(ctx context.Context) ([]string, error) {
	var serverIDs []string
	if strings.TrimSpace(s.pinHex) != "" {
		p, err := agentpolicy.FetchVerifiedExclusionsWithKeys(ctx, s.client, s.baseURL, s.verificationKeys())
		if err != nil {
			return nil, err
		}
		serverIDs = p.ExcludedAppSigningIDs
		// Publish the operator's stale-before declaration from this VERIFIED payload. Only on success: a
		// transient failure returned above leaves the last verified cutoff in force. An absent/malformed field
		// parses to the zero time here, which the scheduler reads as "no declaration" — the safe direction.
		if s.publishRenewCutoff != nil {
			s.publishRenewCutoff(parseRenewCutoff(p.RenewCertificatesIssuedBefore))
		}
	}
	// ★★★ AND WHAT THE DEPLOYMENT SAYS IT CAN CARRY (2026-08-25). This document was already being served and
	// signed by the Edge and NOTHING here read it. It is fetched on the same interval, with the same pinned
	// keys, and a failure is ignored on purpose: not being able to ask must leave this agent steering exactly
	// as it was. See deployment_carries_family.go.
	if strings.TrimSpace(s.pinHex) != "" {
		if posture, perr := agentpolicy.FetchVerifiedSteeringPostureWithKeys(ctx, s.client, s.baseURL,
			s.verificationKeys()); perr == nil {
			setCarriedFamilies(posture.CaptureAddressFamilies)
		} else if s.logf != nil {
			s.logf("steering-posture sync: could not read what this deployment can carry (%v) — steering is "+
				"unchanged", perr)
		}
	}
	merged := agentpolicy.MergeExclusions(s.localBaseline, serverIDs)
	// Apply only when a signed server set can have changed the effective set. With no pin there is no
	// server set and the baseline is already in force, so re-applying would be a churny no-op — skip it.
	if strings.TrimSpace(s.pinHex) != "" {
		s.apply(merged)
	}
	if err := s.reportEffective(ctx, merged, len(serverIDs)); err != nil {
		if s.logf != nil {
			s.logf("steer-exclusion sync: effective-set report failed (ignored): %v", err)
		}
	}
	return merged, nil
}

// verificationKeys is the set this sync accepts signatures from: the published set when one has been adopted,
// otherwise the pin alone. Never empty when pinHex is set, so a device cannot end up accepting nothing.
func (s *exclusionSync) verificationKeys() []string {
	if s.policyKeys != nil {
		if keys := s.policyKeys(); len(keys) > 0 {
			return keys
		}
	}
	return []string{s.pinHex}
}

// parseRenewCutoff turns the policy's renew_certificates_issued_before into a time. Anything empty or
// unparseable becomes the zero time — "no declaration" — mirroring the macOS reader: a garbled value must fall
// back to the ordinary schedule, never be read as "renew now".
func parseRenewCutoff(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// reportEffective POSTs the merged effective steer-exclusion set back to the Edge for admin observability.
// It is best-effort reverse telemetry: a short timeout, errors returned for logging only, and it never
// blocks or changes enforcement. Success is HTTP 204; the Edge keys the report to the cert-proven device
// identity over the (T) mTLS client, so no device id is sent.
func (s *exclusionSync) reportEffective(ctx context.Context, merged []string, serverCount int) error {
	body := struct {
		Platform                string   `json:"platform"`
		EffectiveAppSigningIDs  []string `json:"effective_app_signing_ids"`
		ServerAppSigningIDCount int      `json:"server_app_signing_id_count"`
		// Device-state fields (Phase 1): omitempty so a stateless report (state==nil) is byte-for-byte the
		// legacy payload and the Edge — which ignores unknown/zero fields — stays backward compatible.
		Posture                  string `json:"posture,omitempty"`
		FailOpenConfigured       bool   `json:"fail_open_configured,omitempty"`
		RegionFailoverEnabled    bool   `json:"region_failover_enabled,omitempty"`
		ActiveRegion             string `json:"active_region,omitempty"`
		ServerInitiatedRuleCount int    `json:"server_initiated_rule_count,omitempty"`
		// Which transport CAs this device trusts, so an operator can see who is ready before rotating.
		PinnedTransportCASHA256 []string `json:"pinned_transport_ca_sha256,omitempty"`
		// The serial of the adopted trust bundle those fingerprints came from. omitempty so 0 (nothing adopted)
		// is absent on the wire — the Edge treats absent/0 exactly as before, fingerprint-only.
		AdoptedTrustSerial int64 `json:"adopted_trust_serial,omitempty"`
		// What this device REFUSED, carried late because a refusal cannot travel over the connection it caused
		// to fail. omitempty: no refusals => absent => the report is byte-for-byte the legacy payload.
		TrustRefusals []trustRefusal `json:"trust_refusals,omitempty"`
		// What this device cannot USE, as opposed to what it refused to connect to. omitempty for the same
		// reason: absent is an agent that does not answer this question, which must read as UNKNOWN and never
		// as "this device's interception is fine".
		InterceptionRefusals []interceptionRefusal `json:"interception_refusals,omitempty"`
		// Which interception roots the deployment named are in this machine's trust store. omitempty so "found
		// none" is absent, which the Edge reads as UNKNOWN (not "trusts none") — the two lead to opposite errors.
		PinnedInterceptionRootSHA256 []string `json:"pinned_interception_root_sha256,omitempty"`
		// The certificate this device would FALL BACK to if its renewed identity became unusable, so the retire
		// gate can refuse to retire a CA that still issues somebody's safety net. A public certificate only —
		// never the key. omitempty: not reported means the gate adds no constraint, as before.
		FallbackClientCertPEM string `json:"fallback_client_cert_pem,omitempty"`
		// The signing keys this device will ACCEPT policy from — the provisioned pin plus anything adopted from
		// a signed trust bundle. This is what makes a signing-key switch safe to schedule: the Edge can see that
		// every device already holds the next key before anything is signed with it, instead of finding out from
		// the devices that go quiet afterwards. Deliberately the effective verification set rather than only the
		// adopted part, because the question being answered is "would this device verify a policy signed by key
		// X", which the adopted subset alone cannot answer without also knowing the device's pin.
		// omitempty: absent means an agent that does not report this yet — UNKNOWN, not "accepts nothing".
		AgentPolicyPublicKeys []string `json:"agent_policy_public_keys,omitempty"`
		// The names this device SENDS — see sentServerNames. omitempty: absent is an agent that does not
		// answer this question yet, which must read as UNKNOWN and never as "sends nothing".
		TransportServerNameSent string `json:"transport_server_name_sent,omitempty"`
		RenewalRecoverySNISent  string `json:"renewal_recovery_sni_sent,omitempty"`
		// Where recovery would actually go — see renewalRecoveryTarget.
		RenewalRecoveryTarget string `json:"renewal_recovery_target,omitempty"`
	}{
		Platform:                "windows",
		EffectiveAppSigningIDs:  merged,
		ServerAppSigningIDCount: serverCount,
	}
	// Read the fingerprints and the serial from the live sources together, so the pair the Edge's withdrawal
	// gate evaluates describes one reality — never a live fingerprint set beside a stale serial.
	if s.pinnedCAFingerprints != nil {
		body.PinnedTransportCASHA256 = s.pinnedCAFingerprints()
	}
	if s.adoptedTrustSerial != nil {
		body.AdoptedTrustSerial = s.adoptedTrustSerial()
	}
	if s.interceptionRoots != nil {
		body.PinnedInterceptionRootSHA256 = s.interceptionRoots()
	}
	if s.sentServerNames != nil {
		body.TransportServerNameSent, body.RenewalRecoverySNISent = s.sentServerNames()
	}
	if s.renewalRecoveryTarget != nil {
		body.RenewalRecoveryTarget = s.renewalRecoveryTarget()
	}
	if s.fallbackClientCert != nil {
		body.FallbackClientCertPEM = s.fallbackClientCert()
	}
	// Report the same set this sync just verified with, from the same accessor — a report that disagreed with
	// what the device actually accepts would be worse than none, since the switch is scheduled off it.
	// Sanitised on the way out for the same reason it is on the way in: an unconfigured pin would otherwise
	// put an empty string on the wire, and the Edge would be reading a key set that contains a non-key.
	body.AgentPolicyPublicKeys = sanitisePolicyKeys(s.verificationKeys())
	// Snapshot the refusals now and remember exactly what we sent: they are cleared ONLY if the Edge accepts,
	// and only the entries at the counts we sent — anything that recurred mid-flight has a higher count and is
	// kept (its acknowledged copy is gone, what happened since is not).
	reportedRefusals := s.refusals.pending()
	body.TrustRefusals = reportedRefusals
	reportedInterception := s.interceptionRefusals.pending()
	body.InterceptionRefusals = reportedInterception
	if s.state != nil {
		st := s.state()
		body.Posture = st.Posture
		body.FailOpenConfigured = st.FailOpenConfigured
		body.RegionFailoverEnabled = st.RegionFailoverEnabled
		body.ActiveRegion = st.ActiveRegion
		body.ServerInitiatedRuleCount = st.ServerInitiatedRuleCount
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, strings.TrimRight(s.baseURL, "/")+effectiveReportPath, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// The applied-exclusions half is never retried; the REFUSALS half is the only copy, so it is dropped ONLY
	// once the Edge has actually taken it (any 2xx). No response, an error, or a non-2xx keeps it for next time.
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		s.refusals.clear(reportedRefusals)
		s.interceptionRefusals.clear(reportedInterception)
		s.noticeTrustSerialHint(resp.Header.Get(trustSerialHintHeader))
	}
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("the Edge refused the effective-set report: %s", edgeRefusal(resp))
	}
	return nil
}

// run applies once immediately, then on every interval until ctx is cancelled. Errors are logged and the
// loop continues with the last-applied set.
func (s *exclusionSync) run(ctx context.Context) {
	logf := s.logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	signed := strings.TrimSpace(s.pinHex) != ""
	if merged, err := s.refreshOnce(ctx); err != nil {
		logf("steer-exclusion sync: initial fetch failed; keeping local baseline %v: %v", s.localBaseline, err)
	} else if signed {
		logf("steer-exclusion sync: applied %d signed exclusion(s): %v", len(merged), merged)
	} else {
		logf("steer-exclusion sync: no signed policy; reported %d effective exclusion(s): %v", len(merged), merged)
	}
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if merged, err := s.refreshOnce(ctx); err != nil {
				logf("steer-exclusion sync: refresh failed; keeping current set: %v", err)
			} else if signed {
				logf("steer-exclusion sync: refreshed %d signed exclusion(s)", len(merged))
			} else {
				logf("steer-exclusion sync: reported %d effective exclusion(s)", len(merged))
			}
		}
	}
}

// noticeTrustSerialHint acts on the Edge's "there is something newer" header, and refuses to act on anything
// else. Silent when there is nothing to do: this runs every minute and a healthy device is up to date.
func (s *exclusionSync) noticeTrustSerialHint(raw string) {
	if s.trustSerialHint == nil {
		return
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return // an Edge that does not send it, which must keep working exactly as before
	}
	offered, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || offered <= 0 {
		return // unparseable is not an event; the timer still covers this device
	}
	if s.adoptedTrustSerialNow != nil && offered <= s.adoptedTrustSerialNow() {
		return // strictly greater, or nothing happens — the same rule adoption itself applies
	}
	s.trustSerialHint(offered)
}
